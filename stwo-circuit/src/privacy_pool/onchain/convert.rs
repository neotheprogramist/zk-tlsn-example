use alloy::primitives::{Bytes, FixedBytes, U256};
use stwo::{
    core::{
        fields::qm31::SecureField, poly::circle::CanonicCoset, proof::StarkProof,
        utils::bit_reverse, vcs::keccak_merkle::KeccakMerkleHasher,
    },
    prover::{backend::simd::SimdBackend, poly::circle::SecureCirclePoly},
};

use super::types::{
    CM31, CompositionPoly, Config, Decommitment, FriConfig, FriLayerProof, FriProof, Proof, QM31,
};

pub(crate) fn extract_composition_oods_eval(
    proof: &StarkProof<KeccakMerkleHasher>,
) -> Option<SecureField> {
    let [.., composition_mask] = &**proof.sampled_values else {
        return None;
    };
    let coordinate_evals = composition_mask
        .iter()
        .map(|columns| {
            let &[eval] = &columns[..] else {
                return None;
            };
            Some(eval)
        })
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()?;
    Some(SecureField::from_partial_evals(coordinate_evals))
}

pub(crate) fn qm31(value: SecureField) -> QM31 {
    QM31 {
        first: CM31 {
            real: value.0.0.0,
            imag: value.0.1.0,
        },
        second: CM31 {
            real: value.1.0.0,
            imag: value.1.1.0,
        },
    }
}

fn encode_decommitment_packed(hash_witness: &[FixedBytes<32>], column_witness: &[u32]) -> Bytes {
    let mut encoded = Vec::new();

    let length_bytes: [u8; 32] = U256::from(hash_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&length_bytes);

    for witness in hash_witness {
        encoded.extend_from_slice(witness.as_slice());
    }

    let column_length_bytes: [u8; 32] = U256::from(column_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&column_length_bytes);

    for &value in column_witness {
        encoded.extend_from_slice(&value.to_be_bytes());
    }

    Bytes::from(encoded)
}

pub fn convert_to_solidity_proof(
    proof: &StarkProof<KeccakMerkleHasher>,
    composition_polynomial: &SecureCirclePoly<SimdBackend>,
) -> Proof {
    let sol_config = Config {
        powBits: proof.config.pow_bits,
        friConfig: FriConfig {
            logBlowupFactor: proof.config.fri_config.log_blowup_factor,
            logLastLayerDegreeBound: proof.config.fri_config.log_last_layer_degree_bound,
            nQueries: U256::from(proof.config.fri_config.n_queries),
        },
    };

    let commitments: Vec<FixedBytes<32>> = proof
        .0
        .commitments
        .iter()
        .map(|commitment| FixedBytes::from(commitment.0))
        .collect();

    let sampled_values: Vec<Vec<Vec<QM31>>> = proof
        .sampled_values
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|row| row.iter().copied().map(qm31).collect())
                .collect()
        })
        .collect();

    let decommitments: Vec<Decommitment> = proof
        .0
        .decommitments
        .iter()
        .map(|decommitment| Decommitment {
            witness: decommitment
                .hash_witness
                .iter()
                .map(|hash| FixedBytes::from(hash.0))
                .collect(),
            columnWitness: decommitment
                .column_witness
                .iter()
                .map(|value| value.0)
                .collect(),
        })
        .collect();

    let first_layer = {
        let layer = &proof.0.fri_proof.first_layer;
        FriLayerProof {
            friWitness: layer.fri_witness.iter().copied().map(qm31).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|hash| FixedBytes::from(hash.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|value| value.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        }
    };

    let inner_layers: Vec<FriLayerProof> = proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| FriLayerProof {
            friWitness: layer.fri_witness.iter().copied().map(qm31).collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|hash| FixedBytes::from(hash.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|value| value.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        })
        .collect();

    let mut last_layer_coeffs = proof
        .0
        .fri_proof
        .last_layer_poly
        .clone()
        .into_ordered_coefficients();
    bit_reverse(&mut last_layer_coeffs);

    let fri_proof = FriProof {
        firstLayer: first_layer,
        innerLayers: inner_layers,
        lastLayerPoly: last_layer_coeffs.into_iter().map(qm31).collect(),
    };

    let composition_coordinates: Vec<Vec<u32>> = composition_polynomial
        .clone()
        .into_coordinate_polys()
        .iter()
        .map(|poly| {
            let domain = CanonicCoset::new(poly.log_size()).circle_domain();
            let cpu_poly = poly.evaluate(domain).to_cpu().interpolate();
            cpu_poly.coeffs.iter().map(|value| value.0).collect()
        })
        .collect();

    let composition_poly = CompositionPoly {
        coeffs0: composition_coordinates[0].clone(),
        coeffs1: composition_coordinates[1].clone(),
        coeffs2: composition_coordinates[2].clone(),
        coeffs3: composition_coordinates[3].clone(),
    };

    let queried_values: Vec<Vec<u32>> = proof
        .0
        .queried_values
        .iter()
        .map(|column| column.iter().map(|value| value.0).collect())
        .collect();

    Proof {
        config: sol_config,
        commitments,
        sampledValues: sampled_values,
        decommitments,
        queriedValues: queried_values,
        proofOfWork: proof.proof_of_work,
        friProof: fri_proof,
        compositionPoly: composition_poly,
    }
}
