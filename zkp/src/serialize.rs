//! Wire-format envelope for `ProofRecord` ↔ bytes roundtrip.
//!
//! `CircuitProof.components: Vec<Box<dyn Component>>` is not `Serialize` and
//! is dropped on serialise. The host verifier
//! ([`verifier::verify_record`](crate::verifier::verify_record))
//! reconstructs the canonical component set from `claim`,
//! `interaction_claim`, channel-drawn `interaction_elements`, and
//! `metadata.pp_trace_ids` — so a deserialised record is fully
//! host-verifiable; we don't need to ship components on the wire.
//!
//! `CircuitClaim` and `CircuitInteractionClaim` are not `Serialize` either —
//! we map them to/from plain `Vec<u32>` / `Vec<QM31>` representations and
//! validate the array shape on deserialise. `PreProcessedColumnId.id` is a
//! `String` which we ship directly.
//!
//! All M31-valued u32 fields (`lo`, `hi`, `count`) are range-checked against
//! `M31::P` at the deserialize boundary so that downstream code can trust
//! the record's M31 fields are already canonical (GUIDELINES §6).

use circuit_prover::prover::CircuitProof;
use circuit_verifier::{
    circuit_claim::{CircuitClaim, CircuitInteractionClaim},
    circuit_components::N_COMPONENTS,
};
use serde::{Deserialize, Serialize};
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    pcs::PcsConfig,
    proof::ExtendedStarkProof,
    vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::{
    error::{Error, Result},
    recursion::{CircuitProofMetadata, ProofRecord, assert_canonical_pcs_config},
};

/// Wire-format struct for cross-worker proof transfer. All fields are
/// `Serialize`/`Deserialize`-compatible — the upstream `CircuitClaim`,
/// `CircuitInteractionClaim`, and `PreProcessedColumnId` types lack serde
/// derives, so we hold their fields directly and validate shape on import.
#[derive(Serialize, Deserialize)]
pub struct SerializedProofRecord {
    // CircuitProof fields (sans `components`):
    pub pcs_config: PcsConfig,
    pub claim_log_sizes: Vec<u32>,
    pub claim_output_values: Vec<QM31>,
    pub interaction_pow_nonce: u64,
    pub interaction_claim_sums: Vec<QM31>,
    pub channel_salt: u32,
    pub stark_proof: ExtendedStarkProof<Blake2sM31MerkleHasher>,

    // Metadata mirroring `CircuitProofMetadata`:
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
    pub pp_trace_id_strings: Vec<String>,
    pub pp_trace_log_sizes: Vec<u32>,

    // Public outputs (lifted to plain u32):
    pub lo: u32,
    pub hi: u32,
    pub count: u32,
}

impl SerializedProofRecord {
    pub fn from_record(record: &ProofRecord) -> Result<Self> {
        let cp = &record.circuit_proof;
        let stark_proof = cp
            .stark_proof
            .as_ref()
            .map_err(|e| Error::StarkProofIsErr(*e))?
            .clone();

        let claim_log_sizes = cp.claim.log_sizes.to_vec();
        let claim_output_values = cp.claim.output_values.clone();
        let interaction_claim_sums = cp.interaction_claim.claimed_sums.to_vec();

        let pp_trace_id_strings = record
            .metadata
            .pp_trace_ids
            .iter()
            .map(|id| id.id.clone())
            .collect();

        Ok(Self {
            pcs_config: cp.pcs_config,
            claim_log_sizes,
            claim_output_values,
            interaction_pow_nonce: cp.interaction_pow_nonce,
            interaction_claim_sums,
            channel_salt: cp.channel_salt,
            stark_proof,
            output_addresses: record.metadata.output_addresses.clone(),
            n_blake_gates: record.metadata.n_blake_gates,
            pp_trace_id_strings,
            pp_trace_log_sizes: record.metadata.pp_trace_log_sizes.clone(),
            lo: record.lo.0,
            hi: record.hi.0,
            count: record.count.0,
        })
    }

    pub fn into_record(self) -> Result<ProofRecord> {
        if self.claim_log_sizes.len() != N_COMPONENTS {
            return Err(Error::ClaimLogSizesShape {
                got: self.claim_log_sizes.len(),
                expected: N_COMPONENTS,
            });
        }
        if self.interaction_claim_sums.len() != N_COMPONENTS {
            return Err(Error::InteractionClaimSumsShape {
                got: self.interaction_claim_sums.len(),
                expected: N_COMPONENTS,
            });
        }
        if self.pp_trace_log_sizes.len() != self.pp_trace_id_strings.len() {
            return Err(Error::MetadataInconsistent {
                reason: "pp_trace_log_sizes.len() != pp_trace_ids.len()",
            });
        }
        // Length-equality is the soundness-critical bound; see
        // `verifier::EXPECTED_OUTPUT_VALUES` for the rationale.
        if self.claim_output_values.len() != 5 {
            return Err(Error::OutputCardinalityMismatch {
                actual: self.claim_output_values.len(),
            });
        }
        Error::check_canonical_m31("lo", self.lo)?;
        Error::check_canonical_m31("hi", self.hi)?;
        Error::check_canonical_m31("count", self.count)?;
        // Refuse a deserialized record whose pcs_config doesn't match the
        // crate-canonical one. Without this check, an imported proof flowing
        // straight to `verifier::verify` would never trip the canonicality
        // gate (which currently lives only inside `prove_merge`).
        assert_canonical_pcs_config("imported", &self.pcs_config)?;

        let log_sizes_arr: [u32; N_COMPONENTS] = self
            .claim_log_sizes
            .as_slice()
            .try_into()
            .expect("length checked above");
        let claimed_sums_arr: [QM31; N_COMPONENTS] = self
            .interaction_claim_sums
            .as_slice()
            .try_into()
            .expect("length checked above");

        let claim = CircuitClaim {
            log_sizes: log_sizes_arr,
            output_values: self.claim_output_values,
        };
        let interaction_claim = CircuitInteractionClaim {
            claimed_sums: claimed_sums_arr,
        };

        let circuit_proof = CircuitProof::<Blake2sM31MerkleHasher> {
            pcs_config: self.pcs_config,
            claim,
            interaction_pow_nonce: self.interaction_pow_nonce,
            interaction_claim,
            // Imported proofs carry no components; see module-level docs.
            components: Vec::new(),
            stark_proof: Ok(self.stark_proof),
            channel_salt: self.channel_salt,
        };

        let metadata = CircuitProofMetadata {
            output_addresses: self.output_addresses,
            n_blake_gates: self.n_blake_gates,
            pp_trace_ids: self
                .pp_trace_id_strings
                .into_iter()
                .map(|id| PreProcessedColumnId { id })
                .collect(),
            pp_trace_log_sizes: self.pp_trace_log_sizes,
        };

        Ok(ProofRecord {
            circuit_proof,
            metadata,
            lo: M31::from(self.lo),
            hi: M31::from(self.hi),
            count: M31::from(self.count),
        })
    }
}

pub fn serialize_record(record: &ProofRecord) -> Result<Vec<u8>> {
    let envelope = SerializedProofRecord::from_record(record)?;
    bincode::serialize(&envelope).map_err(Error::Bincode)
}

pub fn deserialize_record(bytes: &[u8]) -> Result<ProofRecord> {
    let envelope: SerializedProofRecord = bincode::deserialize(bytes).map_err(Error::Bincode)?;
    envelope.into_record()
}
