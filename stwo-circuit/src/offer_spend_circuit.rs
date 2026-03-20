use stwo::{
    core::{
        channel::KeccakChannel,
        fields::{m31::BaseField, qm31::SecureField},
        pcs::{CommitmentSchemeVerifier, PcsConfig},
        poly::circle::CanonicCoset,
        proof::StarkProof,
        vcs::{
            MerkleHasher,
            keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher},
        },
        verifier::verify,
    },
    prover::{
        CommitmentSchemeProver,
        backend::simd::SimdBackend,
        poly::circle::{PolyOps, SecureCirclePoly},
    },
};
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_polynomial::prove::prove;

use crate::privacy_pool::{
    merkle_membership::{
        MerkleInputs, MerkleMembershipComponent, MerkleMembershipEval, MerkleStatement0,
        gen_merkle_is_active_column, gen_merkle_is_first_column, gen_merkle_is_last_column,
        gen_merkle_is_step_column, gen_merkle_membership_interaction_trace, gen_merkle_trace,
        merkle_is_active_column_id, merkle_is_first_column_id, merkle_is_last_column_id,
        merkle_is_step_column_id,
    },
    poseidon_chain::{
        ChainInputs, ChainStatement0, OfferChainInputs, N_OFFER_CHAIN_ROWS,
        PoseidonChainComponent, PoseidonChainEval,
        gen_is_active_column_n, gen_is_last_column_n, gen_is_step_column_n,
        gen_offer_chain_trace, gen_poseidon_chain_interaction_trace, gen_poseidon_chain_trace,
        is_active_column_id, is_last_column_id, is_step_column_id,
    },
    relations::{LeafRelation, RootRelation},
    offer_scheduler::{
        OfferSchedulerComponent, OfferSchedulerEval, OfferSchedulerStatement0,
        gen_offer_scheduler_interaction_trace, gen_offer_scheduler_trace,
    },
    scheduler::{
        gen_is_first_column as gen_scheduler_is_first_column,
        is_first_column_id as scheduler_is_first_column_id,
    },
};

#[derive(Clone, Debug)]
pub struct OfferAcceptInputs {
    pub offer_secret: BaseField,
    pub offer_nullifier: BaseField,
    pub offer_amount: BaseField,
    pub token_address: BaseField,
    pub fiat_amount: BaseField,
    pub currency_hash: BaseField,
    pub rev_tag_hash: BaseField,
    pub offers_merkle_siblings: Vec<BaseField>,
    pub offers_merkle_index: u32,
    pub offers_merkle_root: BaseField,
    pub output_secret: BaseField,
    pub output_nullifier: BaseField,
}

#[derive(Clone, Debug)]
pub struct OfferAcceptPublicInputs {
    pub offers_merkle_root: BaseField,
    pub nullifier: BaseField,
    pub amount: BaseField,
    pub offer_commitment: BaseField,
    pub output_commitment: BaseField,
    pub token_address: BaseField,
}

impl OfferAcceptPublicInputs {
    pub fn mix_into(&self, channel: &mut impl stwo::core::channel::Channel) {
        channel.mix_u64(self.offers_merkle_root.0 as u64);
        channel.mix_u64(self.nullifier.0 as u64);
        channel.mix_u64(self.amount.0 as u64);
        channel.mix_u64(self.offer_commitment.0 as u64);
        channel.mix_u64(self.output_commitment.0 as u64);
        channel.mix_u64(self.token_address.0 as u64);
    }
}

#[derive(Clone, Debug)]
pub struct OfferAcceptProof<H: MerkleHasher> {
    pub public_inputs: OfferAcceptPublicInputs,
    pub log_size: u32,
    pub merkle_depth: usize,
    pub offer_claimed_sum: SecureField,
    pub merkle_claimed_sum: SecureField,
    pub scheduler_claimed_sum: SecureField,
    pub composition_polynomial: SecureCirclePoly<SimdBackend>,
    pub transcript_digest: [u8; 32],
    pub transcript_n_draws: u32,
    pub proof: StarkProof<H>,
}

pub fn prove_offer_accept(
    inputs: OfferAcceptInputs,
    log_size: u32,
) -> Result<OfferAcceptProof<KeccakMerkleHasher>, String> {
    tracing::info!("Starting offer-accept proof generation");

    let offer_chain_inputs = OfferChainInputs {
        offer_secret: inputs.offer_secret,
        offer_nullifier: inputs.offer_nullifier,
        offer_amount: inputs.offer_amount,
        token_address: inputs.token_address,
        fiat_amount: inputs.fiat_amount,
        currency_hash: inputs.currency_hash,
        rev_tag_hash: inputs.rev_tag_hash,
    };
    let (offer_trace, offer_leaf) = gen_offer_chain_trace(log_size, offer_chain_inputs);

    let output_inputs = ChainInputs::for_deposit(
        inputs.output_secret,
        inputs.output_nullifier,
        inputs.offer_amount,
        inputs.token_address,
    );
    let (_, output_outputs) = gen_poseidon_chain_trace(log_size, output_inputs);
    let output_leaf = output_outputs.leaf;

    let merkle_inputs = MerkleInputs::new(
        offer_leaf,
        inputs.offers_merkle_siblings.clone(),
        inputs.offers_merkle_index,
        inputs.offers_merkle_root,
    );
    let merkle_depth = merkle_inputs.depth();
    let (merkle_trace, computed_root) = gen_merkle_trace(log_size, &merkle_inputs);
    
    if computed_root != inputs.offers_merkle_root {
        return Err(format!(
            "Offers merkle root mismatch: computed={}, expected={}",
            computed_root.0, inputs.offers_merkle_root.0
        ));
    }

    let scheduler_trace = gen_offer_scheduler_trace(
        log_size,
        computed_root,
        inputs.offers_merkle_root,
        inputs.offer_amount,
        inputs.offer_amount,
        BaseField::from_u32_unchecked(0),
        offer_leaf,
        offer_leaf,
        output_leaf,
    );

    let config = PcsConfig::default();
    let log_max_rows = log_size + 3;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let prover_channel = &mut KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

    let public_inputs = OfferAcceptPublicInputs {
        offers_merkle_root: inputs.offers_merkle_root,
        nullifier: inputs.offer_nullifier,
        amount: inputs.offer_amount,
        offer_commitment: offer_leaf,
        output_commitment: output_leaf,
        token_address: inputs.token_address,
    };
    public_inputs.mix_into(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![
        gen_is_active_column_n(log_size, N_OFFER_CHAIN_ROWS),
        gen_is_step_column_n(log_size, N_OFFER_CHAIN_ROWS),
        gen_is_last_column_n(log_size, N_OFFER_CHAIN_ROWS),
        gen_merkle_is_active_column(log_size, merkle_depth),
        gen_merkle_is_step_column(log_size, merkle_depth),
        gen_merkle_is_first_column(log_size, merkle_depth),
        gen_merkle_is_last_column(log_size, merkle_depth),
        gen_scheduler_is_first_column(log_size),
    ]);
    tree_builder.commit(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(offer_trace.clone());
    tree_builder.extend_evals(merkle_trace.clone());
    tree_builder.extend_evals(scheduler_trace.clone());
    tree_builder.commit(prover_channel);

    let leaf_relation = LeafRelation::draw(prover_channel);
    let root_relation = RootRelation::draw(prover_channel);

    let (offer_interaction, offer_claimed_sum) =
        gen_poseidon_chain_interaction_trace(&offer_trace, &leaf_relation, log_size, 2, N_OFFER_CHAIN_ROWS);
    let (merkle_interaction, merkle_claimed_sum) = gen_merkle_membership_interaction_trace(
        &merkle_trace,
        &leaf_relation,
        &root_relation,
        log_size,
        merkle_depth,
    );
    let (scheduler_interaction, scheduler_claimed_sum) = gen_offer_scheduler_interaction_trace(
        &scheduler_trace,
        &leaf_relation,
        &root_relation,
        log_size,
    );

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(offer_interaction);
    tree_builder.extend_evals(merkle_interaction);
    tree_builder.extend_evals(scheduler_interaction);
    tree_builder.commit(prover_channel);
    let transcript_digest = prover_channel.digest().0;

    let mut tree_span_provider = TraceLocationAllocator::default();
    let offer_component = PoseidonChainComponent::new(
        &mut tree_span_provider,
        PoseidonChainEval {
            log_n_rows: log_size,
            is_active_id: is_active_column_id(log_size, "offer"),
            is_step_id: is_step_column_id(log_size, "offer"),
            is_last_id: is_last_column_id(log_size, "offer"),
            leaf_relation: leaf_relation.clone(),
            leaf_multiplicity: 2,
            claimed_sum: offer_claimed_sum,
        },
        offer_claimed_sum,
    );
    let merkle_component = MerkleMembershipComponent::new(
        &mut tree_span_provider,
        MerkleMembershipEval {
            log_n_rows: log_size,
            depth: merkle_depth,
            is_active_id: merkle_is_active_column_id(log_size, merkle_depth),
            is_step_id: merkle_is_step_column_id(log_size, merkle_depth),
            is_first_id: merkle_is_first_column_id(log_size, merkle_depth),
            is_last_id: merkle_is_last_column_id(log_size, merkle_depth),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            claimed_sum: merkle_claimed_sum,
        },
        merkle_claimed_sum,
    );
    let scheduler_component = OfferSchedulerComponent::new(
        &mut tree_span_provider,
        OfferSchedulerEval {
            log_n_rows: log_size,
            is_first_id: scheduler_is_first_column_id(log_size),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            offer_amount: inputs.offer_amount,
            offer_commitment: offer_leaf,
            refund_commitment_hash: output_leaf,
            claimed_sum: scheduler_claimed_sum,
        },
        scheduler_claimed_sum,
    );

    let all_component_provers = vec![
        &offer_component as &dyn stwo::prover::ComponentProver<SimdBackend>,
        &merkle_component as &dyn stwo::prover::ComponentProver<SimdBackend>,
        &scheduler_component as &dyn stwo::prover::ComponentProver<SimdBackend>,
    ];

    let (proof, composition_polynomial) =
        prove(&all_component_provers, prover_channel, commitment_scheme)
            .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    Ok(OfferAcceptProof {
        public_inputs,
        log_size,
        merkle_depth,
        offer_claimed_sum,
        merkle_claimed_sum,
        scheduler_claimed_sum,
        composition_polynomial,
        transcript_digest,
        transcript_n_draws: 0,
        proof,
    })
}

pub fn verify_offer_accept(
    proof_data: OfferAcceptProof<KeccakMerkleHasher>,
) -> Result<(), String> {
    tracing::info!("Starting offer-accept proof verification");

    let offer_log_sizes = ChainStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();
    let merkle_log_sizes = MerkleStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();
    let scheduler_log_sizes = OfferSchedulerStatement0 {
        log_size: proof_data.log_size,
    }
    .log_sizes();

    let mut full_log_sizes = offer_log_sizes.clone();
    full_log_sizes[0].extend(merkle_log_sizes[0].iter().copied());
    full_log_sizes[0].extend(scheduler_log_sizes[0].iter().copied());
    full_log_sizes[1].extend(merkle_log_sizes[1].iter().copied());
    full_log_sizes[1].extend(scheduler_log_sizes[1].iter().copied());
    full_log_sizes[2].extend(merkle_log_sizes[2].iter().copied());
    full_log_sizes[2].extend(scheduler_log_sizes[2].iter().copied());

    let channel = &mut KeccakChannel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(proof_data.proof.config);

    proof_data.public_inputs.mix_into(channel);
    commitment_scheme.commit(proof_data.proof.commitments[0], &full_log_sizes[0], channel);
    commitment_scheme.commit(proof_data.proof.commitments[1], &full_log_sizes[1], channel);

    let leaf_relation = LeafRelation::draw(channel);
    let root_relation = RootRelation::draw(channel);

    commitment_scheme.commit(proof_data.proof.commitments[2], &full_log_sizes[2], channel);

    let mut tree_span_provider = TraceLocationAllocator::default();
    let offer_component = PoseidonChainComponent::new(
        &mut tree_span_provider,
        PoseidonChainEval {
            log_n_rows: proof_data.log_size,
            is_active_id: is_active_column_id(proof_data.log_size, "offer"),
            is_step_id: is_step_column_id(proof_data.log_size, "offer"),
            is_last_id: is_last_column_id(proof_data.log_size, "offer"),
            leaf_relation: leaf_relation.clone(),
            leaf_multiplicity: 2,
            claimed_sum: proof_data.offer_claimed_sum,
        },
        proof_data.offer_claimed_sum,
    );
    let merkle_component = MerkleMembershipComponent::new(
        &mut tree_span_provider,
        MerkleMembershipEval {
            log_n_rows: proof_data.log_size,
            depth: proof_data.merkle_depth,
            is_active_id: merkle_is_active_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_step_id: merkle_is_step_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_first_id: merkle_is_first_column_id(proof_data.log_size, proof_data.merkle_depth),
            is_last_id: merkle_is_last_column_id(proof_data.log_size, proof_data.merkle_depth),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            claimed_sum: proof_data.merkle_claimed_sum,
        },
        proof_data.merkle_claimed_sum,
    );
    let scheduler_component = OfferSchedulerComponent::new(
        &mut tree_span_provider,
        OfferSchedulerEval {
            log_n_rows: proof_data.log_size,
            is_first_id: scheduler_is_first_column_id(proof_data.log_size),
            leaf_relation: leaf_relation.clone(),
            root_relation: root_relation.clone(),
            offer_amount: proof_data.public_inputs.amount,
            offer_commitment: proof_data.public_inputs.offer_commitment,
            refund_commitment_hash: proof_data.public_inputs.output_commitment,
            claimed_sum: proof_data.scheduler_claimed_sum,
        },
        proof_data.scheduler_claimed_sum,
    );

    let all_components = vec![
        &offer_component as &dyn stwo::core::air::Component,
        &merkle_component as &dyn stwo::core::air::Component,
        &scheduler_component as &dyn stwo::core::air::Component,
    ];

    verify(
        &all_components,
        channel,
        commitment_scheme,
        proof_data.proof,
    )
    .map_err(|_| "STARK verification failed".to_string())?;

    tracing::info!("✅ Offer-accept proof verified successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::BaseField;

    use super::{OfferAcceptInputs, prove_offer_accept, verify_offer_accept};
    use crate::{
        offchain_merkle::OffchainMerkleTree,
        privacy_pool::poseidon_chain::{OfferChainInputs, gen_offer_chain_trace},
    };

    fn test_offer_chain_inputs(
        offer_secret: BaseField,
        offer_nullifier: BaseField,
        offer_amount: BaseField,
        token_address: BaseField,
    ) -> OfferChainInputs {
        OfferChainInputs {
            offer_secret,
            offer_nullifier,
            offer_amount,
            token_address,
            fiat_amount: BaseField::from_u32_unchecked(100),
            currency_hash: BaseField::from_u32_unchecked(111),
            rev_tag_hash: BaseField::from_u32_unchecked(222),
        }
    }

    #[test]
    fn offer_accept_proof_roundtrip_succeeds() {
        let log_size = 8;
        let token_address = BaseField::from_u32_unchecked(12345);
        let offer_amount = BaseField::from_u32_unchecked(70);
        let fiat_amount = BaseField::from_u32_unchecked(100);
        let currency_hash = BaseField::from_u32_unchecked(111);
        let rev_tag_hash = BaseField::from_u32_unchecked(222);

        let offer_secret = BaseField::from_u32_unchecked(5555);
        let offer_nullifier = BaseField::from_u32_unchecked(6666);
        let output_secret = BaseField::from_u32_unchecked(7777);
        let output_nullifier = BaseField::from_u32_unchecked(8888);

        let chain_inputs = test_offer_chain_inputs(offer_secret, offer_nullifier, offer_amount, token_address);
        let (_, offer_leaf) = gen_offer_chain_trace(log_size, chain_inputs);

        let mut offers_tree = OffchainMerkleTree::new(31);
        offers_tree.add_leaf(BaseField::from_u32_unchecked(11));
        offers_tree.add_leaf(BaseField::from_u32_unchecked(22));
        let offers_merkle_index = offers_tree.add_leaf(offer_leaf) as u32;
        let (offers_merkle_siblings, _) = offers_tree.path(offers_merkle_index as usize);
        let offers_merkle_root = offers_tree.root();

        let inputs = OfferAcceptInputs {
            offer_secret,
            offer_nullifier,
            offer_amount,
            token_address,
            fiat_amount,
            currency_hash,
            rev_tag_hash,
            offers_merkle_siblings,
            offers_merkle_index,
            offers_merkle_root,
            output_secret,
            output_nullifier,
        };

        let proof = prove_offer_accept(inputs, log_size)
            .expect("offer accept proof should be generated");
        verify_offer_accept(proof).expect("offer accept proof should verify");
    }

    #[test]
    fn offer_accept_proof_fails_with_invalid_merkle_root() {
        let log_size = 8;
        let token_address = BaseField::from_u32_unchecked(12345);
        let offer_amount = BaseField::from_u32_unchecked(70);
        let fiat_amount = BaseField::from_u32_unchecked(100);
        let currency_hash = BaseField::from_u32_unchecked(111);
        let rev_tag_hash = BaseField::from_u32_unchecked(222);

        let offer_secret = BaseField::from_u32_unchecked(5555);
        let offer_nullifier = BaseField::from_u32_unchecked(6666);
        let output_secret = BaseField::from_u32_unchecked(7777);
        let output_nullifier = BaseField::from_u32_unchecked(8888);

        let chain_inputs = test_offer_chain_inputs(offer_secret, offer_nullifier, offer_amount, token_address);
        let (_, offer_leaf) = gen_offer_chain_trace(log_size, chain_inputs);

        let mut offers_tree = OffchainMerkleTree::new(31);
        let offers_merkle_index = offers_tree.add_leaf(offer_leaf) as u32;
        let (offers_merkle_siblings, _) = offers_tree.path(offers_merkle_index as usize);

        let inputs = OfferAcceptInputs {
            offer_secret,
            offer_nullifier,
            offer_amount,
            token_address,
            fiat_amount,
            currency_hash,
            rev_tag_hash,
            offers_merkle_siblings,
            offers_merkle_index,
            offers_merkle_root: BaseField::from_u32_unchecked(1),
            output_secret,
            output_nullifier,
        };

        let result = prove_offer_accept(inputs, log_size);
        assert!(result.is_err(), "invalid offers merkle root should fail");
        let err = result.err().unwrap_or_default();
        assert!(err.contains("Offers merkle root mismatch"));
    }
}