use circuit_air::statement::all_circuit_components;
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{CircuitProof, preprare_circuit_proof_for_circuit_verifier};
use circuits::{
    context::{Context, Var},
    eval,
    ops::{Guess, eq, guess, output},
    poseidon2,
};
use circuits_stark_verifier::{proof::ProofConfig, verify::verify};
use stwo::core::fields::qm31::QM31;

// Output indices for null/accumulator circuits.
const IDX_ROOT_ACC: usize = 0;
const IDX_NULLIFIER_ACC: usize = 1;
const IDX_TOKEN: usize = 2;
const IDX_AMOUNT: usize = 3;

// Output indices for the terminal offer circuit (matches single-deposit offer_circuit.rs).
pub const TERMINAL_IDX_ROOT_ACC: usize = 0;
pub const TERMINAL_IDX_NULLIFIER_ACC: usize = 1;
pub const TERMINAL_IDX_TOKEN: usize = 2;
pub const TERMINAL_IDX_AMOUNT: usize = 3;
pub const TERMINAL_IDX_OFFER_COMMITMENT: usize = 4;
pub const TERMINAL_IDX_OFFER_REFUND_SN_HASH: usize = 6;

/// Null (identity) circuit for recursive offer accumulation.
///
/// No recipient — all deposits in a batch offer may come from any address.
/// Outputs [root_acc=0, nullifier_acc=0, token, amount=0, 0, 0].
pub fn build_null_offer_context(token: QM31) -> Context<QM31> {
    let mut context = Context::<QM31>::default();

    let zero = context.zero();
    let token_v = guess(&mut context, token);

    output(&mut context, zero); // root_acc = 0
    output(&mut context, zero); // nullifier_acc = 0
    output(&mut context, token_v);
    output(&mut context, zero); // amount = 0
    output(&mut context, zero);
    output(&mut context, zero);

    context
}

fn verify_recursive_proof(
    context: &mut Context<QM31>,
    preprocessed_circuit: &PreprocessedCircuit,
    circuit_proof: CircuitProof,
) -> Vec<Var> {
    let preprocessed_column_ids = preprocessed_circuit.preprocessed_trace.ids();
    let proof_config = ProofConfig::from_components(
        &all_circuit_components::<QM31>(),
        preprocessed_column_ids.len(),
        &circuit_proof.pcs_config,
        circuit_air::statement::INTERACTION_POW_BITS,
    );
    let (proof, public_data) =
        preprare_circuit_proof_for_circuit_verifier(circuit_proof, &proof_config);

    let inner = circuit_air::statement::CircuitStatement::new(
        context,
        &preprocessed_circuit.params.output_addresses,
        &public_data.output_values,
        preprocessed_circuit.params.n_blake_gates,
        preprocessed_column_ids,
        proof.preprocessed_root,
    );
    let proof_vars = proof.guess(context);
    verify(context, &proof_vars, &proof_config, &inner);
    inner.output_values.clone()
}

/// Aggregates two proofs: the previous accumulator (null or recursive) and a new withdraw proof.
///
/// Only enforces token consistency across deposits — no recipient constraint.
/// Aggregated outputs [root_acc, nullifier_acc, token, total_amount, 0, 0].
pub fn build_recursive_offer_context(
    preprocessed_proof_a: &PreprocessedCircuit,
    circuit_proof_proof_a: CircuitProof,
    preprocessed_proof_b: &PreprocessedCircuit,
    circuit_proof_proof_b: CircuitProof,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    let a = verify_recursive_proof(&mut ctx, preprocessed_proof_a, circuit_proof_proof_a);
    let b = verify_recursive_proof(&mut ctx, preprocessed_proof_b, circuit_proof_proof_b);

    eq(&mut ctx, a[IDX_TOKEN], b[IDX_TOKEN]);

    let root_acc = poseidon2::poseidon2_hash_two(&mut ctx, a[IDX_ROOT_ACC], b[IDX_ROOT_ACC]);
    let total = eval!(&mut ctx, (a[IDX_AMOUNT]) + (b[IDX_AMOUNT]));
    let nullifier_acc =
        poseidon2::poseidon2_hash_two(&mut ctx, a[IDX_NULLIFIER_ACC], b[IDX_NULLIFIER_ACC]);

    let zero = ctx.zero();

    output(&mut ctx, root_acc);
    output(&mut ctx, nullifier_acc);
    output(&mut ctx, a[IDX_TOKEN]);
    output(&mut ctx, total);
    output(&mut ctx, zero);
    output(&mut ctx, zero);

    ctx
}

/// Terminal step for recursive offer creation.
///
/// Verifies the accumulated deposit proof (N deposits already aggregated) and computes
/// offerCommitment IN CIRCUIT as a public output — no private data leaves the user's machine.
///
/// Offer-specific private inputs (offer_secret, offer_nullifier, etc.) are proven inside
/// the circuit; only the 7 public outputs are visible to the trusted server and contract.
///
/// Outputs (7 values, same layout as single-deposit offer_circuit.rs):
///   [0] root_acc, [1] nullifier_acc, [2] token, [3] total_amount,
///   [4] offerCommitment (PROVEN), [5] 0, [6] offerRefundSnHash (PROVEN)
#[allow(clippy::too_many_arguments)]
pub fn build_offer_terminal_context(
    preprocessed_accumulated: &PreprocessedCircuit,
    circuit_proof_accumulated: CircuitProof,
    offer_secret: QM31,
    offer_nullifier: QM31,
    fiat_amount: QM31,
    currency_hash: QM31,
    rev_tag_hash: QM31,
    offer_refund_secret: QM31,
    offer_refund_nullifier: QM31,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    // Verify accumulated deposit proof → [root_acc, nullifier_acc, token, total_amount, 0, 0].
    let acc = verify_recursive_proof(&mut ctx, preprocessed_accumulated, circuit_proof_accumulated);

    // Offer private inputs — proven inside circuit, never sent to server.
    let os = guess(&mut ctx, offer_secret);
    let on_ = guess(&mut ctx, offer_nullifier);
    let fa = guess(&mut ctx, fiat_amount);
    let ch = guess(&mut ctx, currency_hash);
    let rth = guess(&mut ctx, rev_tag_hash);
    let ors = guess(&mut ctx, offer_refund_secret);
    let orn = guess(&mut ctx, offer_refund_nullifier);

    // offer_refund_sn_hash = H(offer_refund_secret, offer_refund_nullifier)
    let offer_refund_sn_hash = poseidon2::poseidon2_hash_two(&mut ctx, ors, orn);

    // offerCommitment = H(H(H(H(H(H(H(offer_secret, offer_nullifier), total_amount), token),
    //                         fiat_amount), currency_hash), rev_tag_hash), offer_refund_sn_hash)
    let h0 = poseidon2::poseidon2_hash_two(&mut ctx, os, on_);
    let h1 = poseidon2::poseidon2_hash_two(&mut ctx, h0, acc[IDX_AMOUNT]);
    let h2 = poseidon2::poseidon2_hash_two(&mut ctx, h1, acc[IDX_TOKEN]);
    let h3 = poseidon2::poseidon2_hash_two(&mut ctx, h2, fa);
    let h4 = poseidon2::poseidon2_hash_two(&mut ctx, h3, ch);
    let h5 = poseidon2::poseidon2_hash_two(&mut ctx, h4, rth);
    let offer_commitment = poseidon2::poseidon2_hash_two(&mut ctx, h5, offer_refund_sn_hash);

    let zero = ctx.zero();

    output(&mut ctx, acc[IDX_ROOT_ACC]);
    output(&mut ctx, acc[IDX_NULLIFIER_ACC]);
    output(&mut ctx, acc[IDX_TOKEN]);
    output(&mut ctx, acc[IDX_AMOUNT]);
    output(&mut ctx, offer_commitment);
    output(&mut ctx, zero);
    output(&mut ctx, offer_refund_sn_hash);

    ctx
}

#[cfg(test)]
mod tests {
    use circuit_air::{CircuitInteractionElements, lookup_sum};
    use circuit_common::preprocessed::PreprocessedCircuit;
    use circuit_prover::prover::{
        BaseColumnPool, CircuitProof, SimdBackend, prove_circuit_assignment,
    };
    use circuits::blake::HashValue;
    use num_traits::Zero;
    use stwo::core::{
        air::Component,
        channel::{Blake2sM31Channel, Channel},
        fields::m31::BaseField,
        pcs::{CommitmentSchemeVerifier, TreeVec},
        vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel,
    };

    use super::*;
    use crate::{
        offchain_merkle::{OffchainMerkleTree, poseidon_hash_pair},
        paymoney_circuits::withdraw_circuit::build_withdraw_merkle_context_from_offchain_tree,
    };

    pub const INTERACTION_POW_BITS: u32 = 20;

    fn bf(v: u32) -> BaseField {
        BaseField::from_u32_unchecked(v)
    }

    fn m31(v: BaseField) -> QM31 {
        QM31::from(v.0)
    }

    struct ProofBundle {
        preprocessed: PreprocessedCircuit,
        preprocessed_root: stwo::core::vcs::blake2_hash::Blake2sHash,
        proof: CircuitProof,
    }

    impl std::fmt::Debug for ProofBundle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProofBundle")
                .field("preprocessed_root", &self.preprocessed_root)
                .finish()
        }
    }

    fn make_bundle(mut context: Context<QM31>) -> ProofBundle {
        context.finalize_guessed_vars();
        context.validate_circuit();
        let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
        let proof = prove_circuit_assignment(
            context.values(),
            &preprocessed,
            &BaseColumnPool::<SimdBackend>::new(),
        );
        let preprocessed_root = proof
            .stark_proof
            .as_ref()
            .expect("proof generation failed")
            .proof
            .commitments[0];
        ProofBundle { preprocessed, preprocessed_root, proof }
    }

    fn make_withdraw_bundle(
        tree: &OffchainMerkleTree,
        amount: BaseField,
        refund_amount: BaseField,
        secret: BaseField,
        nullifier: BaseField,
        refund_secret: BaseField,
        refund_nullifier: BaseField,
        token: BaseField,
        recipient: BaseField,
    ) -> ProofBundle {
        let ctx = build_withdraw_merkle_context_from_offchain_tree(
            tree,
            secret,
            nullifier,
            amount + refund_amount,
            token,
            amount,
            refund_secret,
            refund_nullifier,
            refund_amount,
            recipient,
        )
        .expect("withdraw witness should build");
        make_bundle(ctx)
    }

    fn compute_nullifier_chain(nullifiers: &[BaseField]) -> BaseField {
        nullifiers
            .iter()
            .fold(BaseField::from_u32_unchecked(0), |acc, &n| {
                poseidon_hash_pair(acc, n)
            })
    }

    fn compute_root_chain(roots: &[BaseField]) -> BaseField {
        roots
            .iter()
            .fold(BaseField::from_u32_unchecked(0), |acc, &r| {
                poseidon_hash_pair(acc, r)
            })
    }

    fn verify_stwo_proof(
        preprocessed_circuit: &PreprocessedCircuit,
        circuit_proof: CircuitProof,
    ) {
        let circuit_prover::prover::CircuitProof {
            pcs_config,
            claim,
            interaction_pow_nonce,
            interaction_claim,
            components,
            stark_proof,
            channel_salt,
        } = circuit_proof;
        assert!(stark_proof.is_ok());
        let proof = stark_proof.expect("proof generation failed");

        let verifier_channel = &mut Blake2sM31Channel::default();
        verifier_channel.mix_felts(&[channel_salt.into()]);
        pcs_config.mix_into(verifier_channel);
        let commitment_scheme =
            &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

        let sizes = TreeVec::concat_cols(components.iter().map(|c| c.trace_log_degree_bounds()));

        commitment_scheme.commit(
            proof.proof.commitments[0],
            &preprocessed_circuit.preprocessed_trace.log_sizes(),
            verifier_channel,
        );
        claim.mix_into(verifier_channel);
        commitment_scheme.commit(proof.proof.commitments[1], &sizes[1], verifier_channel);
        verifier_channel.verify_pow_nonce(INTERACTION_POW_BITS, interaction_pow_nonce);
        verifier_channel.mix_u64(interaction_pow_nonce);
        let interaction_elements = CircuitInteractionElements::draw(verifier_channel);
        interaction_claim.mix_into(verifier_channel);
        commitment_scheme.commit(proof.proof.commitments[2], &sizes[2], verifier_channel);

        stwo::core::verifier::verify_ex(
            &components
                .iter()
                .map(|c| c.as_ref())
                .collect::<Vec<&dyn Component>>(),
            verifier_channel,
            commitment_scheme,
            proof.proof,
            true,
        )
        .expect("stark verification failed");

        assert_eq!(
            lookup_sum(
                &claim,
                &interaction_claim,
                &interaction_elements,
                &preprocessed_circuit.params.output_addresses,
                preprocessed_circuit.params.n_blake_gates
            ),
            QM31::zero()
        );
    }

    #[test]
    fn test_recursive_offer_4_deposits() {
        let token_bf = bf(42);
        // No recipient for offer accumulation.
        let recipient_bf = bf(777); // used in leaf withdraw proofs only

        let deposits: [(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField); 4] = [
            (bf(100), bf(10), bf(11), bf(1001), bf(21), bf(31)),
            (bf(200), bf(20), bf(22), bf(1002), bf(22), bf(32)),
            (bf(150), bf(15), bf(33), bf(1003), bf(23), bf(33)),
            (bf(50), bf(5), bf(44), bf(1004), bf(24), bf(34)),
        ];
        let expected_total: u32 = 500;

        let mut tree = OffchainMerkleTree::new(4);
        for &(amount, refund_amount, secret, nullifier, ..) in &deposits {
            let sn = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, amount + refund_amount);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        let withdraw_bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(|&(amount, refund_amount, secret, nullifier, refund_secret, refund_nullifier)| {
                make_withdraw_bundle(
                    &tree,
                    amount,
                    refund_amount,
                    secret,
                    nullifier,
                    refund_secret,
                    refund_nullifier,
                    token_bf,
                    recipient_bf,
                )
            })
            .collect();

        let [w0, w1, w2, w3]: [ProofBundle; 4] =
            withdraw_bundles.try_into().expect("4 deposit proofs");

        let null_bundle = make_bundle(build_null_offer_context(m31(token_bf)));

        println!("[roots] null offer circuit:  {:?}", null_bundle.preprocessed_root);
        println!("[roots] withdraw circuit:    {:?}", w0.preprocessed_root);

        let rec_0 = make_bundle(build_recursive_offer_context(
            &null_bundle.preprocessed,
            null_bundle.proof,
            &w0.preprocessed,
            w0.proof,
        ));
        println!("[roots] rec step 1 (null+w0): {:?}", rec_0.preprocessed_root);
        let rec_step_1_hash: HashValue<QM31> = rec_0.preprocessed_root.into();
        println!("[roots] rec step 1 hash value: {:?}", rec_step_1_hash);

        let rec_1 = make_bundle(build_recursive_offer_context(
            &rec_0.preprocessed,
            rec_0.proof,
            &w1.preprocessed,
            w1.proof,
        ));
        println!("[roots] rec step 2 (rec+w1): {:?}", rec_1.preprocessed_root);
        let rec_step_2_hash: HashValue<QM31> = rec_1.preprocessed_root.into();
        println!("[roots] rec step 2 hash value: {:?}", rec_step_2_hash);

        let rec_2 = make_bundle(build_recursive_offer_context(
            &rec_1.preprocessed,
            rec_1.proof,
            &w2.preprocessed,
            w2.proof,
        ));
        println!("[roots] rec step 3 (rec+w2): {:?}", rec_2.preprocessed_root);
        let rec_step_3_hash: HashValue<QM31> = rec_2.preprocessed_root.into();
        println!("[roots] rec step 3 hash value: {:?}", rec_step_3_hash);

        let final_bundle = make_bundle(build_recursive_offer_context(
            &rec_2.preprocessed,
            rec_2.proof,
            &w3.preprocessed,
            w3.proof,
        ));
        println!("[roots] rec step 4 (rec+w3): {:?}", final_bundle.preprocessed_root);
        println!();
        println!("Server allowlist roots (offer circuit):");
        let null_hash: HashValue<QM31> = null_bundle.preprocessed_root.into();
        println!("  NULL_OFFER_CIRCUIT_ROOT:        {:?}", null_hash);
        println!("  RECURSIVE_OFFER_STEP1_ROOT:     {:?}", rec_step_1_hash);
        println!("  RECURSIVE_OFFER_STEP2_ROOT:     {:?}", rec_step_2_hash);
        println!("  RECURSIVE_OFFER_STABLE_ROOT:    {:?}", rec_step_3_hash);
        println!("  (step3 == step4: {})", rec_2.preprocessed_root == final_bundle.preprocessed_root);

        let out = &final_bundle.proof.claim.output_values;

        assert_eq!(
            out[IDX_AMOUNT],
            QM31::from(expected_total),
            "final accumulated amount must equal 500"
        );
        assert_eq!(out[IDX_TOKEN], m31(token_bf), "token must be unchanged");

        let roots: Vec<BaseField> = deposits.iter().map(|_| tree.root()).collect();
        let expected_root_acc = compute_root_chain(&roots);
        assert_eq!(
            out[IDX_ROOT_ACC],
            m31(expected_root_acc),
            "root_acc must match off-chain poseidon chain"
        );

        let nullifiers: Vec<BaseField> = deposits.iter().map(|&(_, _, _, n, ..)| n).collect();
        let expected_nullifier_acc = compute_nullifier_chain(&nullifiers);
        assert_eq!(
            out[IDX_NULLIFIER_ACC],
            m31(expected_nullifier_acc),
            "nullifier_acc must match off-chain poseidon chain"
        );

        verify_stwo_proof(&final_bundle.preprocessed, final_bundle.proof);
    }

    /// Same as test_recursive_offer_root_stabilises but uses depth-31 tree (production depth).
    /// Run this test to get the correct allowlist roots for the trusted server.
    #[test]
    fn test_recursive_offer_root_stabilises_depth31() {
        let token_bf = bf(42);
        let recipient_bf = bf(777);

        let deposits: [(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField); 4] = [
            (bf(75), bf(5), bf(10), bf(2001), bf(20), bf(30)),
            (bf(125), bf(15), bf(11), bf(2002), bf(21), bf(31)),
            (bf(50), bf(5), bf(12), bf(2003), bf(22), bf(32)),
            (bf(250), bf(25), bf(13), bf(2004), bf(23), bf(33)),
        ];

        let mut tree = OffchainMerkleTree::new(31);
        for &(amount, refund, secret, nullifier, ..) in &deposits {
            let sn = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, amount + refund);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        let bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(|&(amount, refund, secret, nullifier, rs, rn)| {
                make_withdraw_bundle(&tree, amount, refund, secret, nullifier, rs, rn, token_bf, recipient_bf)
            })
            .collect();
        let [w0, w1, w2, w3]: [ProofBundle; 4] = bundles.try_into().expect("4 proofs");

        let null_bundle = make_bundle(build_null_offer_context(m31(token_bf)));

        let rec_0 = make_bundle(build_recursive_offer_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &w0.preprocessed, w0.proof,
        ));
        let rec_1 = make_bundle(build_recursive_offer_context(
            &rec_0.preprocessed, rec_0.proof,
            &w1.preprocessed, w1.proof,
        ));
        let rec_2 = make_bundle(build_recursive_offer_context(
            &rec_1.preprocessed, rec_1.proof,
            &w2.preprocessed, w2.proof,
        ));
        let final_bundle = make_bundle(build_recursive_offer_context(
            &rec_2.preprocessed, rec_2.proof,
            &w3.preprocessed, w3.proof,
        ));

        println!();
        println!("=== Offer circuit allowlist roots (depth-31, production) ===");
        let null_hash: HashValue<QM31> = null_bundle.preprocessed_root.into();
        let step1_hash: HashValue<QM31> = rec_0.preprocessed_root.into();
        let step2_hash: HashValue<QM31> = rec_1.preprocessed_root.into();
        let stable_hash: HashValue<QM31> = rec_2.preprocessed_root.into();
        println!("NULL_OFFER_CIRCUIT_ROOT:     {:?}", null_hash);
        println!("RECURSIVE_OFFER_STEP1_ROOT:  {:?}", step1_hash);
        println!("RECURSIVE_OFFER_STEP2_ROOT:  {:?}", step2_hash);
        println!("RECURSIVE_OFFER_STABLE_ROOT: {:?}", stable_hash);
        println!("step3 == step4: {}", rec_2.preprocessed_root == final_bundle.preprocessed_root);
        println!("============================================================");

        assert_eq!(
            rec_2.preprocessed_root, final_bundle.preprocessed_root,
            "recursive offer root must stabilise from step 3 (depth-31)"
        );
    }

    /// Confirms recursive offer circuit stable root is reached at step 3.
    /// Prints 4 allowlist roots needed by the trusted server.
    #[test]
    fn test_recursive_offer_root_stabilises() {
        let token_bf = bf(42);
        let recipient_bf = bf(777);

        let deposits: [(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField); 4] = [
            (bf(75), bf(5), bf(10), bf(2001), bf(20), bf(30)),
            (bf(125), bf(15), bf(11), bf(2002), bf(21), bf(31)),
            (bf(50), bf(5), bf(12), bf(2003), bf(22), bf(32)),
            (bf(250), bf(25), bf(13), bf(2004), bf(23), bf(33)),
        ];

        let mut tree = OffchainMerkleTree::new(4);
        for &(amount, refund, secret, nullifier, ..) in &deposits {
            let sn = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, amount + refund);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        let bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(|&(amount, refund, secret, nullifier, rs, rn)| {
                make_withdraw_bundle(&tree, amount, refund, secret, nullifier, rs, rn, token_bf, recipient_bf)
            })
            .collect();
        let [w0, w1, w2, w3]: [ProofBundle; 4] = bundles.try_into().expect("4 proofs");

        let null_bundle = make_bundle(build_null_offer_context(m31(token_bf)));

        let rec_0 = make_bundle(build_recursive_offer_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &w0.preprocessed, w0.proof,
        ));
        let rec_1 = make_bundle(build_recursive_offer_context(
            &rec_0.preprocessed, rec_0.proof,
            &w1.preprocessed, w1.proof,
        ));
        let rec_2 = make_bundle(build_recursive_offer_context(
            &rec_1.preprocessed, rec_1.proof,
            &w2.preprocessed, w2.proof,
        ));
        let final_bundle = make_bundle(build_recursive_offer_context(
            &rec_2.preprocessed, rec_2.proof,
            &w3.preprocessed, w3.proof,
        ));

        println!();
        println!("=== Offer circuit allowlist roots ===");
        let null_hash: HashValue<QM31> = null_bundle.preprocessed_root.into();
        let step1_hash: HashValue<QM31> = rec_0.preprocessed_root.into();
        let step2_hash: HashValue<QM31> = rec_1.preprocessed_root.into();
        let stable_hash: HashValue<QM31> = rec_2.preprocessed_root.into();
        println!("NULL_OFFER_CIRCUIT_ROOT:     {:?}", null_hash);
        println!("RECURSIVE_OFFER_STEP1_ROOT:  {:?}", step1_hash);
        println!("RECURSIVE_OFFER_STEP2_ROOT:  {:?}", step2_hash);
        println!("RECURSIVE_OFFER_STABLE_ROOT: {:?}", stable_hash);
        println!("step3 == step4: {}", rec_2.preprocessed_root == final_bundle.preprocessed_root);
        println!("=====================================");

        assert_eq!(
            rec_2.preprocessed_root, final_bundle.preprocessed_root,
            "recursive offer root must stabilise from step 3"
        );
    }

    /// Helper: build the accumulated proof for N deposits from a depth-31 tree.
    fn make_accumulated_bundle(
        n_deposits: usize,
        token_bf: BaseField,
        recipient_bf: BaseField,
    ) -> (OffchainMerkleTree, Vec<BaseField>, Vec<BaseField>, ProofBundle) {
        let deposits: Vec<(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField)> =
            (0..n_deposits)
                .map(|i| (bf((100 + i * 50) as u32), bf(10), bf((10 + i) as u32), bf((1000 + i) as u32), bf((20 + i) as u32), bf((30 + i) as u32)))
                .collect();

        let mut tree = OffchainMerkleTree::new(31);
        for &(amount, refund, secret, nullifier, ..) in &deposits {
            let sn = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, amount + refund);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        let withdraw_bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(|&(amount, refund, secret, nullifier, rs, rn)| {
                make_withdraw_bundle(&tree, amount, refund, secret, nullifier, rs, rn, token_bf, recipient_bf)
            })
            .collect();

        let nullifiers: Vec<BaseField> = deposits.iter().map(|&(_, _, _, n, ..)| n).collect();
        let roots: Vec<BaseField> = deposits.iter().map(|_| tree.root()).collect();

        let null_bundle = make_bundle(build_null_offer_context(m31(token_bf)));
        let mut acc = make_bundle(build_recursive_offer_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &withdraw_bundles[0].preprocessed,
            // SAFETY: we need to move out of the vec; rebuild the proof for index 0
            {
                let ctx = build_withdraw_merkle_context_from_offchain_tree(
                    &tree,
                    deposits[0].2, deposits[0].3, deposits[0].0 + deposits[0].1,
                    token_bf, deposits[0].0, deposits[0].4, deposits[0].5, deposits[0].1, recipient_bf,
                ).expect("rebuild withdraw 0");
                make_bundle(ctx).proof
            },
        ));
        for i in 1..n_deposits {
            let ctx = build_withdraw_merkle_context_from_offchain_tree(
                &tree,
                deposits[i].2, deposits[i].3, deposits[i].0 + deposits[i].1,
                token_bf, deposits[i].0, deposits[i].4, deposits[i].5, deposits[i].1, recipient_bf,
            ).expect("rebuild withdraw");
            let wi = make_bundle(ctx);
            let prev_preprocessed = acc.preprocessed;
            let prev_proof = acc.proof;
            acc = make_bundle(build_recursive_offer_context(
                &prev_preprocessed, prev_proof,
                &wi.preprocessed, wi.proof,
            ));
        }

        (tree, nullifiers, roots, acc)
    }

    /// Prints terminal circuit allowlist roots for depth-31.
    /// Run this to get roots to add to trusted-stwo-server/src/verify.rs.
    #[test]
    fn test_offer_terminal_roots_depth31() {
        let token_bf = bf(42);
        let recipient_bf = bf(777);
        let offer_secret = bf(111);
        let offer_nullifier = bf(222);
        let fiat_amount = bf(50000);
        let currency_hash = bf(777);
        let rev_tag_hash = bf(888);
        let offer_refund_secret = bf(991);
        let offer_refund_nullifier = bf(992);

        // Terminal after step1 accumulated (N=1).
        let (_, _, _, acc1) = make_accumulated_bundle(1, token_bf, recipient_bf);
        let terminal1 = make_bundle(build_offer_terminal_context(
            &acc1.preprocessed, acc1.proof,
            m31(offer_secret), m31(offer_nullifier), m31(fiat_amount),
            m31(currency_hash), m31(rev_tag_hash),
            m31(offer_refund_secret), m31(offer_refund_nullifier),
        ));
        let t1_hash: HashValue<QM31> = terminal1.preprocessed_root.into();
        println!("[terminal] after step1 (N=1): {:?}", t1_hash);

        // Terminal after step2 accumulated (N=2).
        let (_, _, _, acc2) = make_accumulated_bundle(2, token_bf, recipient_bf);
        let terminal2 = make_bundle(build_offer_terminal_context(
            &acc2.preprocessed, acc2.proof,
            m31(offer_secret), m31(offer_nullifier), m31(fiat_amount),
            m31(currency_hash), m31(rev_tag_hash),
            m31(offer_refund_secret), m31(offer_refund_nullifier),
        ));
        let t2_hash: HashValue<QM31> = terminal2.preprocessed_root.into();
        println!("[terminal] after step2 (N=2): {:?}", t2_hash);

        // Terminal after stable accumulated (N=3).
        let (_, _, _, acc3) = make_accumulated_bundle(3, token_bf, recipient_bf);
        let terminal3 = make_bundle(build_offer_terminal_context(
            &acc3.preprocessed, acc3.proof,
            m31(offer_secret), m31(offer_nullifier), m31(fiat_amount),
            m31(currency_hash), m31(rev_tag_hash),
            m31(offer_refund_secret), m31(offer_refund_nullifier),
        ));
        let t3_hash: HashValue<QM31> = terminal3.preprocessed_root.into();
        println!("[terminal] after step3/stable (N=3): {:?}", t3_hash);

        // Terminal after N=4 (should be same as N=3 since accumulator is stable).
        let (_, _, _, acc4) = make_accumulated_bundle(4, token_bf, recipient_bf);
        let terminal4 = make_bundle(build_offer_terminal_context(
            &acc4.preprocessed, acc4.proof,
            m31(offer_secret), m31(offer_nullifier), m31(fiat_amount),
            m31(currency_hash), m31(rev_tag_hash),
            m31(offer_refund_secret), m31(offer_refund_nullifier),
        ));
        let t4_hash: HashValue<QM31> = terminal4.preprocessed_root.into();
        println!("[terminal] after step4 (N=4): {:?}", t4_hash);
        println!("terminal step3 == step4: {}", terminal3.preprocessed_root == terminal4.preprocessed_root);

        println!();
        println!("=== Terminal circuit allowlist roots (depth-31) ===");
        println!("OFFER_TERMINAL_STEP1_ROOT:  {:?}", t1_hash);
        println!("OFFER_TERMINAL_STEP2_ROOT:  {:?}", t2_hash);
        println!("OFFER_TERMINAL_STABLE_ROOT: {:?}", t3_hash);
        println!("===================================================");

        assert_eq!(
            terminal3.preprocessed_root, terminal4.preprocessed_root,
            "terminal circuit root must stabilise from step 3"
        );

        // Verify outputs: offerCommitment is in output[4], offerRefundSnHash in output[6].
        let out = &terminal4.proof.claim.output_values;
        assert_eq!(out[TERMINAL_IDX_TOKEN], m31(token_bf));
        // offerCommitment must be non-zero (non-trivial hash).
        assert_ne!(out[TERMINAL_IDX_OFFER_COMMITMENT], QM31::from(0u32));
        assert_ne!(out[TERMINAL_IDX_OFFER_REFUND_SN_HASH], QM31::from(0u32));
    }
}
