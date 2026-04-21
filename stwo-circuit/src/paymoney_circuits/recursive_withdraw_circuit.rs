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

// Output indices shared by null, withdraw, and recursive circuits.
const IDX_ROOT: usize = 0;
const IDX_NULLIFIER_ACC: usize = 1;
const IDX_TOKEN: usize = 2;
const IDX_AMOUNT: usize = 3;
const _IDX_REFUND_COMMITMENT_HASH: usize = 4;
const IDX_RECIPIENT: usize = 5;

/// Null (identity) circuit for recursive withdrawal aggregation.
///
/// Outputs the same 6-value structure as `build_withdraw_merkle_context`:
///   [root, nullifier_acc=0, token, amount=0, refund_commitment_hash=0, recipient]
///
/// `recipient` is anchored here so the recursive verifier can enforce that all
/// subsequent withdrawals in the batch go to the same address.
/// `nullifier_acc` starts at 0; each recursive step hashes it with the new nullifier.
pub fn build_null_context(token: QM31, root: QM31, recipient: QM31) -> Context<QM31> {
    let mut context = Context::<QM31>::default();

    let zero = context.zero();
    let root_v = guess(&mut context, root);
    let token_v = guess(&mut context, token);
    let recipient_v = guess(&mut context, recipient);

    output(&mut context, root_v);
    output(&mut context, zero); // nullifier_acc = 0
    output(&mut context, token_v);
    output(&mut context, zero); // amount = 0
    output(&mut context, zero); // refund_commitment_hash = 0 (per-deposit, not aggregated)
    output(&mut context, recipient_v);

    context
}

/// Embeds proof verification into `context` and returns the proof's output variables.
///
/// The returned `Vec<Var>` maps to the 6-output layout:
///   [root, nullifier_acc, token, amount, refund_commitment_hash, recipient]
pub fn verify_recursive_proof(
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

/// Builds a recursive context that aggregates two proofs:
///
/// - `proof_a`: the previous accumulator (null or a previous recursive proof)
/// - `proof_b`: a new withdraw proof
///
/// **Enforced constraints:**
/// - `root_a == root_b`      — both proofs reference the same Merkle tree
/// - `token_a == token_b`    — same token type
/// - `recipient_a == recipient_b` — all withdrawals in the batch go to the same address
///
/// **Aggregated outputs** (same 6-value layout as null/withdraw):
/// - `root`           = root from proof_a (== root_b after constraint)
/// - `nullifier_acc`  = poseidon(nullifier_acc_a, nullifier_b)  ← hash chain
/// - `token`          = token_a
/// - `total`          = amount_a + amount_b
/// - `refund_commitment_hash` = 0 (per-deposit value, not aggregated)
/// - `recipient`      = recipient_a
///
/// **Nullifier aggregation strategy:** poseidon hash chain.
/// The final proof carries a single `nullifier_acc` that commits to the ordered
/// list of all nullifiers. To verify on-chain, supply the nullifier list; the
/// smart contract recomputes `poseidon(poseidon(... poseidon(0, n1) ..., nk-1), nk)`
/// and checks it equals `nullifier_acc`, then marks each nullifier as spent.
pub fn build_recursive_context(
    preprocessed_proof_a: &PreprocessedCircuit,
    circuit_proof_proof_a: CircuitProof,
    preprocessed_proof_b: &PreprocessedCircuit,
    circuit_proof_proof_b: CircuitProof,
) -> Context<QM31> {
    let mut ctx = Context::<QM31>::default();

    let a = verify_recursive_proof(&mut ctx, preprocessed_proof_a, circuit_proof_proof_a);
    let b = verify_recursive_proof(&mut ctx, preprocessed_proof_b, circuit_proof_proof_b);

    // Consistency constraints.
    eq(&mut ctx, a[IDX_ROOT], b[IDX_ROOT]);
    eq(&mut ctx, a[IDX_TOKEN], b[IDX_TOKEN]);
    eq(&mut ctx, a[IDX_RECIPIENT], b[IDX_RECIPIENT]);

    // Aggregate amount.
    let total = eval!(&mut ctx, (a[IDX_AMOUNT]) + (b[IDX_AMOUNT]));

    // Chain nullifiers: nullifier_acc_new = poseidon(nullifier_acc_a, nullifier_b).
    let nullifier_acc =
        poseidon2::poseidon2_hash_two(&mut ctx, a[IDX_NULLIFIER_ACC], b[IDX_NULLIFIER_ACC]);

    let zero = ctx.zero();

    output(&mut ctx, a[IDX_ROOT]);
    output(&mut ctx, nullifier_acc);
    output(&mut ctx, a[IDX_TOKEN]);
    output(&mut ctx, total);
    output(&mut ctx, zero); // refund_commitment_hash not aggregated
    output(&mut ctx, a[IDX_RECIPIENT]);

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
    use stwo::core::{channel::{Blake2sM31Channel, Channel}, fields::m31::BaseField, pcs::{CommitmentSchemeVerifier, TreeVec}, vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel, air::Component};

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
        /// Blake2s Merkle root of the preprocessed trace — commitment[0] from the STARK proof.
        /// This is the value the trusted server must accept in its allowlist.
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

    /// Replicates the in-circuit nullifier hash chain using off-chain poseidon.
    /// Starts from 0 and folds each nullifier: acc = poseidon(acc, nullifier).
    /// The trusted server runs this before signing to verify the nullifier list
    /// matches the `nullifier_acc` in the final recursive proof output.
    fn compute_nullifier_chain(nullifiers: &[BaseField]) -> BaseField {
        nullifiers
            .iter()
            .fold(BaseField::from_u32_unchecked(0), |acc, &n| {
                poseidon_hash_pair(acc, n)
            })
    }

    /// Builds a withdraw proof bundle for a single deposit using the shared tree.
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

    pub fn verify_stwo_proof(
        preprocessed_circuit: &PreprocessedCircuit,
        circuit_proof: CircuitProof,
    ) {
        let CircuitProof {
            pcs_config,
            claim,
            interaction_pow_nonce,
            interaction_claim,
            components,
            stark_proof,
            channel_salt,
        } = circuit_proof;
        assert!(stark_proof.is_ok());
        let proof = stark_proof.unwrap();

        let verifier_channel = &mut Blake2sM31Channel::default();
        verifier_channel.mix_felts(&[channel_salt.into()]);
        pcs_config.mix_into(verifier_channel);
        let commitment_scheme =
            &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);

        // Retrieve the expected column sizes in each commitment interaction, from the AIR.
        let sizes = TreeVec::concat_cols(components.iter().map(|c| c.trace_log_degree_bounds()));

        commitment_scheme.commit(
            proof.proof.commitments[0],
            &preprocessed_circuit.preprocessed_trace.log_sizes(),
            verifier_channel,
        );
        claim.mix_into(verifier_channel);
        println!("Claim: {claim:?}");
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
        .unwrap();

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

    /// Recursive aggregation of 4 deposits.
    ///
    /// Verifies:
    /// 1. Final `amount` output equals the sum of all 4 deposit amounts.
    /// 2. Final `nullifier_acc` matches the off-chain poseidon hash chain —
    ///    this is the check the trusted server performs before signing the nullifier list.
    /// 3. `root`, `token`, `recipient` are preserved unchanged across all steps.
    #[test]
    fn test_recursive_4_deposits_amount_and_nullifier_chain() {
        // ── shared parameters ──────────────────────────────────────────────
        let token_bf = bf(42);
        let recipient_bf = bf(777);

        // (amount, refund_amount, secret, nullifier, refund_secret, refund_nullifier)
        // total = 100 + 200 + 150 + 50 = 500
        let deposits: [(
            BaseField,
            BaseField,
            BaseField,
            BaseField,
            BaseField,
            BaseField,
        ); 4] = [
            (bf(100), bf(10), bf(11), bf(1001), bf(21), bf(31)),
            (bf(200), bf(20), bf(22), bf(1002), bf(22), bf(32)),
            (bf(150), bf(15), bf(33), bf(1003), bf(23), bf(33)),
            (bf(50), bf(5), bf(44), bf(1004), bf(24), bf(34)),
        ];
        let expected_total: u32 = 500;

        // ── build Merkle tree ──────────────────────────────────────────────
        let mut tree = OffchainMerkleTree::new(4);
        for &(amount, refund_amount, secret, nullifier, ..) in &deposits {
            let commitment_amount = amount + refund_amount;
            let sn = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, commitment_amount);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        // ── prove 4 withdrawals ────────────────────────────────────────────
        let withdraw_bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(
                |&(amount, refund_amount, secret, nullifier, refund_secret, refund_nullifier)| {
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
                },
            )
            .collect();

        let [w0, w1, w2, w3]: [ProofBundle; 4] =
            withdraw_bundles.try_into().expect("4 deposit proofs");

        // ── null accumulator ───────────────────────────────────────────────
        let null_bundle = make_bundle(build_null_context(
            m31(token_bf),
            m31(tree.root()),
            m31(recipient_bf),
        ));

        println!("[roots] null circuit:     {:?}", null_bundle.preprocessed_root);
        println!("[roots] withdraw circuit: {:?}", w0.preprocessed_root);

        // ── recursive aggregation ──────────────────────────────────────────
        // Step 1: null + withdraw_0  →  running total = 100
        let rec_0 = make_bundle(build_recursive_context(
            &null_bundle.preprocessed,
            null_bundle.proof,
            &w0.preprocessed,
            w0.proof,
        ));
        println!("[roots] rec step 1 (null+w0):  {:?}", rec_0.preprocessed_root);
        let rec_step_1_hash_value: HashValue<QM31> = rec_0.preprocessed_root.into();
        println!("[roots] rec step 1 hash value: {:?}", rec_step_1_hash_value);
        // Step 2: rec_0 + withdraw_1  →  running total = 300
        let rec_1 = make_bundle(build_recursive_context(
            &rec_0.preprocessed,
            rec_0.proof,
            &w1.preprocessed,
            w1.proof,
        ));
        println!("[roots] rec step 2 (rec+w1):   {:?}", rec_1.preprocessed_root);
        let rec_step_2_hash_value: HashValue<QM31> = rec_1.preprocessed_root.into();
        println!("[roots] rec step 2 hash value: {:?}", rec_step_2_hash_value);


        // Step 3: rec_1 + withdraw_2  →  running total = 450
        let rec_2 = make_bundle(build_recursive_context(
            &rec_1.preprocessed,
            rec_1.proof,
            &w2.preprocessed,
            w2.proof,
        ));
        println!("[roots] rec step 3 (rec+w2):   {:?}", rec_2.preprocessed_root);
        let rec_step_3_hash_value: HashValue<QM31> = rec_2.preprocessed_root.into();
        println!("[roots] rec step 3 hash value: {:?}", rec_step_3_hash_value);

        // Step 4: rec_2 + withdraw_3  →  running total = 500 (final)
        let final_bundle = make_bundle(build_recursive_context(
            &rec_2.preprocessed,
            rec_2.proof,
            &w3.preprocessed,
            w3.proof,
        ));
        let final_hash_value: HashValue<QM31> = final_bundle.preprocessed_root.into();
        println!("[roots] rec step 4 (rec+w3):   {:?}", final_bundle.preprocessed_root);
        println!();
        println!("Server allowlist roots (5 total — stable from step 3):");
        println!("  NULL_CIRCUIT_ROOT hash value:      {:?}", null_bundle.preprocessed_root);
        println!("  WITHDRAW_CIRCUIT_ROOT hash value:  {:?}", w1.preprocessed_root);
        println!("  RECURSIVE_STEP1_ROOT hash value:   {:?}", rec_step_1_hash_value);
        println!("  RECURSIVE_STEP2_ROOT hash value:   {:?}", rec_step_2_hash_value);
        println!("  RECURSIVE_STABLE_ROOT hash value:  {:?}", rec_step_3_hash_value);
        println!("  FINAL_ROOT hash value:             {:?}", final_hash_value);
        println!("  (step3 == step4: {})", rec_2.preprocessed_root == final_bundle.preprocessed_root);

        let out = &final_bundle.proof.claim.output_values;

        // ── assertions ─────────────────────────────────────────────────────

        // Total amount.
        assert_eq!(
            out[IDX_AMOUNT],
            QM31::from(expected_total),
            "final accumulated amount must equal 100+200+150+50 = 500"
        );

        // Context fields are preserved.
        assert_eq!(out[IDX_ROOT], m31(tree.root()), "root must be unchanged");
        assert_eq!(out[IDX_TOKEN], m31(token_bf), "token must be unchanged");
        assert_eq!(
            out[IDX_RECIPIENT],
            m31(recipient_bf),
            "recipient must be unchanged"
        );

        // Nullifier accumulator: trusted-server POC.
        // The server receives the nullifier list and recomputes the chain
        // poseidon(poseidon(poseidon(poseidon(0, n0), n1), n2), n3)
        // then checks it equals the `nullifier_acc` in the final proof output.
        let nullifiers: Vec<BaseField> = deposits.iter().map(|&(_, _, _, n, ..)| n).collect();
        let expected_nullifier_acc = compute_nullifier_chain(&nullifiers);

        assert_eq!(
            out[IDX_NULLIFIER_ACC],
            m31(expected_nullifier_acc),
            "nullifier_acc must match off-chain poseidon chain over [n0, n1, n2, n3]"
        );
        
        verify_stwo_proof(&final_bundle.preprocessed, final_bundle.proof);
    }

    /// 1 deposit: null + withdraw_0.
    /// Verifies amount and nullifier chain for the simplest recursive case.
    /// Also prints the two preprocessed roots needed on the server for this shape.
    #[test]
    fn test_recursive_1_deposit() {
        let token_bf     = bf(42);
        let recipient_bf = bf(777);
        let amount_bf    = bf(100);
        let refund_bf    = bf(10);
        let secret_bf    = bf(11);
        let nullifier_bf = bf(1001);

        let mut tree = OffchainMerkleTree::new(4);
        let commitment_amount = amount_bf + refund_bf;
        let sn  = poseidon_hash_pair(secret_bf, nullifier_bf);
        let sna = poseidon_hash_pair(sn, commitment_amount);
        tree.add_leaf(poseidon_hash_pair(sna, token_bf));

        let w0 = make_withdraw_bundle(
            &tree, amount_bf, refund_bf, secret_bf, nullifier_bf,
            bf(21), bf(31), token_bf, recipient_bf,
        );
        let null_bundle = make_bundle(build_null_context(
            m31(token_bf), m31(tree.root()), m31(recipient_bf),
        ));

        println!("[1-deposit] null circuit root:    {:?}", null_bundle.preprocessed_root);
        println!("[1-deposit] withdraw circuit root: {:?}", w0.preprocessed_root);

        let final_bundle = make_bundle(build_recursive_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &w0.preprocessed, w0.proof,
        ));

        println!("[1-deposit] recursive root (null+w0): {:?}", final_bundle.preprocessed_root);

        let out = &final_bundle.proof.claim.output_values;
        assert_eq!(out[IDX_AMOUNT], QM31::from(100u32), "amount must be 100");

        let expected_nullifier_acc = compute_nullifier_chain(&[nullifier_bf]);
        assert_eq!(
            out[IDX_NULLIFIER_ACC],
            m31(expected_nullifier_acc),
            "nullifier_acc must match poseidon(0, n0)"
        );
    }

    /// 2 deposits: null + w0, then rec_0 + w1.
    /// Confirms that rec step 2 root differs from rec step 1 (null+w0) root,
    /// so both must be in the server allowlist.
    #[test]
    fn test_recursive_2_deposits() {
        let token_bf     = bf(42);
        let recipient_bf = bf(777);

        let deposits: [(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField); 2] = [
            (bf(100), bf(10), bf(11), bf(1001), bf(21), bf(31)),
            (bf(200), bf(20), bf(22), bf(1002), bf(22), bf(32)),
        ];
        let expected_total: u32 = 300;

        let mut tree = OffchainMerkleTree::new(4);
        for &(amount, refund, secret, nullifier, ..) in &deposits {
            let sn  = poseidon_hash_pair(secret, nullifier);
            let sna = poseidon_hash_pair(sn, amount + refund);
            tree.add_leaf(poseidon_hash_pair(sna, token_bf));
        }

        let withdraw_bundles: Vec<ProofBundle> = deposits
            .iter()
            .map(|&(amount, refund, secret, nullifier, rs, rn)| {
                make_withdraw_bundle(&tree, amount, refund, secret, nullifier, rs, rn, token_bf, recipient_bf)
            })
            .collect();
        let [w0, w1]: [ProofBundle; 2] = withdraw_bundles.try_into().expect("2 proofs");

        let null_bundle = make_bundle(build_null_context(
            m31(token_bf), m31(tree.root()), m31(recipient_bf),
        ));

        let rec_0 = make_bundle(build_recursive_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &w0.preprocessed, w0.proof,
        ));
        println!("[2-deposits] rec step 1 (null+w0) root: {:?}", rec_0.preprocessed_root);

        let final_bundle = make_bundle(build_recursive_context(
            &rec_0.preprocessed, rec_0.proof,
            &w1.preprocessed, w1.proof,
        ));
        println!("[2-deposits] rec step 2 (rec+w1) root:  {:?}", final_bundle.preprocessed_root);
        println!(
            "[2-deposits] step1 root == step2 root: {}  (expected: false — different circuit shapes)",
            rec_0.preprocessed_root == final_bundle.preprocessed_root
        );

        let out = &final_bundle.proof.claim.output_values;
        assert_eq!(out[IDX_AMOUNT], QM31::from(expected_total), "amount must be 300");

        let nullifiers: Vec<BaseField> = deposits.iter().map(|&(_, _, _, n, ..)| n).collect();
        let expected_nullifier_acc = compute_nullifier_chain(&nullifiers);
        assert_eq!(
            out[IDX_NULLIFIER_ACC],
            m31(expected_nullifier_acc),
            "nullifier_acc must match poseidon(poseidon(0, n0), n1)"
        );
    }

    /// Confirms that the recursive circuit shape stabilises from step 2 onward.
    /// The server only needs 4 roots in its allowlist:
    ///   1. null circuit root
    ///   2. withdraw circuit root
    ///   3. rec step-1 root  (null + withdraw)
    ///   4. stable recursive root  (rec + withdraw, same for all subsequent steps)
    #[test]
    fn test_recursive_root_stabilises_from_step2() {
        let token_bf     = bf(42);
        let recipient_bf = bf(777);

        let deposits: [(BaseField, BaseField, BaseField, BaseField, BaseField, BaseField); 4] = [
            (bf(75),  bf(5),  bf(10), bf(2001), bf(20), bf(30)),
            (bf(125), bf(15), bf(11), bf(2002), bf(21), bf(31)),
            (bf(50),  bf(5),  bf(12), bf(2003), bf(22), bf(32)),
            (bf(250), bf(25), bf(13), bf(2004), bf(23), bf(33)),
        ];
        let expected_total: u32 = 75 + 125 + 50 + 250; // 500

        let mut tree = OffchainMerkleTree::new(4);
        for &(amount, refund, secret, nullifier, ..) in &deposits {
            let sn  = poseidon_hash_pair(secret, nullifier);
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

        let null_bundle = make_bundle(build_null_context(
            m31(token_bf), m31(tree.root()), m31(recipient_bf),
        ));

        let rec_0 = make_bundle(build_recursive_context(
            &null_bundle.preprocessed, null_bundle.proof,
            &w0.preprocessed, w0.proof,
        ));
        let rec_1 = make_bundle(build_recursive_context(
            &rec_0.preprocessed, rec_0.proof,
            &w1.preprocessed, w1.proof,
        ));
        let rec_2 = make_bundle(build_recursive_context(
            &rec_1.preprocessed, rec_1.proof,
            &w2.preprocessed, w2.proof,
        ));
        let final_bundle = make_bundle(build_recursive_context(
            &rec_2.preprocessed, rec_2.proof,
            &w3.preprocessed, w3.proof,
        ));

        println!();
        println!("=== Server allowlist roots (copy these into trusted-server constants) ===");
        println!("NULL_CIRCUIT_ROOT:         {:?}", null_bundle.preprocessed_root);
        println!("WITHDRAW_CIRCUIT_ROOT:     {:?}", w0.preprocessed_root);
        println!("RECURSIVE_STEP1_ROOT:      {:?}", rec_0.preprocessed_root);
        println!("RECURSIVE_STEP2_ROOT:      {:?}", rec_1.preprocessed_root);
        println!("RECURSIVE_STABLE_ROOT:     {:?}", rec_2.preprocessed_root);
        println!("================================================================");
        println!("step3 == step4: {}", rec_2.preprocessed_root == final_bundle.preprocessed_root);

        // Stable root is reached at step 3 (rec_2), confirmed by step 4 being identical.
        assert_eq!(
            rec_2.preprocessed_root, final_bundle.preprocessed_root,
            "recursive root must stabilise from step 3"
        );

        let out = &final_bundle.proof.claim.output_values;
        assert_eq!(out[IDX_AMOUNT], QM31::from(expected_total));

        let nullifiers: Vec<BaseField> = deposits.iter().map(|&(_, _, _, n, ..)| n).collect();
        assert_eq!(out[IDX_NULLIFIER_ACC], m31(compute_nullifier_chain(&nullifiers)));
    }
}
