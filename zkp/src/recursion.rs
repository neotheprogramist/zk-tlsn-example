//! Recursion engine: base AIR (proves `n=0`) and step AIR (verifies prev proof
//! in-circuit and binds the new counter via `n_new = prev_n + 1`).
//!
//! Both AIRs are proven via `circuit_prover::prove_circuit_assignment`, which
//! produces structurally identical `circuit_prover`-shape proofs. From step 1
//! onward, every proof's verifier circuit verifies a `circuit_prover`-shape
//! proof — so step 2 onward is uniform recursion.

use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    BaseColumnPool, CircuitProof, SimdBackend, prepare_circuit_proof_for_circuit_verifier,
    prove_circuit_assignment,
};
use circuit_verifier::statement::{CircuitStatement, INTERACTION_POW_BITS};
use circuits::{
    context::{Context, TraceContext, Var},
    ivalue::NoValue,
    ops::{Guess, add, eq, guess, output},
};
use circuits_stark_verifier::{proof::ProofConfig, statement::Statement, verify::verify};
use stwo::core::{
    fields::{m31::M31, qm31::QM31},
    pcs::PcsConfig,
    vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
};

/// All state we keep between steps. Owned values; consumed by `prove_step`.
pub struct ProofRecord {
    pub circuit_proof: CircuitProof<Blake2sM31MerkleHasher>,
    pub preprocessed: PreprocessedCircuit,
    pub counter: M31,
}

/// Builds + proves the base circuit. Public output is the counter `n`,
/// fixed to 0 by outputting `context.zero()`.
pub fn prove_base() -> ProofRecord {
    let mut context = TraceContext::default();
    let zero_var = context.zero();
    output(&mut context, zero_var);
    context.finalize_guessed_vars();
    context.validate_circuit();

    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let circuit_proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        PcsConfig::default(),
    );

    ProofRecord {
        circuit_proof,
        preprocessed,
        counter: M31::from(0u32),
    }
}

/// Inductive step. Consumes `prev` and produces the next record:
///   - verifies `prev`'s `circuit_prover` proof in-circuit
///   - constrains `n_new == prev_n + 1`
///   - outputs `n_new` as the new public output
pub fn prove_step(prev: ProofRecord) -> ProofRecord {
    let ProofRecord {
        circuit_proof: prev_proof,
        preprocessed: prev_pp,
        counter: prev_n,
    } = prev;

    // Extract metadata before consuming `prev_proof`.
    let pcs_config = prev_proof.pcs_config;
    let preprocessed_root_hash = prev_proof
        .stark_proof
        .as_ref()
        .expect("base/step prover must succeed")
        .proof
        .commitments[0];
    let preprocessed_root = preprocessed_root_hash.into();
    let output_addresses = prev_pp.params.output_addresses.clone();
    let n_blake_gates = prev_pp.params.n_blake_gates;
    let pp_ids = prev_pp.preprocessed_trace.ids();
    let pp_log_sizes = prev_pp.preprocessed_trace.log_sizes();
    let prev_output_values = prev_proof.claim.output_values.clone();

    // Reconstruct the `ProofConfig` `prev_proof` was sealed with. Required to
    // re-derive channel-mixing constants when lifting the proof into the circuit.
    let proof_config_for_prev = {
        let mut shape_ctx = Context::<NoValue>::default();
        let stmt = CircuitStatement::<NoValue>::new(
            &mut shape_ctx,
            &output_addresses,
            &prev_output_values,
            n_blake_gates,
            pp_ids.clone(),
            pp_log_sizes.clone(),
            preprocessed_root,
        );
        ProofConfig::from_statement(
            &stmt,
            vec![true; stmt.get_components().len()],
            &pcs_config,
            INTERACTION_POW_BITS,
        )
    };

    // Lift the prev proof into in-circuit form.
    let (prev_proof_qm31, _public_data) =
        prepare_circuit_proof_for_circuit_verifier(prev_proof, &proof_config_for_prev);

    // Build the new context: verifier circuit + counter constraint + output.
    let mut context = TraceContext::default();

    let statement = CircuitStatement::new(
        &mut context,
        &output_addresses,
        &prev_output_values,
        n_blake_gates,
        pp_ids,
        pp_log_sizes,
        preprocessed_root,
    );
    // Capture the Var that `verify(...)` will bind to prev's actual public output.
    let prev_n_var: Var = statement.output_values[0];

    let proof_config_for_verify = ProofConfig::from_statement(
        &statement,
        vec![true; statement.get_components().len()],
        &pcs_config,
        INTERACTION_POW_BITS,
    );
    let proof_vars = prev_proof_qm31.guess(&mut context);

    verify(
        &mut context,
        &proof_vars,
        &proof_config_for_verify,
        &statement,
    );

    // Inductive constraint: n_new == prev_n + 1.
    let one_var = context.one();
    let computed_new = add(&mut context, prev_n_var, one_var);
    let new_counter = prev_n + M31::from(1u32);
    let n_new_var = guess(&mut context, QM31::from(new_counter));
    eq(&mut context, n_new_var, computed_new);

    output(&mut context, n_new_var);

    context.finalize_guessed_vars();
    context.validate_circuit();

    let preprocessed = PreprocessedCircuit::preprocess_circuit(&mut context);
    let circuit_proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        PcsConfig::default(),
    );

    ProofRecord {
        circuit_proof,
        preprocessed,
        counter: new_counter,
    }
}

/// Returns the byte-size estimate of the underlying StarkProof.
pub fn proof_size(record: &ProofRecord) -> usize {
    record
        .circuit_proof
        .stark_proof
        .as_ref()
        .map(|p| p.proof.size_estimate())
        .unwrap_or(0)
}
