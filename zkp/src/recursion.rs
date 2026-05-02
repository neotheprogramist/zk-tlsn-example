//! Recursion engine: base AIR (proves `n=0`) and step AIR (verifies prev proof
//! in-circuit and binds the new counter via `n_new = prev_n + 1`).
//!
//! Both AIRs are proven via `circuit_prover::prove_circuit_assignment`, which
//! produces structurally identical `circuit_prover`-shape proofs. From step 1
//! onward, every proof's verifier circuit verifies a `circuit_prover`-shape
//! proof — so step 2 onward is uniform recursion.
//!
//! The base AIR's `n=0` claim leans on one un-asserted upstream invariant:
//! `BaseColumnPool::new()` initialises trace index 0 to `M31::zero()`, so
//! `output(context.zero())` writes `0` into the public claim. That invariant
//! is exercised by `tests/recursion.rs` (the chain reaches counter `2`) and
//! by `tests/mutations.rs` (mutating any prev-claim field is rejected by the
//! step prover). If upstream changes the column-pool initialisation, those
//! tests are the tripwire.

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
use stwo::{
    core::{
        fields::{
            m31::{M31, P},
            qm31::QM31,
        },
        fri::FriConfig,
        pcs::PcsConfig,
        vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
    },
    prover::ProvingError,
};
use thiserror::Error;

/// Errors a `prove_*` call can return.
#[derive(Debug, Error)]
pub enum ProverError {
    /// `prove_circuit_assignment` left `stark_proof = Err(_)`. Carries the
    /// upstream cause (e.g. `ConstraintsNotSatisfied`, `InvalidLiftingLogSize`).
    #[error("circuit prover failed: {0}")]
    StarkProofFailed(#[from] ProvingError),
    /// The next counter would equal `M31::P ≡ 0` and silently wrap.
    /// Refuse the step instead.
    #[error("counter would wrap at M31 modulus (chain depth ≈ 2^31 − 1)")]
    CounterOverflow,
}

/// PcsConfig tuned to the highest setting the in-circuit step verifier
/// will tolerate inside browser WASM:
///   security_bits = pow_bits + log_blowup_factor * n_queries = 20 + 1 * 19 = 39.
/// Stwo's `PcsConfig::default()` is `pow_bits=10, log_blowup=1, n_queries=3`
/// → ~13 bits, fine for unit tests, not for anything calling itself a STARK.
/// Upstream agrees: <https://github.com/starkware-libs/stwo/issues/1399>
/// proposes renaming the default to `default_insecure` and adding a real
/// secure default.
///
/// 39 bits is well below the 96-bit cryptographic target an audit would
/// normally ask for. Pushing higher hits an upstream `unreachable!` panic
/// in the in-circuit `circuits-stark-verifier` verify path inside WASM
/// (reproducible by setting `n_queries = 20` here and running
/// `node scripts/e2e-zkp.mjs`; the host `tests/recursion.rs` run still
/// succeeds at any setting because the panic is WASM-specific). The
/// upstream tracking issue for unguarded panics on FRI inputs is
/// <https://github.com/starkware-libs/stwo/issues/1311>; the in-circuit
/// verifier inherits that class of panic. Native callers that don't go
/// through WASM can construct a stronger config inline; the recursion
/// code reads `prev_proof.pcs_config`, so a stronger base proof flows
/// through.
///
/// Changing `n_queries` here changes `prev_pp.params` and therefore the
/// in-circuit verifier shape; keep this in lockstep with
/// `verify::verify_record`.
pub fn tuned_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(
            /* log_last_layer_degree_bound */ 0, /* log_blowup_factor */ 1,
            /* n_queries */ 19, /* fold_step */ 1,
        ),
        lifting_log_size: None,
    }
}

/// All state we keep between steps. Owned values; consumed by `prove_step`.
pub struct ProofRecord {
    pub circuit_proof: CircuitProof<Blake2sM31MerkleHasher>,
    pub preprocessed: PreprocessedCircuit,
    pub counter: M31,
}

/// Builds + proves the base circuit. Public output is the counter `n`,
/// fixed to 0 by outputting `context.zero()`.
pub fn prove_base() -> Result<ProofRecord, ProverError> {
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
        tuned_pcs_config(),
    );
    if let Err(err) = &circuit_proof.stark_proof {
        return Err(ProverError::StarkProofFailed(*err));
    }

    Ok(ProofRecord {
        circuit_proof,
        preprocessed,
        counter: M31::from(0u32),
    })
}

/// Inductive step. Consumes `prev` and produces the next record:
///   - verifies `prev`'s `circuit_prover` proof in-circuit
///   - constrains `n_new == prev_n + 1`
///   - outputs `n_new` as the new public output
pub fn prove_step(prev: ProofRecord) -> Result<ProofRecord, ProverError> {
    let ProofRecord {
        circuit_proof: prev_proof,
        preprocessed: prev_pp,
        counter: prev_n,
    } = prev;

    // PROOF: M31 elements canonicalise into [0, P − 1]. The field add
    // `(P − 1) + 1 ≡ 0 (mod P)`, so `prev_n.0 == P − 1` is the only value
    // that silently wraps. Rejecting it here keeps the counter strictly
    // monotonic across the chain. (Also exercised by a unit test once a
    // boundary fixture exists; today the depth is browser-bounded long
    // before hitting it.)
    if prev_n.0 == P - 1 {
        return Err(ProverError::CounterOverflow);
    }

    // Extract metadata before consuming `prev_proof`.
    let pcs_config = prev_proof.pcs_config;
    let preprocessed_root_hash = prev_proof
        .stark_proof
        .as_ref()
        .map_err(|err| ProverError::StarkProofFailed(*err))?
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
        tuned_pcs_config(),
    );
    if let Err(err) = &circuit_proof.stark_proof {
        return Err(ProverError::StarkProofFailed(*err));
    }

    Ok(ProofRecord {
        circuit_proof,
        preprocessed,
        counter: new_counter,
    })
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
