//! Binary streaming PCD over Stwo: leaf AIR (no in-circuit verify) and merge
//! AIR (verifies TWO children in-circuit and binds parent `(lo, hi, count)`).
//!
//! The merge AIR is the load-bearing piece — it embeds two
//! `circuits-stark-verifier::verify(...)` calls in the same context, then
//! constrains:
//!   - contiguity: `right.lo == left.hi + 1`
//!   - count consistency: `count == left.count + right.count`
//!   - range/count: `count + lo == hi + 1` (= `count == hi - lo + 1`)
//!
//! Leaf and merge proofs share the same `circuit_prover`-shape, so the merge
//! AIR's in-circuit verifier handles both child kinds uniformly. Recursion is
//! uniform from depth 1 upward.
//!
//! See `verify::verify_record` for the host-side STARK verifier that closes
//! the trust loop on every produced proof.

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

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("circuit prover failed: {0}")]
    StarkProofFailed(#[from] ProvingError),

    #[error("leaf index {index} ≥ M31::P; cannot fit in field")]
    LeafIndexOutOfRange { index: u32 },

    #[error(
        "contiguity violated: left.hi = {left_hi}, right.lo = {right_lo} (expected right.lo == left.hi + 1)"
    )]
    ContiguityViolated { left_hi: u32, right_lo: u32 },

    #[error("merge would overflow leaf-index space: left.hi = {left_hi} (== M31::P − 1)")]
    IndexOverflow { left_hi: u32 },

    #[error(
        "merge count would overflow M31: left.count = {left_count}, right.count = {right_count}"
    )]
    CountOverflow { left_count: u32, right_count: u32 },
}

/// PcsConfig tuned to the highest `n_queries` the merge AIR's TWO embedded
/// in-circuit verifiers tolerate inside browser WASM:
///   security_bits ≈ pow_bits + log_blowup_factor * n_queries = 20 + 1 * 3 = 23.
///
/// The previous chain-shape recursion (`prove_step`, single in-circuit
/// verifier) tolerated `n_queries = 19` (≈39-bit FRI soundness). The merge
/// AIR doubles trace rows but not PCS column log-sizes, so on paper the same
/// 19 should hold; in practice it trips an upstream `unreachable!` panic in
/// `circuits-stark-verifier`'s in-circuit verify path inside WASM (the
/// **native** `cargo test -p zkp` accepts any setting up to and beyond 19
/// — the panic is WASM-specific). Empirically `n_queries = 3` is the
/// highest value that survives both children's in-circuit verifier in the
/// browser at the time of writing.
///
/// 23 bits is well below the 96-bit cryptographic target an audit would
/// normally ask for, and lower than the 39 bits the chain version achieved.
/// The right fix is upstream — see
/// <https://github.com/starkware-libs/stwo/issues/1311> ("Uncaught panics on
/// invalid FRI inputs") and
/// <https://github.com/starkware-libs/stwo/issues/1399> ("`PcsConfig::default`
/// should be renamed `default_insecure`"). Until then, raise `n_queries`
/// here only when both `cargo test -p zkp` AND `node scripts/e2e-zkp.mjs`
/// pass cleanly with `tree_of_four_leaves` semantics.
pub fn tuned_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 20,
        fri_config: FriConfig::new(
            /* log_last_layer_degree_bound */ 0, /* log_blowup_factor */ 1,
            /* n_queries */ 3, /* fold_step */ 1,
        ),
        lifting_log_size: None,
    }
}

/// Per-proof state held by the worker's local store, indexed by node id
/// assigned by the JS scheduler. Owned values; consumed by `prove_merge`.
pub struct ProofRecord {
    pub circuit_proof: CircuitProof<Blake2sM31MerkleHasher>,
    pub preprocessed: PreprocessedCircuit,
    pub lo: M31,
    pub hi: M31,
    pub count: M31,
}

/// Builds + proves a leaf at the given index. Public output is the 3-tuple
/// `(lo, hi, count) = (index, index, 1)`.
///
/// Two separate witnesses for `lo` and `hi`, bound equal by an `eq`
/// constraint — sounder than aliasing a single Var into two output slots
/// (the Var-sharing variant would also work but couples leaf and merge AIR
/// shapes more tightly than necessary).
pub fn prove_leaf(index: u32) -> Result<ProofRecord, ProverError> {
    if index >= P {
        return Err(ProverError::LeafIndexOutOfRange { index });
    }
    let lo = M31::from(index);
    let hi = lo;
    let count = M31::from(1u32);

    let mut context = TraceContext::default();

    let lo_var = guess(&mut context, QM31::from(lo));
    let hi_var = guess(&mut context, QM31::from(hi));
    eq(&mut context, lo_var, hi_var);

    let one_var = context.one();

    output(&mut context, lo_var);
    output(&mut context, hi_var);
    output(&mut context, one_var);

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
        lo,
        hi,
        count,
    })
}

/// Inductive merge. Verifies BOTH children in-circuit and binds the parent
/// `(lo, hi, count)` per the contiguity + count constraints documented at
/// the module level. Consumes both children; on failure they're gone.
pub fn prove_merge(left: ProofRecord, right: ProofRecord) -> Result<ProofRecord, ProverError> {
    // ─── Host-side fail-fast bound checks ─────────────────────────────────
    // PROOF: M31 elements canonicalise into [0, P − 1]. The field add
    // `(P − 1) + 1 ≡ 0 (mod P)`, so `left.hi == P − 1` is the only value
    // that silently wraps. Rejecting it here keeps the leaf-index range
    // strictly monotonic across the chain.
    if left.hi.0 == P - 1 {
        return Err(ProverError::IndexOverflow { left_hi: left.hi.0 });
    }
    if left.hi.0 + 1 != right.lo.0 {
        return Err(ProverError::ContiguityViolated {
            left_hi: left.hi.0,
            right_lo: right.lo.0,
        });
    }
    let new_count_u64 = u64::from(left.count.0) + u64::from(right.count.0);
    if new_count_u64 >= u64::from(P) {
        return Err(ProverError::CountOverflow {
            left_count: left.count.0,
            right_count: right.count.0,
        });
    }
    let new_count = M31::from(new_count_u64 as u32);
    let new_lo = left.lo;
    let new_hi = right.hi;

    let ProofRecord {
        circuit_proof: left_proof,
        preprocessed: left_pp,
        ..
    } = left;
    let ProofRecord {
        circuit_proof: right_proof,
        preprocessed: right_pp,
        ..
    } = right;

    // ─── Per-child metadata ───────────────────────────────────────────────
    let left_pcs_config = left_proof.pcs_config;
    let left_root = left_proof
        .stark_proof
        .as_ref()
        .map_err(|err| ProverError::StarkProofFailed(*err))?
        .proof
        .commitments[0]
        .into();
    let left_output_addresses = left_pp.params.output_addresses.clone();
    let left_n_blake_gates = left_pp.params.n_blake_gates;
    let left_pp_ids = left_pp.preprocessed_trace.ids();
    let left_pp_log_sizes = left_pp.preprocessed_trace.log_sizes();
    let left_output_values = left_proof.claim.output_values.clone();

    let right_pcs_config = right_proof.pcs_config;
    let right_root = right_proof
        .stark_proof
        .as_ref()
        .map_err(|err| ProverError::StarkProofFailed(*err))?
        .proof
        .commitments[0]
        .into();
    let right_output_addresses = right_pp.params.output_addresses.clone();
    let right_n_blake_gates = right_pp.params.n_blake_gates;
    let right_pp_ids = right_pp.preprocessed_trace.ids();
    let right_pp_log_sizes = right_pp.preprocessed_trace.log_sizes();
    let right_output_values = right_proof.claim.output_values.clone();

    // ─── Reconstruct ProofConfig that each child was sealed with ──────────
    // Required to re-derive channel-mixing constants when lifting. Mirrors
    // the `proof_config_for_prev` block from the previous single-child step.
    let proof_config_for_left = {
        let mut shape_ctx = Context::<NoValue>::default();
        let stmt = CircuitStatement::<NoValue>::new(
            &mut shape_ctx,
            &left_output_addresses,
            &left_output_values,
            left_n_blake_gates,
            left_pp_ids.clone(),
            left_pp_log_sizes.clone(),
            left_root,
        );
        ProofConfig::from_statement(
            &stmt,
            vec![true; stmt.get_components().len()],
            &left_pcs_config,
            INTERACTION_POW_BITS,
        )
    };
    let proof_config_for_right = {
        let mut shape_ctx = Context::<NoValue>::default();
        let stmt = CircuitStatement::<NoValue>::new(
            &mut shape_ctx,
            &right_output_addresses,
            &right_output_values,
            right_n_blake_gates,
            right_pp_ids.clone(),
            right_pp_log_sizes.clone(),
            right_root,
        );
        ProofConfig::from_statement(
            &stmt,
            vec![true; stmt.get_components().len()],
            &right_pcs_config,
            INTERACTION_POW_BITS,
        )
    };

    // ─── Lift each child's proof into in-circuit form ─────────────────────
    let (left_proof_qm31, _left_public_data) =
        prepare_circuit_proof_for_circuit_verifier(left_proof, &proof_config_for_left);
    let (right_proof_qm31, _right_public_data) =
        prepare_circuit_proof_for_circuit_verifier(right_proof, &proof_config_for_right);

    // ─── Build the merge circuit context ──────────────────────────────────
    let mut context = TraceContext::default();

    // Left child statement + in-circuit verifier.
    let left_statement = CircuitStatement::new(
        &mut context,
        &left_output_addresses,
        &left_output_values,
        left_n_blake_gates,
        left_pp_ids,
        left_pp_log_sizes,
        left_root,
    );
    let left_lo_var: Var = left_statement.output_values[0];
    let left_hi_var: Var = left_statement.output_values[1];
    let left_count_var: Var = left_statement.output_values[2];
    let proof_config_for_verify_left = ProofConfig::from_statement(
        &left_statement,
        vec![true; left_statement.get_components().len()],
        &left_pcs_config,
        INTERACTION_POW_BITS,
    );
    let left_proof_vars = left_proof_qm31.guess(&mut context);
    verify(
        &mut context,
        &left_proof_vars,
        &proof_config_for_verify_left,
        &left_statement,
    );

    // Right child statement + in-circuit verifier.
    let right_statement = CircuitStatement::new(
        &mut context,
        &right_output_addresses,
        &right_output_values,
        right_n_blake_gates,
        right_pp_ids,
        right_pp_log_sizes,
        right_root,
    );
    let right_lo_var: Var = right_statement.output_values[0];
    let right_hi_var: Var = right_statement.output_values[1];
    let right_count_var: Var = right_statement.output_values[2];
    let proof_config_for_verify_right = ProofConfig::from_statement(
        &right_statement,
        vec![true; right_statement.get_components().len()],
        &right_pcs_config,
        INTERACTION_POW_BITS,
    );
    let right_proof_vars = right_proof_qm31.guess(&mut context);
    verify(
        &mut context,
        &right_proof_vars,
        &proof_config_for_verify_right,
        &right_statement,
    );

    // ─── PCD constraints binding the two children ─────────────────────────
    let one_var = context.one();

    // Contiguity: right.lo == left.hi + 1.
    let left_hi_plus_one = add(&mut context, left_hi_var, one_var);
    eq(&mut context, right_lo_var, left_hi_plus_one);

    // Count consistency: count == left.count + right.count.
    let computed_count = add(&mut context, left_count_var, right_count_var);
    let count_var = guess(&mut context, QM31::from(new_count));
    eq(&mut context, count_var, computed_count);

    // Range/count consistency: count + lo == hi + 1.
    // (Uses only `add` + `eq`; the circuits crate has no subtract op.)
    let count_plus_lo = add(&mut context, count_var, left_lo_var);
    let hi_plus_one = add(&mut context, right_hi_var, one_var);
    eq(&mut context, count_plus_lo, hi_plus_one);

    // ─── Public outputs: (lo, hi, count) ──────────────────────────────────
    output(&mut context, left_lo_var);
    output(&mut context, right_hi_var);
    output(&mut context, count_var);

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
        lo: new_lo,
        hi: new_hi,
        count: new_count,
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
