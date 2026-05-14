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
//! `ProofRecord` carries `metadata: CircuitProofMetadata` rather than the
//! full `PreprocessedCircuit` because the heavy `Arc<PreProcessedTrace>` has
//! private fields that can't be reconstructed across a serialization boundary.
//! Metadata is the small, serialisable subset that `prove_merge` and
//! `verifier::verify_record` actually read.

use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    BaseColumnPool, CircuitProof, SimdBackend, prepare_circuit_proof_for_circuit_verifier,
    prove_circuit_assignment,
};
use circuit_verifier::statement::{CircuitStatement, INTERACTION_POW_BITS};
use circuits::{
    blake::HashValue,
    context::{Context, TraceContext, Var},
    ivalue::NoValue,
    ops::{Guess, add, eq, guess, output},
};
use circuits_stark_verifier::{
    proof::{Proof as CircuitVerifierProof, ProofConfig},
    statement::Statement,
    verify::verify,
};
use stwo::core::{
    fields::{
        m31::{M31, P},
        qm31::QM31,
    },
    fri::FriConfig,
    pcs::PcsConfig,
    proof::ExtendedStarkProof,
    vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher,
};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::{
    error::{Error, Result},
    verifier::verify_record,
};

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

/// The subset of `PreprocessedCircuit` that `prove_merge` and `verify_record`
/// actually read. Lives on every `ProofRecord`, including imported ones —
/// `PreprocessedCircuit` itself can't cross a serialisation boundary because
/// `Arc<PreProcessedTrace>` has private fields.
#[derive(Clone, Debug, PartialEq)]
pub struct CircuitProofMetadata {
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
    pub pp_trace_ids: Vec<PreProcessedColumnId>,
    pub pp_trace_log_sizes: Vec<u32>,
}

impl CircuitProofMetadata {
    pub fn from_preprocessed(pp: &PreprocessedCircuit) -> Self {
        Self {
            output_addresses: pp.params.output_addresses.clone(),
            n_blake_gates: pp.params.n_blake_gates,
            pp_trace_ids: pp.preprocessed_trace.ids(),
            pp_trace_log_sizes: pp.preprocessed_trace.log_sizes(),
        }
    }

    pub fn n_preprocessed_columns(&self) -> usize {
        self.pp_trace_ids.len()
    }
}

/// Per-proof state held by the worker's local store, indexed by node id
/// assigned by the JS scheduler. Owned values; consumed by `prove_merge`.
pub struct ProofRecord {
    pub circuit_proof: CircuitProof<Blake2sM31MerkleHasher>,
    pub metadata: CircuitProofMetadata,
    pub lo: M31,
    pub hi: M31,
    pub count: M31,
}

impl ProofRecord {
    /// PROOF: every `ProofRecord` is constructed via `prove_leaf`, `prove_merge`,
    /// or `serialize::deserialize_record` — all three produce or wrap an `Ok`
    /// `stark_proof`. The `Result` wrapper on `CircuitProof.stark_proof` is a
    /// relic of the upstream type; at this boundary it is never `Err`.
    pub fn extended_stark_proof(&self) -> &ExtendedStarkProof<Blake2sM31MerkleHasher> {
        self.circuit_proof
            .stark_proof
            .as_ref()
            .expect("ProofRecord stark_proof must be Ok by construction")
    }
}

pub fn prove_leaf(index: u32) -> Result<ProofRecord> {
    if index >= P {
        return Err(Error::LeafIndexOutOfRange { index });
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

    finalize_and_prove(&mut context, lo, hi, count)
}

pub fn prove_merge(left: ProofRecord, right: ProofRecord) -> Result<ProofRecord> {
    let canonical = tuned_pcs_config();
    check_canonical_pcs_config("left", &left.circuit_proof.pcs_config, &canonical)?;
    check_canonical_pcs_config("right", &right.circuit_proof.pcs_config, &canonical)?;

    // PROOF: M31 elements canonicalise into [0, P − 1]. The field add
    // `(P − 1) + 1 ≡ 0 (mod P)`, so `left.hi == P − 1` is the only value
    // that silently wraps. Rejecting it here keeps the leaf-index range
    // strictly monotonic across the chain.
    if left.hi.0 == P - 1 {
        return Err(Error::IndexOverflow { left_hi: left.hi.0 });
    }
    if left.hi.0 + 1 != right.lo.0 {
        return Err(Error::ContiguityViolated {
            left_hi: left.hi.0,
            right_lo: right.lo.0,
        });
    }
    let new_count_u64 = u64::from(left.count.0) + u64::from(right.count.0);
    if new_count_u64 >= u64::from(P) {
        return Err(Error::CountOverflow {
            left_count: left.count.0,
            right_count: right.count.0,
        });
    }
    let new_count = M31::from(new_count_u64 as u32);
    let new_lo = left.lo;
    let new_hi = right.hi;

    let left_lifted = lift_child(left);
    let right_lifted = lift_child(right);

    let mut context = TraceContext::default();
    let (left_lo_var, left_hi_var, left_count_var) =
        add_in_context_verifier(&mut context, left_lifted);
    let (right_lo_var, right_hi_var, right_count_var) =
        add_in_context_verifier(&mut context, right_lifted);

    let one_var = context.one();
    let left_hi_plus_one = add(&mut context, left_hi_var, one_var);
    eq(&mut context, right_lo_var, left_hi_plus_one);

    let computed_count = add(&mut context, left_count_var, right_count_var);
    let count_var = guess(&mut context, QM31::from(new_count));
    eq(&mut context, count_var, computed_count);

    // count + lo == hi + 1  (≡ count == hi - lo + 1; the circuits crate has no subtract op)
    let count_plus_lo = add(&mut context, count_var, left_lo_var);
    let hi_plus_one = add(&mut context, right_hi_var, one_var);
    eq(&mut context, count_plus_lo, hi_plus_one);

    output(&mut context, left_lo_var);
    output(&mut context, right_hi_var);
    output(&mut context, count_var);

    let record = finalize_and_prove(&mut context, new_lo, new_hi, new_count)?;
    verify_record(&record).map_err(|e| Error::VerifyAfterProveFailed(Box::new(e)))?;
    Ok(record)
}

/// Finalise the in-progress trace context and produce a proof record.
///
/// `pub` since vault reuses this exact path for its own per-kind leaf
/// circuits. The function is canonical for the zkp+vault stack: any
/// circuit whose context emits the `(lo, hi, count)` output triple in
/// slots 0..3 can be sealed through this entry point and the resulting
/// `ProofRecord` is byte-shape-identical to a zkp-native one.
pub fn finalize_and_prove(
    context: &mut TraceContext,
    lo: M31,
    hi: M31,
    count: M31,
) -> Result<ProofRecord> {
    context.finalize_guessed_vars();
    context.validate_circuit();
    let preprocessed = PreprocessedCircuit::preprocess_circuit(context);
    let circuit_proof = prove_circuit_assignment(
        context.values(),
        &preprocessed,
        &BaseColumnPool::<SimdBackend>::new(),
        tuned_pcs_config(),
    );
    if let Err(err) = &circuit_proof.stark_proof {
        return Err(Error::StarkProofFailed(*err));
    }
    Ok(ProofRecord {
        circuit_proof,
        metadata: CircuitProofMetadata::from_preprocessed(&preprocessed),
        lo,
        hi,
        count,
    })
}

/// Owns everything needed to re-verify one child inside the merge AIR's
/// trace context. Built outside the merge context so the proof's `Result`
/// can be unwrapped once and the metadata moved into the helper.
///
/// PROOF: `proof_config` is computed via `ProofConfig::from_statement` from
/// a `NoValue` statement, but `from_statement` reads only metadata-derived
/// shapes (component log sizes, preprocessed log sizes). It is invariant
/// under the `IValue` parameter, so the same config is reused when the
/// merge context calls `verify(...)` with a `Var`-valued statement.
struct LiftedChild {
    root: HashValue<QM31>,
    output_values: Vec<QM31>,
    output_addresses: Vec<usize>,
    n_blake_gates: usize,
    pp_trace_ids: Vec<PreProcessedColumnId>,
    pp_trace_log_sizes: Vec<u32>,
    proof_qm31: CircuitVerifierProof<QM31>,
    proof_config: ProofConfig,
}

fn lift_child(child: ProofRecord) -> LiftedChild {
    let ProofRecord {
        circuit_proof,
        metadata,
        ..
    } = child;
    let CircuitProofMetadata {
        output_addresses,
        n_blake_gates,
        pp_trace_ids,
        pp_trace_log_sizes,
    } = metadata;
    let pcs_config = circuit_proof.pcs_config;
    // PROOF: see ProofRecord::extended_stark_proof — every CircuitProof reaching
    // this path carries an `Ok` stark_proof by construction.
    let stark_proof = circuit_proof
        .stark_proof
        .as_ref()
        .expect("ProofRecord stark_proof must be Ok by construction");
    let root = stark_proof.proof.commitments[0].into();
    let output_values = circuit_proof.claim.output_values.clone();
    let proof_config = build_child_proof_config(
        &output_addresses,
        &output_values,
        n_blake_gates,
        pp_trace_ids.clone(),
        pp_trace_log_sizes.clone(),
        root,
        &pcs_config,
    );
    let (proof_qm31, _public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &proof_config);
    LiftedChild {
        root,
        output_values,
        output_addresses,
        n_blake_gates,
        pp_trace_ids,
        pp_trace_log_sizes,
        proof_qm31,
        proof_config,
    }
}

fn add_in_context_verifier(context: &mut TraceContext, child: LiftedChild) -> (Var, Var, Var) {
    let LiftedChild {
        root,
        output_values,
        output_addresses,
        n_blake_gates,
        pp_trace_ids,
        pp_trace_log_sizes,
        proof_qm31,
        proof_config,
    } = child;
    let statement = CircuitStatement::new(
        context,
        &output_addresses,
        &output_values,
        n_blake_gates,
        pp_trace_ids,
        pp_trace_log_sizes,
        root,
    );
    let lo = statement.output_values[0];
    let hi = statement.output_values[1];
    let count = statement.output_values[2];
    let proof_vars = proof_qm31.guess(context);
    verify(context, &proof_vars, &proof_config, &statement);
    (lo, hi, count)
}

fn build_child_proof_config(
    output_addresses: &[usize],
    output_values: &[QM31],
    n_blake_gates: usize,
    pp_trace_ids: Vec<PreProcessedColumnId>,
    pp_trace_log_sizes: Vec<u32>,
    root: HashValue<QM31>,
    pcs_config: &PcsConfig,
) -> ProofConfig {
    let mut shape_ctx = Context::<NoValue>::default();
    let stmt = CircuitStatement::<NoValue>::new(
        &mut shape_ctx,
        output_addresses,
        output_values,
        n_blake_gates,
        pp_trace_ids,
        pp_trace_log_sizes,
        root,
    );
    let n_components = stmt.get_components().len();
    ProofConfig::from_statement(
        &stmt,
        vec![true; n_components],
        pcs_config,
        INTERACTION_POW_BITS,
    )
}

/// Refuses a child whose `pcs_config` differs from canonical on any
/// security-relevant field. `lifting_log_size` is intentionally ignored —
/// the prover sets it from `trace_log_size + log_blowup_factor` at proof
/// time, so it always differs from the `tuned_pcs_config()` template even
/// on an honest child.
fn check_canonical_pcs_config(
    side: &'static str,
    child: &PcsConfig,
    canonical: &PcsConfig,
) -> Result<()> {
    let matches = child.pow_bits == canonical.pow_bits
        && child.fri_config.log_blowup_factor == canonical.fri_config.log_blowup_factor
        && child.fri_config.log_last_layer_degree_bound
            == canonical.fri_config.log_last_layer_degree_bound
        && child.fri_config.n_queries == canonical.fri_config.n_queries
        && child.fri_config.fold_step == canonical.fri_config.fold_step;
    if matches {
        Ok(())
    } else {
        Err(Error::ChildPcsConfigMismatch {
            side,
            canonical_n_queries: canonical.fri_config.n_queries,
            child_n_queries: child.fri_config.n_queries,
        })
    }
}

/// Public predicate so `serialize::into_record` can refuse a deserialized
/// record whose `pcs_config` doesn't match what this crate proves under.
pub(crate) fn assert_canonical_pcs_config(side: &'static str, child: &PcsConfig) -> Result<()> {
    check_canonical_pcs_config(side, child, &tuned_pcs_config())
}
