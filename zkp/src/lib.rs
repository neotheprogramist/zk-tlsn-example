pub mod recursion;
pub mod verify;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{cell::RefCell, collections::HashMap};

    use serde::Serialize;
    use stwo::core::fields::m31::M31;
    use wasm_bindgen::{JsCast, prelude::*};
    use web_sys::console;

    use crate::{
        recursion::{ProofRecord, proof_size, prove_leaf, prove_merge},
        verify::verify_record,
    };

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    // Worker-local proof store. Keyed by node ids assigned by the JS
    // scheduler. Single-worker design (v1): all proofs live in this HashMap;
    // cross-worker proof transfer would require serialising `CircuitProof`,
    // blocked by the upstream `Vec<Box<dyn Component>>` field.
    thread_local! {
        static STORE: RefCell<HashMap<u32, ProofRecord>> = RefCell::new(HashMap::new());
    }

    fn now() -> f64 {
        // In a Worker, `web_sys::window()` is None — performance lives on
        // `WorkerGlobalScope` instead. Try main-thread Window first, fall
        // back to the worker scope.
        if let Some(p) = web_sys::window().and_then(|w| w.performance()) {
            return p.now();
        }
        let global = js_sys::global();
        let scope: web_sys::WorkerGlobalScope = global.unchecked_into();
        scope.performance().map(|p| p.now()).unwrap_or(0.0)
    }

    fn emit_event(level: &str, name: &str, fields: &[(&str, &dyn core::fmt::Display)]) {
        use core::fmt::Write;
        let ts: String = js_sys::Date::new_0().to_iso_string().into();
        let mut line = format!("{ts}  {level} {name}");
        for (k, v) in fields {
            let _ = write!(line, " {k}={v}");
        }
        let value = JsValue::from_str(&line);
        if level == "ERROR" {
            console::error_1(&value);
        } else {
            console::log_1(&value);
        }
    }

    fn event_info(name: &str, fields: &[(&str, &dyn core::fmt::Display)]) {
        emit_event("INFO", name, fields);
    }

    /// Result returned to JS for any prove operation. Carries the public
    /// outputs (lifted to plain u32 for JS consumption) plus the prove time
    /// and the byte-size of the underlying StarkProof.
    #[derive(Serialize)]
    struct ProveResult {
        node_id: u32,
        lo: u32,
        hi: u32,
        count: u32,
        prove_ms: u64,
        proof_size_bytes: usize,
    }

    /// Result returned to JS for a verify operation.
    #[derive(Serialize)]
    struct VerifyResult {
        node_id: u32,
        verified: bool,
        verify_ms: u64,
    }

    fn store_record(node_id: u32, record: ProofRecord, prove_ms: u64) -> Result<JsValue, JsValue> {
        let result = ProveResult {
            node_id,
            lo: m31_to_u32(record.lo),
            hi: m31_to_u32(record.hi),
            count: m31_to_u32(record.count),
            prove_ms,
            proof_size_bytes: proof_size(&record),
        };
        STORE.with(|store| store.borrow_mut().insert(node_id, record));
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Proves a leaf at the given index and stores the resulting proof
    /// under `node_id` in the worker-local store. Returns the public
    /// outputs + timing/size to JS.
    #[wasm_bindgen]
    pub fn prove_leaf_op(node_id: u32, index: u32) -> Result<JsValue, JsValue> {
        event_info(
            "zkp.prove.leaf.start",
            &[("node_id", &node_id), ("index", &index)],
        );
        let t0 = now();
        let record = prove_leaf(index).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let elapsed = (now() - t0).round() as u64;
        let size = proof_size(&record);
        event_info(
            "zkp.prove.leaf.done",
            &[
                ("node_id", &node_id),
                ("index", &index),
                ("prove_ms", &elapsed),
                ("size_bytes", &size),
            ],
        );
        store_record(node_id, record, elapsed)
    }

    /// Merges the proofs at `left_id` and `right_id`, removing both from
    /// the store, and stores the new merge proof under `node_id`. Returns
    /// the parent's public outputs `(lo, hi, count) = (left.lo,
    /// right.hi, left.count + right.count)`.
    #[wasm_bindgen]
    pub fn prove_merge_op(node_id: u32, left_id: u32, right_id: u32) -> Result<JsValue, JsValue> {
        event_info(
            "zkp.prove.merge.start",
            &[
                ("node_id", &node_id),
                ("left_id", &left_id),
                ("right_id", &right_id),
            ],
        );
        let (left, right) = STORE.with(|store| -> Result<(ProofRecord, ProofRecord), JsValue> {
            let mut store = store.borrow_mut();
            let left = store.remove(&left_id).ok_or_else(|| {
                JsValue::from_str(&format!("missing proof for left_id={left_id}"))
            })?;
            let right = store.remove(&right_id).ok_or_else(|| {
                JsValue::from_str(&format!("missing proof for right_id={right_id}"))
            })?;
            Ok((left, right))
        })?;
        let t0 = now();
        let record = prove_merge(left, right).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let elapsed = (now() - t0).round() as u64;
        let size = proof_size(&record);
        let lo = m31_to_u32(record.lo);
        let hi = m31_to_u32(record.hi);
        let count = m31_to_u32(record.count);
        event_info(
            "zkp.prove.merge.done",
            &[
                ("node_id", &node_id),
                ("lo", &lo),
                ("hi", &hi),
                ("count", &count),
                ("prove_ms", &elapsed),
                ("size_bytes", &size),
            ],
        );
        store_record(node_id, record, elapsed)
    }

    /// Runs the host-side STARK verifier against the proof at `node_id`
    /// and asserts that `claim.output_values[0..3]` matches the
    /// prover-tracked `(lo, hi, count)`. Throws on any verification
    /// failure (caller catches in JS).
    #[wasm_bindgen]
    pub fn verify_op(node_id: u32) -> Result<JsValue, JsValue> {
        let t0 = now();
        STORE.with(|store| -> Result<(), JsValue> {
            let store = store.borrow();
            let record = store.get(&node_id).ok_or_else(|| {
                JsValue::from_str(&format!("missing proof for node_id={node_id}"))
            })?;
            verify_record(record).map_err(|e| JsValue::from_str(&e.to_string()))
        })?;
        let elapsed = (now() - t0).round() as u64;
        event_info(
            "zkp.verify.done",
            &[("node_id", &node_id), ("verify_ms", &elapsed)],
        );
        let result = VerifyResult {
            node_id,
            verified: true,
            verify_ms: elapsed,
        };
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Drops the proof at `node_id` from the store. No-op if absent.
    #[wasm_bindgen]
    pub fn forget_op(node_id: u32) {
        STORE.with(|store| store.borrow_mut().remove(&node_id));
    }

    /// Drops all proofs from the store. Used by the scheduler's Reset path.
    #[wasm_bindgen]
    pub fn reset_op() {
        STORE.with(|store| store.borrow_mut().clear());
    }

    fn m31_to_u32(value: M31) -> u32 {
        let qm31: stwo::core::fields::qm31::QM31 = value.into();
        // M31 stored as the real coordinate (a) of the QM31; QM31::Display
        // shows "(a + bi) + (c + di)u" — for our (lo, hi, count) outputs we
        // always have b=c=d=0.
        let arr = qm31.to_m31_array();
        arr[0].0
    }
}
