#![cfg(target_arch = "wasm32")]

mod recursion;

use recursion::{ProofRecord, proof_size, prove_base, prove_step};
use serde::Serialize;
use stwo::core::fields::m31::M31;
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::console;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn now() -> f64 {
    // In a Worker, `web_sys::window()` is None — performance lives on
    // `WorkerGlobalScope` instead. Try main-thread Window first, fall back
    // to the worker scope.
    if let Some(p) = web_sys::window().and_then(|w| w.performance()) {
        return p.now();
    }
    let global = js_sys::global();
    let scope: web_sys::WorkerGlobalScope = global.unchecked_into();
    scope.performance().map(|p| p.now()).unwrap_or(0.0)
}

fn log(msg: &str) {
    console::log_1(&JsValue::from_str(msg));
}

#[derive(Serialize)]
struct StepSummary {
    counter: u32,
    prove_ms: f64,
    proof_size_bytes: usize,
    is_base: bool,
}

/// Holds the latest proof + its preprocessed circuit between calls.
#[wasm_bindgen]
#[derive(Default)]
pub struct Prover {
    record: Option<ProofRecord>,
}

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current proven counter, or null if no proof exists yet.
    #[wasm_bindgen(getter)]
    pub fn counter(&self) -> Option<u32> {
        self.record.as_ref().map(|r| m31_to_u32(r.counter))
    }

    /// Generates the base proof (n = 0). Replaces any existing state.
    pub fn prove_base(&mut self) -> Result<JsValue, JsValue> {
        log("zkp: prove_base start");
        let t0 = now();
        let record = prove_base();
        let elapsed = now() - t0;
        let size = proof_size(&record);
        log(&format!("zkp: prove_base done ms={elapsed:.0} size={size}"));

        let summary = StepSummary {
            counter: m31_to_u32(record.counter),
            prove_ms: elapsed,
            proof_size_bytes: size,
            is_base: true,
        };
        self.record = Some(record);
        serde_wasm_bindgen::to_value(&summary).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Generates the next inductive step. Requires `prove_base` to have been
    /// called first.
    pub fn prove_step(&mut self) -> Result<JsValue, JsValue> {
        let prev = self
            .record
            .take()
            .ok_or_else(|| JsValue::from_str("must call prove_base before prove_step"))?;
        let prev_counter = m31_to_u32(prev.counter);
        log(&format!("zkp: prove_step from n={prev_counter} start"));
        let t0 = now();
        let record = prove_step(prev);
        let elapsed = now() - t0;
        let size = proof_size(&record);
        let counter = m31_to_u32(record.counter);
        log(&format!(
            "zkp: prove_step n={prev_counter}->{counter} done ms={elapsed:.0} size={size}"
        ));

        let summary = StepSummary {
            counter,
            prove_ms: elapsed,
            proof_size_bytes: size,
            is_base: false,
        };
        self.record = Some(record);
        serde_wasm_bindgen::to_value(&summary).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Resets the prover (drops any held proof state).
    pub fn reset(&mut self) {
        self.record = None;
    }
}

fn m31_to_u32(value: M31) -> u32 {
    let qm31: stwo::core::fields::qm31::QM31 = value.into();
    // M31 stored as the real coordinate (a) of the QM31; QM31::Display shows
    // "(a + bi) + (c + di)u" — for our base counter we always have b=c=d=0.
    let arr = qm31.to_m31_array();
    arr[0].0
}
