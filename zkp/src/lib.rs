pub mod recursion;
pub mod verify;

#[cfg(target_arch = "wasm32")]
mod wasm {
    use serde::Serialize;
    use stwo::core::fields::m31::M31;
    use wasm_bindgen::{JsCast, prelude::*};
    use web_sys::console;

    use crate::{
        recursion::{ProofRecord, proof_size, prove_base, prove_step},
        verify::verify_record,
    };

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

    #[derive(Serialize)]
    struct StepSummary {
        counter: u32,
        prove_ms: u64,
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
        ///
        /// This getter only reads the prover-tracked `M31` field. Until
        /// `verify_current()` returns `true` for the *same* held record, the
        /// value is an unauthenticated assertion by this WASM module. The
        /// demo Worker calls `verify_current()` after every `prove_*`, so
        /// the surfaced counter is bound to a real STARK check on that path.
        #[wasm_bindgen(getter)]
        pub fn counter(&self) -> Option<u32> {
            self.record.as_ref().map(|r| m31_to_u32(r.counter))
        }

        /// Generates the base proof (n = 0). Replaces any existing state.
        pub fn prove_base(&mut self) -> Result<JsValue, JsValue> {
            event_info("zkp.prove.base.start", &[]);
            let t0 = now();
            let record = prove_base().map_err(|e| JsValue::from_str(&e.to_string()))?;
            let elapsed = (now() - t0).round() as u64;
            let size = proof_size(&record);
            event_info(
                "zkp.prove.base.done",
                &[("prove_ms", &elapsed), ("size_bytes", &size)],
            );

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
            event_info("zkp.prove.step.start", &[("prev_counter", &prev_counter)]);
            let t0 = now();
            let record = prove_step(prev).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let elapsed = (now() - t0).round() as u64;
            let size = proof_size(&record);
            let counter = m31_to_u32(record.counter);
            event_info(
                "zkp.prove.step.done",
                &[
                    ("prev_counter", &prev_counter),
                    ("counter", &counter),
                    ("prove_ms", &elapsed),
                    ("size_bytes", &size),
                ],
            );

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

        /// Runs the host-side STARK verifier against the held record and
        /// asserts that `claim.output_values[0]` matches the prover-tracked
        /// counter. Returns `true` on success; throws on any verification
        /// failure (caller catches in JS).
        pub fn verify_current(&self) -> Result<bool, JsValue> {
            let record = self
                .record
                .as_ref()
                .ok_or_else(|| JsValue::from_str("no proof to verify; call prove_base first"))?;
            let t0 = now();
            verify_record(record).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let elapsed = (now() - t0).round() as u64;
            event_info("zkp.verify.done", &[("verify_ms", &elapsed)]);
            Ok(true)
        }
    }

    fn m31_to_u32(value: M31) -> u32 {
        let qm31: stwo::core::fields::qm31::QM31 = value.into();
        // M31 stored as the real coordinate (a) of the QM31; QM31::Display shows
        // "(a + bi) + (c + di)u" — for our base counter we always have b=c=d=0.
        let arr = qm31.to_m31_array();
        arr[0].0
    }
}
