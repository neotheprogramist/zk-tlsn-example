//! Browser bindings — exposes [`Prover`] and [`Verifier`] as
//! `#[wasm_bindgen]` classes that JavaScript instantiates per request.
//!
//! There is no module-level state: every operation runs against fresh
//! Prover/Verifier instances created by the JS caller (`new Prover()` /
//! `new Verifier()`). Workers stay long-lived for wasm-init reuse but
//! carry no per-job state — the JS scheduler owns the proof bytes and
//! ferries them to whichever worker is idle.
//!
//! Timings and event emission are the JS caller's responsibility; the
//! Rust side is pure.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name = ProofPayload)]
pub struct JsProofPayload {
    inner: crate::ProofPayload,
}

#[wasm_bindgen(js_class = ProofPayload)]
impl JsProofPayload {
    #[wasm_bindgen(getter)]
    pub fn lo(&self) -> u32 {
        self.inner.lo
    }
    #[wasm_bindgen(getter)]
    pub fn hi(&self) -> u32 {
        self.inner.hi
    }
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 {
        self.inner.count
    }
    #[wasm_bindgen(getter, js_name = proofSizeBytes)]
    pub fn proof_size_bytes(&self) -> usize {
        self.inner.bytes.len()
    }
    /// Returns a copy of the serialized proof as a `Uint8Array`. The handle
    /// stays usable; callers can release it by letting it go out of scope.
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.bytes.clone()
    }
}

#[wasm_bindgen(js_name = VerifyOutput)]
pub struct JsVerifyOutput {
    inner: crate::VerifyOutput,
}

#[wasm_bindgen(js_class = VerifyOutput)]
impl JsVerifyOutput {
    #[wasm_bindgen(getter)]
    pub fn lo(&self) -> u32 {
        self.inner.lo
    }
    #[wasm_bindgen(getter)]
    pub fn hi(&self) -> u32 {
        self.inner.hi
    }
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> u32 {
        self.inner.count
    }
    #[wasm_bindgen(getter)]
    pub fn verified(&self) -> bool {
        self.inner.verified
    }
}

#[wasm_bindgen(js_name = Prover)]
#[derive(Default)]
pub struct JsProver {
    inner: crate::Prover,
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    #[wasm_bindgen(js_name = proveLeaf)]
    pub fn prove_leaf(&self, index: u32) -> Result<JsProofPayload, JsValue> {
        let inner = self.inner.prove_leaf(index)?;
        Ok(JsProofPayload { inner })
    }

    #[wasm_bindgen(js_name = proveMerge)]
    pub fn prove_merge(&self, left: &[u8], right: &[u8]) -> Result<JsProofPayload, JsValue> {
        let inner = self.inner.prove_merge(left, right)?;
        Ok(JsProofPayload { inner })
    }
}

#[wasm_bindgen(js_name = Verifier)]
#[derive(Default)]
pub struct JsVerifier {
    inner: crate::Verifier,
}

#[wasm_bindgen(js_class = Verifier)]
impl JsVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<JsVerifyOutput, JsValue> {
        let inner = self.inner.verify(bytes)?;
        Ok(JsVerifyOutput { inner })
    }
}
