//! Browser bindings — exposes [`crate::Prover`] and [`crate::Verifier`]
//! as `#[wasm_bindgen]` classes. Mirrors `zkp::wasm` in shape.

use stwo::core::fields::m31::M31;
use wasm_bindgen::prelude::*;

use crate::{
    air::AirKind,
    poseidon::{RATE, hash_host},
    types::{LeafWitness, PublicInputs},
};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Host-side Poseidon2-M31 hash exposed to JavaScript.
///
/// `inputs_json` is a JSON array of u32 M31-safe limbs (each `0 ≤ v < 2^31 − 1`).
/// Returns a JSON array of 8 u32 limbs representing the 256-bit hash output.
///
/// The output is bit-identical to the in-circuit Poseidon constraint used
/// by every vault leaf — i.e., what JS computes here is what the prover
/// must reproduce inside its circuit.
#[wasm_bindgen(js_name = poseidonHash)]
pub fn poseidon_hash(inputs_json: &str) -> Result<String, JsValue> {
    let limbs: Vec<u32> = serde_json::from_str(inputs_json)
        .map_err(|e| JsValue::from_str(&format!("invalid inputs_json: {e}")))?;
    let inputs_m31: Vec<M31> = limbs.into_iter().map(M31::from).collect();
    let out_m31 = hash_host(&inputs_m31);
    let out_u32: Vec<u32> = (0..RATE).map(|i| out_m31[i].0).collect();
    serde_json::to_string(&out_u32)
        .map_err(|e| JsValue::from_str(&format!("serialise output: {e}")))
}

#[wasm_bindgen(js_name = ProofPayload)]
pub struct JsProofPayload {
    inner: crate::ProofPayload,
}

#[wasm_bindgen(js_class = ProofPayload)]
impl JsProofPayload {
    #[wasm_bindgen(getter, js_name = airKindTag)]
    pub fn air_kind_tag(&self) -> u32 {
        self.inner.air_kind_tag
    }
    #[wasm_bindgen(getter, js_name = airKindName)]
    pub fn air_kind_name(&self) -> String {
        // PROOF: ProofPayload is constructed only by `Prover::prove_leaf`
        // (vault/src/prover.rs) which sources `air_kind_tag` from a valid
        // AirKind via `kind.tag()`. The tag is round-tripped through the
        // proof envelope; `from_tag` is provably `Some` here.
        AirKind::from_tag(self.inner.air_kind_tag)
            .expect("ProofPayload carries a valid AirKind tag")
            .name()
            .to_owned()
    }
    #[wasm_bindgen(getter, js_name = digestHi)]
    pub fn digest_hi(&self) -> u32 {
        self.inner.digest_hi
    }
    #[wasm_bindgen(getter, js_name = digestLo)]
    pub fn digest_lo(&self) -> u32 {
        self.inner.digest_lo
    }
    #[wasm_bindgen(getter, js_name = publicInputsJson)]
    pub fn public_inputs_json(&self) -> String {
        self.inner.public_inputs_json.clone()
    }
    #[wasm_bindgen(getter, js_name = proofSizeBytes)]
    pub fn proof_size_bytes(&self) -> usize {
        self.inner.bytes.len()
    }
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
    #[wasm_bindgen(getter, js_name = airKindTag)]
    pub fn air_kind_tag(&self) -> u32 {
        self.inner.air_kind_tag
    }
    #[wasm_bindgen(getter, js_name = airKindName)]
    pub fn air_kind_name(&self) -> String {
        self.inner.air_kind_name.clone()
    }
    #[wasm_bindgen(getter, js_name = digestHi)]
    pub fn digest_hi(&self) -> u32 {
        self.inner.digest_hi
    }
    #[wasm_bindgen(getter, js_name = digestLo)]
    pub fn digest_lo(&self) -> u32 {
        self.inner.digest_lo
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

    /// Prove a vault leaf at the given leaf_index in an action's fold
    /// tree, tagging it with `air_kind_tag` and binding the proof to the
    /// digest of the JSON-serialised public-input record. Leaf indices
    /// must be contiguous within an Action (see [`crate::Prover::prove_leaf`]).
    ///
    /// `witness_json` is a JSON-serialised [`LeafWitness`]; the prover
    /// dispatches on its variant to choose which kind's circuit body
    /// to instantiate. Pass `{"kind":"digest_bound"}` for the
    /// digest-bound kinds (Compliance, UserKey, OfferCreate, OfferCancel,
    /// ActionRoot).
    #[wasm_bindgen(js_name = proveLeaf)]
    pub fn prove_leaf(
        &self,
        leaf_index: u32,
        air_kind_tag: u32,
        public_inputs_json: &str,
        witness_json: &str,
    ) -> Result<JsProofPayload, JsValue> {
        let kind = AirKind::from_tag(air_kind_tag)
            .ok_or_else(|| JsValue::from_str(&format!("unknown air_kind_tag {air_kind_tag}")))?;
        let pi: PublicInputs = serde_json::from_str(public_inputs_json)
            .map_err(|e| JsValue::from_str(&format!("invalid public_inputs_json: {e}")))?;
        let witness: LeafWitness = serde_json::from_str(witness_json)
            .map_err(|e| JsValue::from_str(&format!("invalid witness_json: {e}")))?;
        let inner = self.inner.prove_leaf(leaf_index, kind, &pi, &witness)?;
        Ok(JsProofPayload { inner })
    }

    /// Fold two child proofs into one parent. The children must have
    /// adjacent AIR-kind tags (`right.air_kind_tag == left.air_kind_tag + 1`)
    /// because the zkp merge AIR enforces leaf-index contiguity. The
    /// vault scheduler orders leaves before merging.
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

    /// Verify a proof envelope. Pass the public-input JSON for a leaf
    /// proof (binding check); pass `null` for an action-root merge
    /// proof.
    pub fn verify(
        &self,
        bytes: &[u8],
        expected_public_inputs_json: Option<String>,
    ) -> Result<JsVerifyOutput, JsValue> {
        let inner = self
            .inner
            .verify(bytes, expected_public_inputs_json.as_deref())?;
        Ok(JsVerifyOutput { inner })
    }
}
