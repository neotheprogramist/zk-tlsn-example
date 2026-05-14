//! Public-input digest helper — hashes the JSON-serialised public-input
//! payload (one byte per M31 limb) via the same Poseidon2 the in-circuit
//! constraints use, then splits the first two limbs across output slots
//! 3..5 of every leaf proof.

use stwo::core::fields::m31::M31;

use crate::poseidon::hash_host;

/// Hash a JSON-serialised public-input payload and split the first 62
/// bits across two M31-safe halves (used as `(digest_hi, digest_lo)` on
/// the proof payload).
pub fn public_input_digest(payload: &serde_json::Value) -> (u32, u32) {
    let canonical = serde_json::to_vec(payload).expect("serde_json::to_vec on Value is infallible");
    let limbs: Vec<M31> = canonical.iter().map(|&b| M31::from(b as u32)).collect();
    let hash = hash_host(&limbs);
    // First two M31 limbs of the Poseidon output → high and low halves.
    (hash[0].0, hash[1].0)
}

/// Re-export of the split mask used at the host boundary so the JS-facing
/// API can document the truncation explicitly.
pub const M31_HALF_BITS: u32 = 31;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        let payload = serde_json::json!({"a": 1, "b": "x"});
        let d1 = public_input_digest(&payload);
        let d2 = public_input_digest(&payload);
        assert_eq!(d1, d2);
    }

    #[test]
    fn distinct_payloads_distinct_digests() {
        let p1 = serde_json::json!({"a": 1});
        let p2 = serde_json::json!({"a": 2});
        assert_ne!(public_input_digest(&p1), public_input_digest(&p2));
    }
}
