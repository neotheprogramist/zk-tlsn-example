//! Vault — per-kind Logic-AIRs (Compliance, Conservation, OfferSolve,
//! UserKey, OfferCancel) over the unified Poseidon2-M31 hash, folded
//! into a single Action-AIR root via the sibling `zkp` crate's binary
//! merge. Public surface mirrors `zkp` (zero-sized Prover/Verifier,
//! one closed Error enum) so the JS worker import boundary is identical.

pub mod air;
pub mod error;
pub mod hash;
pub mod leaf_circuits;
pub mod poseidon;
pub mod preimage;
pub mod prover;
pub mod types;
pub mod verifier;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use air::AirKind;
pub use error::{Error, Result};
pub use prover::{ProofPayload, Prover};
pub use types::{LeafWitness, PublicInputs, ResourcePreimage};
pub use verifier::{Verifier, VerifyOutput};
