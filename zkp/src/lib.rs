//! Streaming PCD over Stwo. Public API mirrors `zktls`: zero-sized
//! [`Prover`] and [`Verifier`] structs with a single [`Error`] / [`Result`]
//! per crate.
//!
//! The crate is stateless at the boundary: every operation takes serialized
//! proof bytes and returns serialized proof bytes (or a verification
//! verdict). Proof storage lives outside this crate — typically in the JS
//! scheduler's `Map<nodeId, Uint8Array>` for the in-browser PCD demo.
//!
//! - [`Prover::prove_leaf`] / [`Prover::prove_merge`] return [`ProofPayload`]
//!   (bytes + `(lo, hi, count)`).
//! - [`Verifier::verify`] takes serialized bytes and returns
//!   [`VerifyOutput`].
//! - [`recursion`], [`serialize`], [`verifier`] expose the lower-level
//!   pieces (free functions on `ProofRecord`) for tests and downstream
//!   library users.
//! - [`wasm`] is the `wasm_bindgen` adapter layer used by the demo's Web
//!   Worker; it exposes [`Prover`], [`Verifier`], [`ProofPayload`],
//!   [`VerifyOutput`] as wasm-bindgen classes.

pub mod error;
pub mod prover;
pub mod recursion;
pub mod serialize;
pub mod verifier;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::{Error, Result};
pub use prover::{ProofPayload, Prover};
pub use verifier::{Verifier, VerifyOutput};
