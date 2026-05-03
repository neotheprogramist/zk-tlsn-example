//! Stateless prover. Mirrors `zktls::Prover` in shape: a single struct with
//! a `new` constructor and named operation methods that take and return
//! values (no internal store).
//!
//! The proof "store" lives outside this crate — the JS scheduler holds a
//! `Map<nodeId, Uint8Array>` and ferries bytes back and forth. Workers
//! instantiate a fresh `Prover` per job and discard it after; object
//! creation is free (zero-sized struct).
//!
//! Every operation produces a [`ProofPayload`]: the serialized bytes plus
//! the `(lo, hi, count)` triple the caller wants without re-deserializing.

use crate::{
    error::Result,
    recursion::{prove_leaf, prove_merge},
    serialize::{deserialize_record, serialize_record},
};

/// Self-describing serialized proof. The bytes are the canonical wire form;
/// `lo`/`hi`/`count` are derived public outputs surfaced for caller
/// convenience (they're also recoverable by deserializing the bytes).
#[derive(Clone, Debug)]
pub struct ProofPayload {
    pub bytes: Vec<u8>,
    pub lo: u32,
    pub hi: u32,
    pub count: u32,
}

impl ProofPayload {
    pub fn proof_size_bytes(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Default)]
pub struct Prover;

impl Prover {
    pub fn new() -> Self {
        Self
    }

    /// Produces a leaf proof at `index`. Returns the serialized bytes and
    /// the public outputs `(lo == hi == index, count == 1)`.
    pub fn prove_leaf(&self, index: u32) -> Result<ProofPayload> {
        let record = prove_leaf(index)?;
        let bytes = serialize_record(&record)?;
        Ok(ProofPayload {
            bytes,
            lo: record.lo.0,
            hi: record.hi.0,
            count: record.count.0,
        })
    }

    /// Merges two children given as serialized bytes. Returns the serialized
    /// merged proof and its public outputs.
    pub fn prove_merge(&self, left: &[u8], right: &[u8]) -> Result<ProofPayload> {
        let left_record = deserialize_record(left)?;
        let right_record = deserialize_record(right)?;
        let merged = prove_merge(left_record, right_record)?;
        let bytes = serialize_record(&merged)?;
        Ok(ProofPayload {
            bytes,
            lo: merged.lo.0,
            hi: merged.hi.0,
            count: merged.count.0,
        })
    }
}
