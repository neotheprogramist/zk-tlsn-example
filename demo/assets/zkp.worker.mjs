// Stateless wasm worker. The wasm module exposes Prover/Verifier classes;
// each job instantiates a fresh class instance, runs the operation, returns
// the result, and discards the instance. Workers stay alive across jobs
// only to avoid re-initialising the wasm module — they hold no proof state.
//
// Job protocol (request → response):
//   { kind: "leaf",   jobId, index }
//     → { kind: "done", op: "leaf",   jobId, result: { bytes, lo, hi, count, proofSizeBytes } }
//   { kind: "merge",  jobId, left, right }
//     → { kind: "done", op: "merge",  jobId, result: { bytes, lo, hi, count, proofSizeBytes } }
//   { kind: "verify", jobId, bytes }
//     → { kind: "done", op: "verify", jobId, result: { lo, hi, count, verified } }
//   { kind: "init",   jobId }
//     → { kind: "ready", initMs }   (one-time on the first message)
//   any failure → { kind: "error", op, jobId, message }
//
// All Uint8Array buffers are sent with `transfer` for zero-copy when possible.
//
// The proof bytes are owned by the main thread; this worker never holds
// proof state across jobs.

import init, { Prover, Verifier } from "/assets/wasm/zkp.js";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

let ready = false;

async function ensureReady() {
  if (ready) return;
  const t0 = performance.now();
  await init();
  const initMs = performance.now() - t0;
  ready = true;
  self.postMessage({ kind: "ready", initMs });
}

const HANDLERS = {
  leaf: (data) => {
    const prover = new Prover();
    const payload = prover.proveLeaf(data.index);
    return payloadResponse(payload);
  },
  merge: (data) => {
    const prover = new Prover();
    const payload = prover.proveMerge(data.left, data.right);
    return payloadResponse(payload);
  },
  verify: (data) => {
    const verifier = new Verifier();
    const out = verifier.verify(data.bytes);
    return {
      result: {
        lo: out.lo,
        hi: out.hi,
        count: out.count,
        verified: out.verified,
      },
    };
  },
};

function payloadResponse(payload) {
  // Snapshot scalar getters before calling .bytes() so we never read from a
  // freed wasm handle. The Uint8Array returned by .bytes() is owned by the
  // worker and is shipped to the main thread via a transferable buffer.
  const lo = payload.lo;
  const hi = payload.hi;
  const count = payload.count;
  const proofSizeBytes = payload.proofSizeBytes;
  const bytes = payload.bytes();
  return {
    result: { bytes, lo, hi, count, proofSizeBytes },
    transfer: [bytes.buffer],
  };
}

self.addEventListener("message", async ({ data }) => {
  await ensureReady();
  if (data.kind === "init") return;
  const handler = HANDLERS[data.kind];
  if (!handler) {
    self.postMessage({
      kind: "error",
      jobId: data.jobId,
      op: data.kind,
      message: `worker received unknown message kind=${data.kind}`,
    });
    return;
  }
  try {
    const { result, transfer } = handler(data);
    self.postMessage({ kind: "done", jobId: data.jobId, op: data.kind, result }, transfer ?? []);
  } catch (err) {
    self.postMessage({
      kind: "error",
      jobId: data.jobId,
      op: data.kind,
      message: err?.message ?? String(err),
    });
  }
});
