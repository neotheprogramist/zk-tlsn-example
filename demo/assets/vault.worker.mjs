// Stateless vault wasm worker. Mirrors `zkp.worker.mjs` in shape, but
// imports from the vault wasm module so leaf proofs carry the
// `air_kind_tag` + `digestHi/digestLo` metadata.
//
// Job protocol:
//   { kind: "leaf",   jobId, leafIndex, airKindTag, publicInputsJson, witnessJson }
//     → { kind: "done", op: "leaf",   jobId, result: { bytes, airKindTag,
//          airKindName, digestHi, digestLo, publicInputsJson, proofSizeBytes } }
//   { kind: "merge",  jobId, left, right }
//     → { kind: "done", op: "merge",  jobId, result: <same shape as leaf
//          but airKindTag = action_root> }
//   { kind: "verify", jobId, bytes, publicInputsJson|null }
//     → { kind: "done", op: "verify", jobId, result: { airKindTag, airKindName,
//          digestHi, digestLo, verified } }
//   any failure → { kind: "error", op, jobId, message }

import init, { Prover, Verifier } from "/assets/wasm/vault.js";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

let ready = false;

async function ensureReady() {
  if (ready) return;
  const t0 = performance.now();
  await init();
  ready = true;
  self.postMessage({ kind: "ready", initMs: performance.now() - t0 });
}

function leafResponse(payload) {
  const airKindTag = payload.airKindTag;
  const airKindName = payload.airKindName;
  const digestHi = payload.digestHi;
  const digestLo = payload.digestLo;
  const publicInputsJson = payload.publicInputsJson;
  const proofSizeBytes = payload.proofSizeBytes;
  const bytes = payload.bytes();
  return {
    result: {
      bytes,
      airKindTag,
      airKindName,
      digestHi,
      digestLo,
      publicInputsJson,
      proofSizeBytes,
    },
    transfer: [bytes.buffer],
  };
}

const HANDLERS = {
  leaf: (data) => {
    const prover = new Prover();
    const payload = prover.proveLeaf(
      data.leafIndex,
      data.airKindTag,
      data.publicInputsJson,
      data.witnessJson,
    );
    return leafResponse(payload);
  },
  merge: (data) => {
    const prover = new Prover();
    const payload = prover.proveMerge(data.left, data.right);
    return leafResponse(payload);
  },
  verify: (data) => {
    const verifier = new Verifier();
    const out = verifier.verify(data.bytes, data.publicInputsJson ?? null);
    return {
      result: {
        airKindTag: out.airKindTag,
        airKindName: out.airKindName,
        digestHi: out.digestHi,
        digestLo: out.digestLo,
        verified: out.verified,
      },
    };
  },
};

self.addEventListener("message", async ({ data }) => {
  await ensureReady();
  if (data.kind === "init") return;
  const handler = HANDLERS[data.kind];
  if (!handler) {
    self.postMessage({
      kind: "error",
      jobId: data.jobId,
      op: data.kind,
      message: `worker: unknown message kind=${data.kind}`,
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
      message: err.message,
    });
  }
});
