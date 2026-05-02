// Single-threaded prover instance. The wasm module owns a thread-local
// proof store keyed by node id; the scheduler (main thread) dispatches
// jobs by sending {kind, jobId, ...} messages and gets {kind: "done" |
// "error", jobId, result?, message?} back.
//
// v1 design uses ONE worker. The architecture is K-worker-ready, but
// cross-worker proof transfer is blocked by the upstream
// `Vec<Box<dyn Component>>` field on CircuitProof — see
// /Users/neo/.claude/plans/deeply-analyze-zkp-crate-effervescent-rocket.md
// for the full reasoning.

import init, {
  forget_op,
  prove_leaf_op,
  prove_merge_op,
  reset_op,
  verify_op,
} from "/assets/wasm/zkp.js";
import { eventErr } from "./log.mjs";
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

self.addEventListener("message", async ({ data }) => {
  await ensureReady();
  const jobId = data.jobId;
  try {
    let result;
    switch (data.kind) {
      case "init":
        // ensureReady already posted "ready"; nothing more to do.
        return;
      case "leaf":
        result = prove_leaf_op(data.nodeId, data.index);
        break;
      case "merge":
        result = prove_merge_op(data.nodeId, data.leftId, data.rightId);
        break;
      case "verify":
        result = verify_op(data.nodeId);
        break;
      case "forget":
        forget_op(data.nodeId);
        result = { nodeId: data.nodeId };
        break;
      case "reset":
        reset_op();
        result = {};
        break;
      default:
        eventErr("zkp.worker.message.unknown", { kind: data.kind });
        self.postMessage({
          kind: "error",
          jobId,
          message: `unknown message kind=${data.kind}`,
        });
        return;
    }
    self.postMessage({ kind: "done", jobId, op: data.kind, result });
  } catch (err) {
    self.postMessage({
      kind: "error",
      jobId,
      message: err && err.message ? err.message : String(err),
    });
  }
});
