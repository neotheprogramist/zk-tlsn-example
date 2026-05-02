import init, { Prover } from "/assets/wasm/zkp.js";
import { eventErr } from "./log.mjs";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

const post = (msg) => self.postMessage(msg);

let prover = null;

async function ensureProver() {
  if (prover) return prover;
  const t0 = performance.now();
  await init();
  const initMs = performance.now() - t0;
  prover = new Prover();
  post({ kind: "ready", initMs });
  return prover;
}

self.addEventListener("message", async (ev) => {
  const msg = ev.data;
  try {
    switch (msg.kind) {
      case "init":
        await ensureProver();
        break;
      case "prove_base": {
        const p = await ensureProver();
        const summary = p.prove_base();
        const verifyT0 = performance.now();
        const verified = p.verify_current();
        const verifyMs = performance.now() - verifyT0;
        post({
          kind: "base_done",
          counter: summary.counter,
          proveMs: summary.prove_ms,
          sizeBytes: summary.proof_size_bytes,
          verified,
          verifyMs,
        });
        break;
      }
      case "prove_step": {
        const p = await ensureProver();
        const summary = p.prove_step();
        const verifyT0 = performance.now();
        const verified = p.verify_current();
        const verifyMs = performance.now() - verifyT0;
        post({
          kind: "step_done",
          counter: summary.counter,
          proveMs: summary.prove_ms,
          sizeBytes: summary.proof_size_bytes,
          verified,
          verifyMs,
        });
        break;
      }
      case "reset": {
        const p = await ensureProver();
        p.reset();
        post({ kind: "reset_done" });
        break;
      }
      default:
        eventErr("zkp.worker.message.unknown", { kind: msg.kind });
    }
  } catch (err) {
    post({ kind: "error", message: err && err.message ? err.message : String(err) });
  }
});
