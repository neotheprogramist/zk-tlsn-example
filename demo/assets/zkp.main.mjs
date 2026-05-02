import { event, eventErr } from "./log.mjs";
import { installPageErrorForwarders, startWorker } from "./flow.mjs";

const els = {
  state: document.querySelector('[data-role="state"]'),
  steps: document.querySelector('[data-role="steps"]'),
  lastProve: document.querySelector('[data-role="last-prove"]'),
  lastSize: document.querySelector('[data-role="last-size"]'),
  btnBase: document.querySelector('[data-role="base"]'),
  btnIncrement: document.querySelector('[data-role="increment"]'),
  btnProve: document.querySelector('[data-role="prove"]'),
  btnReset: document.querySelector('[data-role="reset"]'),
};

const state = { counter: null, pendingIncrement: false, busy: false, stepsProven: 0 };

installPageErrorForwarders();

function render() {
  if (state.counter === null) {
    els.state.textContent = "— (uninitialized)";
  } else if (state.pendingIncrement) {
    els.state.textContent = `${state.counter + 1} (pending — click Prove)`;
  } else {
    els.state.textContent = `${state.counter}  ✓ verified`;
  }

  if (state.stepsProven === 0) {
    els.steps.textContent = "—";
  } else if (state.stepsProven === 1) {
    els.steps.textContent = "1 (base)";
  } else {
    els.steps.textContent = `${state.stepsProven} (base + ${state.stepsProven - 1})`;
  }

  els.btnBase.disabled = state.busy || state.counter !== null;
  els.btnIncrement.disabled = state.busy || state.counter === null || state.pendingIncrement;
  els.btnProve.disabled = state.busy || !state.pendingIncrement;
  els.btnReset.disabled = state.busy;
}

function emitProofResult(isBase, msg) {
  const fields = {
    kind: isBase ? "base" : "step",
    counter: msg.counter,
    prove_ms: Math.round(msg.proveMs),
    proof_size_bytes: msg.sizeBytes,
    verified: msg.verified === true,
    verify_ms: Math.round(msg.verifyMs ?? 0),
    steps_proven: state.stepsProven,
  };
  if (!isBase) fields.prev_counter = msg.counter - 1;
  event("zkp.proof.done", fields);
}

const worker = startWorker("/assets/zkp.worker.mjs", (msg) => {
  switch (msg.kind) {
    case "ready":
      event("zkp.worker.ready", { init_ms: Math.round(msg.initMs) });
      state.busy = false;
      render();
      break;
    case "base_done":
    case "step_done": {
      const isBase = msg.kind === "base_done";
      state.counter = msg.counter;
      state.pendingIncrement = false;
      state.stepsProven = isBase ? 1 : state.stepsProven + 1;
      state.busy = false;
      els.lastProve.textContent = `${Math.round(msg.proveMs)} ms`;
      els.lastSize.textContent = `${(msg.sizeBytes / 1024).toFixed(1)} KB`;
      emitProofResult(isBase, msg);
      render();
      break;
    }
    case "error":
      state.busy = false;
      eventErr("zkp.proof.failed", { message: msg.message });
      render();
      break;
    case "reset_done":
      state.counter = null;
      state.pendingIncrement = false;
      state.stepsProven = 0;
      state.busy = false;
      els.lastProve.textContent = "—";
      els.lastSize.textContent = "—";
      event("zkp.action.reset");
      render();
      break;
    default:
      eventErr("zkp.worker.message.unknown", { kind: msg.kind });
  }
});

els.btnBase.addEventListener("click", () => {
  if (state.busy || state.counter !== null) return;
  state.busy = true;
  event("zkp.action.prove_base.click");
  render();
  worker.postMessage({ kind: "prove_base" });
});

els.btnIncrement.addEventListener("click", () => {
  if (state.busy || state.counter === null || state.pendingIncrement) return;
  state.pendingIncrement = true;
  event("zkp.action.increment.click", { pending: state.counter + 1 });
  render();
});

els.btnProve.addEventListener("click", () => {
  if (state.busy || !state.pendingIncrement) return;
  state.busy = true;
  event("zkp.action.prove_step.click", {
    prev_counter: state.counter,
    counter: state.counter + 1,
  });
  render();
  worker.postMessage({ kind: "prove_step" });
});

els.btnReset.addEventListener("click", () => {
  if (state.busy) return;
  state.busy = true;
  event("zkp.action.reset.click");
  render();
  worker.postMessage({ kind: "reset" });
});

event("zkp.page.loading");
worker.postMessage({ kind: "init" });
render();
