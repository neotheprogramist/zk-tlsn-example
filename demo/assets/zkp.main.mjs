import { appendLog, fmtKB, fmtMs, installPageErrorForwarders, startWorker } from "./flow.mjs";

const els = {
  state: document.querySelector('[data-role="state"]'),
  steps: document.querySelector('[data-role="steps"]'),
  lastProve: document.querySelector('[data-role="last-prove"]'),
  lastSize: document.querySelector('[data-role="last-size"]'),
  status: document.querySelector('[data-role="status"]'),
  log: document.querySelector('[data-role="log"]'),
  btnBase: document.querySelector('[data-role="base"]'),
  btnIncrement: document.querySelector('[data-role="increment"]'),
  btnProve: document.querySelector('[data-role="prove"]'),
  btnReset: document.querySelector('[data-role="reset"]'),
};

const state = { counter: null, pendingIncrement: false, busy: false, stepsProven: 0 };

installPageErrorForwarders("ZKP_ERROR");

function setStatus(kind, text) {
  els.status.className = `status-${kind}`;
  els.status.textContent = text;
}

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

function emitResult(isBase, msg) {
  const result = isBase
    ? {
        kind: "base",
        counter: msg.counter,
        prove_ms: Math.round(msg.proveMs),
        proof_size_bytes: msg.sizeBytes,
        steps_proven: state.stepsProven,
      }
    : {
        kind: "step",
        counter: msg.counter,
        prev_counter: msg.counter - 1,
        prove_ms: Math.round(msg.proveMs),
        proof_size_bytes: msg.sizeBytes,
        steps_proven: state.stepsProven,
      };
  console.log("ZKP_RESULT " + JSON.stringify(result));
}

const worker = startWorker("/assets/zkp.worker.mjs", (msg) => {
  switch (msg.kind) {
    case "ready":
      appendLog(els.log, `worker ready (wasm init ${fmtMs(msg.initMs)})`);
      setStatus("idle", "ready");
      state.busy = false;
      render();
      break;
    case "log":
      appendLog(els.log, msg.line);
      break;
    case "base_done":
    case "step_done": {
      const isBase = msg.kind === "base_done";
      state.counter = msg.counter;
      state.pendingIncrement = false;
      state.stepsProven = isBase ? 1 : state.stepsProven + 1;
      state.busy = false;
      els.lastProve.textContent = fmtMs(msg.proveMs);
      els.lastSize.textContent = fmtKB(msg.sizeBytes);
      setStatus("ok", `proven ✓ counter=${msg.counter}`);
      appendLog(
        els.log,
        isBase
          ? `base done: prove ${fmtMs(msg.proveMs)}, size ${msg.sizeBytes} B`
          : `step ${msg.counter - 1}→${msg.counter} (verifies step-shape): prove ${fmtMs(msg.proveMs)}, size ${msg.sizeBytes} B`,
      );
      emitResult(isBase, msg);
      render();
      break;
    }
    case "error":
      state.busy = false;
      setStatus("err", `error: ${msg.message}`);
      appendLog(els.log, "ERROR " + msg.message);
      console.error("ZKP_ERROR " + msg.message);
      render();
      break;
    case "reset_done":
      state.counter = null;
      state.pendingIncrement = false;
      state.stepsProven = 0;
      state.busy = false;
      els.lastProve.textContent = "—";
      els.lastSize.textContent = "—";
      setStatus("idle", "reset");
      appendLog(els.log, "reset");
      render();
      break;
    default:
      appendLog(els.log, "unknown worker message kind=" + msg.kind);
  }
});

els.btnBase.addEventListener("click", () => {
  if (state.busy || state.counter !== null) return;
  state.busy = true;
  setStatus("running", "generating base proof…");
  appendLog(els.log, "→ prove_base");
  render();
  worker.postMessage({ kind: "prove_base" });
});

els.btnIncrement.addEventListener("click", () => {
  if (state.busy || state.counter === null || state.pendingIncrement) return;
  state.pendingIncrement = true;
  setStatus("idle", `pending: ${state.counter + 1}`);
  appendLog(els.log, `+ increment (pending ${state.counter + 1})`);
  render();
});

els.btnProve.addEventListener("click", () => {
  if (state.busy || !state.pendingIncrement) return;
  state.busy = true;
  setStatus("running", `proving ${state.counter}→${state.counter + 1}…`);
  appendLog(els.log, `→ prove_step ${state.counter}→${state.counter + 1}`);
  render();
  worker.postMessage({ kind: "prove_step" });
});

els.btnReset.addEventListener("click", () => {
  if (state.busy) return;
  state.busy = true;
  setStatus("running", "resetting…");
  render();
  worker.postMessage({ kind: "reset" });
});

setStatus("running", "loading wasm…");
appendLog(els.log, "loading wasm…");
worker.postMessage({ kind: "init" });
render();
