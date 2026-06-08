import { event, eventErr, onLog } from "./log.mjs";
import { installPageErrorForwarders, startWorker } from "./flow.mjs";
import { createSteps } from "./ui/ui.steps.mjs";
import { createLog } from "./ui/ui.log.mjs";

const root = document.querySelector('[data-role="prove-root"]');
const startBtn = document.querySelector('[data-role="start"]');
const resetBtn = document.querySelector('[data-role="reset"]');
const stepsHost = document.querySelector('[data-role="steps"]');
const logHost = document.querySelector('[data-role="log"]');
const overallStatus = document.querySelector('[data-role="overall-status"]');
const resultBox = document.querySelector('[data-role="result-summary"]');
const resultErr = document.querySelector('[data-role="result-error"]');
const certChip = document.querySelector('[data-role="cert-chip"]');

installPageErrorForwarders();

const STEPS = [
  { id: "init", label: "wasm init + worker pool" },
  { id: "connect", label: "open WebTransport session" },
  { id: "handshake", label: "create streams + preambles" },
  { id: "prove", label: "MPC-TLS prove_streams" },
  { id: "result", label: "close + result" },
];

// Maps log-event names to step transitions. Worker emits these via log.mjs,
// flow.mjs relays them to the main thread, ui.log.mjs renders them, and
// this handler advances the step list.
const STEP_EVENTS = {
  "zktls.worker.wasm.init.start": { id: "init", phase: "begin" },
  "zktls.worker.pool.ready": { id: "init", phase: "done" },
  "zktls.transport.session.opening": { id: "connect", phase: "begin" },
  "zktls.transport.session.ready": { id: "connect", phase: "done" },
  "zktls.transport.streams.creating": { id: "handshake", phase: "begin" },
  "zktls.transport.streams.preambles_written": { id: "handshake", phase: "done" },
  "zktls.prover.prove_streams.start": { id: "prove", phase: "begin" },
  "zktls.prover.prove_streams.done": { id: "prove", phase: "done" },
  "zktls.transport.session.closed": { id: "result", phase: "done" },
};

const steps = createSteps(stepsHost, STEPS);
const logView = createLog(logHost, { filterPrefix: "" });

// Truncate cert chip to first 10 chars + …; click reveals full hash.
function setupCertChip() {
  const full = certChip.textContent.trim();
  const short = full.length > 10 ? `${full.slice(0, 10)}…` : full;
  certChip.textContent = short;
  certChip.style.cursor = "pointer";
  certChip.title = "click to reveal full hash";
  let expanded = false;
  certChip.addEventListener("click", () => {
    expanded = !expanded;
    certChip.textContent = expanded ? full : short;
  });
}
setupCertChip();

function readConfig() {
  const d = root.dataset;
  return {
    connectUrl: new URL("/connect", location.origin).toString(),
    certHashHex: d.certHash,
    serverHost: d.serverHost,
    serverPort: Number(d.serverPort),
    serverName: d.serverName,
    serverCertDerHex: d.serverCertDerHex,
    fromUser: d.fromUser,
    toUser: d.toUser,
    transferAmount: Number(d.transferAmount),
    txId: Number(d.txId),
  };
}

let currentWorker = null;
let runStartedAt = null;

function setOverall(text) {
  overallStatus.textContent = text;
}

function lockUI(running) {
  startBtn.disabled = running;
  resetBtn.disabled = running;
}

function showResult(result) {
  const elapsedMs = runStartedAt != null ? Math.round(performance.now() - runStartedAt) : null;
  resultBox.hidden = false;
  resultBox.textContent = [
    `flow ${result.flow}`,
    `server ${result.serverName}`,
    `to ${result.toUsername}`,
    `amount ${result.amount}`,
    `eligibleForMint ${result.eligibleForMint}`,
    `commitments ${result.commitmentCount}`,
    elapsedMs != null ? `total ${elapsedMs}ms` : null,
  ]
    .filter(Boolean)
    .join("  ·  ");
}

function showError(message) {
  resultErr.textContent = message;
}

function clearResult() {
  resultBox.hidden = true;
  resultBox.textContent = "";
  resultErr.textContent = "";
}

function handleLogEvent(entry) {
  const m = STEP_EVENTS[entry.name];
  if (!m) return;
  if (m.phase === "begin") steps.begin(m.id);
  else if (m.phase === "done") steps.done(m.id);
}

// Drive the step list off the same event stream the log panel already renders.
onLog((entry) => handleLogEvent(entry));

function start() {
  clearResult();
  steps.reset();
  logView.clear();
  lockUI(true);
  setOverall("running");
  runStartedAt = performance.now();
  console.time("zktls: proving session");

  event("zktls.action.start.click");

  currentWorker = startWorker("/assets/zktls.worker.mjs", (msg) => {
    if (msg.kind === "result") {
      const elapsedMs = runStartedAt != null ? Math.round(performance.now() - runStartedAt) : null;
      console.timeEnd("zktls: proving session");
      event("zktls.notarize.done", {
        ...msg.result,
        ...(elapsedMs != null && { elapsed_ms: elapsedMs }),
      });
      steps.done("result");
      showResult(msg.result);
      setOverall("done");
      currentWorker.terminate();
      currentWorker = null;
      lockUI(false);
    } else if (msg.kind === "error") {
      const elapsedMs = runStartedAt != null ? Math.round(performance.now() - runStartedAt) : null;
      console.timeEnd("zktls: proving session");
      eventErr("zktls.notarize.failed", {
        message: msg.message,
        ...(elapsedMs != null && { elapsed_ms: elapsedMs }),
      });
      steps.failAllPending(msg.message);
      showError(msg.message);
      setOverall("failed");
      currentWorker.terminate();
      currentWorker = null;
      lockUI(false);
    }
  });
  currentWorker.postMessage({ kind: "start", config: readConfig() });
}

function reset() {
  if (currentWorker) {
    currentWorker.terminate();
    currentWorker = null;
  }
  clearResult();
  steps.reset();
  logView.clear();
  setOverall("idle");
  lockUI(false);
}

startBtn.addEventListener("click", start);
resetBtn.addEventListener("click", reset);
