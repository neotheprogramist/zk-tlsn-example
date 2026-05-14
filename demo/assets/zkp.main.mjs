// Page entry. Wires the scheduler + visualization to the Next/Verify/Reset
// buttons + readouts.
//
// Pool sizing: N equivalent workers, all of which can prove leaves OR
// merges. N = navigator.hardwareConcurrency by default (no cap), overridable
// via `?pool=N` URL param. Independent merges (e.g. on disjoint subtrees)
// run in parallel across workers — there is no central merger bottleneck.

import { event, eventErr } from "./log.mjs";
import { installPageErrorForwarders } from "./flow.mjs";
import { NODE_KIND, NODE_STATE, createScheduler } from "./zkp.scheduler.mjs";
import { attachVisualization } from "./zkp.viz.mjs";
import { createLog } from "./ui/ui.log.mjs";

function decidePoolSize() {
  const params = new URLSearchParams(window.location.search);
  const override = Number.parseInt(params.get("pool") ?? "", 10);
  if (Number.isInteger(override) && override >= 1) return override;
  const detected = navigator.hardwareConcurrency;
  if (!Number.isInteger(detected) || detected < 1) {
    throw new Error("navigator.hardwareConcurrency is unavailable; specify ?pool=N");
  }
  return detected;
}

const POOL_SIZE = decidePoolSize();

const els = {
  pool: document.querySelector('[data-role="pool"]'),
  leaves: document.querySelector('[data-role="leaves"]'),
  merges: document.querySelector('[data-role="merges"]'),
  peaks: document.querySelector('[data-role="peaks"]'),
  lastLeaf: document.querySelector('[data-role="last-leaf"]'),
  lastMerge: document.querySelector('[data-role="last-merge"]'),
  root: document.querySelector('[data-role="root"]'),
  verifyResult: document.querySelector('[data-role="verify-result"]'),
  btnNext: document.querySelector('[data-role="next"]'),
  btnVerify: document.querySelector('[data-role="verify"]'),
  btnReset: document.querySelector('[data-role="reset"]'),
  viz: document.querySelector('[data-role="viz"]'),
  log: document.querySelector('[data-role="log"]'),
};
for (const [name, el] of Object.entries(els)) {
  if (!el) throw new Error(`zkp page missing required element els.${name}`);
}

installPageErrorForwarders();

const scheduler = createScheduler({
  workerScriptUrl: "/assets/zkp.worker.mjs",
  poolSize: POOL_SIZE,
});

attachVisualization(els.viz, scheduler);
createLog(els.log);

let lastVerifyResult = null;
let lastVerifyError = null;
let booted = false;

function lastByKind(state, kind, key) {
  let last = null;
  for (const node of state.nodes) {
    if (node.kind !== kind) continue;
    if (node[key] == null) continue;
    if (!last || node.nodeId > last.nodeId) last = node;
  }
  return last;
}

function countByKind(state, kind, predicate) {
  let n = 0;
  for (const node of state.nodes) {
    if (node.kind === kind && predicate(node)) n++;
  }
  return n;
}

function isProvedOrVerified(n) {
  return n.state === NODE_STATE.PROVED || n.state === NODE_STATE.VERIFIED;
}

function renderReadouts(state) {
  els.pool.textContent = booted
    ? `${state.workersBusy} / ${state.poolSize} workers busy`
    : "— (booting)";
  els.leaves.textContent = `${state.nextLeafIndex} / ${countByKind(state, NODE_KIND.LEAF, isProvedOrVerified)}`;
  els.merges.textContent = String(countByKind(state, NODE_KIND.MERGE, isProvedOrVerified));
  els.peaks.textContent = String(state.peaks.length);

  const lastLeaf = lastByKind(state, NODE_KIND.LEAF, "proveMs");
  els.lastLeaf.textContent = lastLeaf ? `${lastLeaf.proveMs} ms` : "—";
  const lastMerge = lastByKind(state, NODE_KIND.MERGE, "proveMs");
  els.lastMerge.textContent = lastMerge ? `${lastMerge.proveMs} ms` : "—";

  if (lastVerifyResult) {
    const r = lastVerifyResult;
    els.root.textContent = `node=${r.rootNodeId}  lo=${r.lo}  hi=${r.hi}  count=${r.count}`;
  } else {
    els.root.textContent = "—";
  }
  if (lastVerifyError) {
    els.verifyResult.textContent = `FAILED ✗ ${lastVerifyError}`;
    els.verifyResult.className = "zkp-verify-result zkp-verify-failed";
  } else if (lastVerifyResult) {
    const r = lastVerifyResult;
    els.verifyResult.textContent = `VERIFIED ✓ [${r.lo}..${r.hi}] count=${r.count}`;
    els.verifyResult.className = "zkp-verify-result zkp-verify-ok";
  } else {
    els.verifyResult.textContent = "(not yet verified)";
    els.verifyResult.className = "zkp-verify-result";
  }

  els.btnNext.disabled = !booted || state.verifying;
  els.btnVerify.disabled =
    !booted || state.verifying || (state.nextLeafIndex === 0 && state.peaks.length === 0);
  els.btnReset.disabled = !booted;
}

scheduler.subscribe(renderReadouts);

els.btnNext.addEventListener("click", () => {
  if (els.btnNext.disabled) return;
  // Click event before scheduler.submitLeaf so the structured log reads
  // chronologically (click → queue → dispatch).
  event("zkp.action.next.click", {});
  scheduler.submitLeaf();
});

els.btnReset.addEventListener("click", () => {
  if (els.btnReset.disabled) return;
  event("zkp.action.reset.click");
  lastVerifyResult = null;
  lastVerifyError = null;
  scheduler.reset();
});

els.btnVerify.addEventListener("click", async () => {
  if (els.btnVerify.disabled) return;
  event("zkp.action.verify.click");
  lastVerifyError = null;
  try {
    const result = await scheduler.verify();
    lastVerifyResult = result;
    event("zkp.verify.done", {
      root_node_id: result.rootNodeId,
      verified: result.verified,
      lo: result.lo,
      hi: result.hi,
      count: result.count,
    });
  } catch (err) {
    lastVerifyError = err.message;
    eventErr("zkp.verify.failed", { message: lastVerifyError });
  }
  renderReadouts(scheduler.snapshot());
});

event("zkp.page.loading", { pool_size: POOL_SIZE });
scheduler
  .init()
  .then(() => {
    booted = true;
    event("zkp.scheduler.booted", { pool_size: POOL_SIZE });
    renderReadouts(scheduler.snapshot());
  })
  .catch((err) => {
    eventErr("zkp.scheduler.boot.failed", { message: err.message });
  });
