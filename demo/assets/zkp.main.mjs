// Page entry. Wires the scheduler + visualization to the Next/Reset/Finish
// buttons + readouts. Single-worker design (v1) — see
// /Users/neo/.claude/plans/deeply-analyze-zkp-crate-effervescent-rocket.md
// for why K=1 in this iteration.

import { event, eventErr } from "./log.mjs";
import { installPageErrorForwarders } from "./flow.mjs";
import { NODE_KIND, NODE_STATE, createScheduler } from "./zkp.scheduler.mjs";
import { attachVisualization } from "./zkp.viz.mjs";

const POOL_SIZE = 1; // v1: single worker (cross-worker proof transfer not yet wired)

const els = {
  pool: document.querySelector('[data-role="pool"]'),
  leaves: document.querySelector('[data-role="leaves"]'),
  merges: document.querySelector('[data-role="merges"]'),
  peaks: document.querySelector('[data-role="peaks"]'),
  lastLeaf: document.querySelector('[data-role="last-leaf"]'),
  lastMerge: document.querySelector('[data-role="last-merge"]'),
  root: document.querySelector('[data-role="root"]'),
  btnNext: document.querySelector('[data-role="next"]'),
  btnFinish: document.querySelector('[data-role="finish"]'),
  btnReset: document.querySelector('[data-role="reset"]'),
  viz: document.querySelector('[data-role="viz"]'),
};

installPageErrorForwarders();

const scheduler = createScheduler({
  workerScriptUrl: "/assets/zkp.worker.mjs",
  poolSize: POOL_SIZE,
});

const viz = attachVisualization(els.viz, scheduler);
void viz;

let lastFinishResult = null;
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

function countByKind(state, kind, predicate = () => true) {
  let n = 0;
  for (const node of state.nodes) {
    if (node.kind === kind && predicate(node)) n++;
  }
  return n;
}

function renderReadouts(state) {
  els.pool.textContent = booted ? `${state.workersBusy} / ${state.poolSize} busy` : "— (booting)";

  const leavesSubmitted = state.nextLeafIndex;
  const leavesProved = countByKind(
    state,
    NODE_KIND.LEAF,
    (n) => n.state === NODE_STATE.PROVED || n.state === NODE_STATE.VERIFIED,
  );
  els.leaves.textContent = `${leavesSubmitted} / ${leavesProved}`;

  const mergesProved = countByKind(
    state,
    NODE_KIND.MERGE,
    (n) => n.state === NODE_STATE.PROVED || n.state === NODE_STATE.VERIFIED,
  );
  els.merges.textContent = String(mergesProved);

  els.peaks.textContent = String(state.peaks.length);

  const lastLeaf = lastByKind(state, NODE_KIND.LEAF, "proveMs");
  els.lastLeaf.textContent = lastLeaf ? `${lastLeaf.proveMs} ms` : "—";

  const lastMerge = lastByKind(state, NODE_KIND.MERGE, "proveMs");
  els.lastMerge.textContent = lastMerge ? `${lastMerge.proveMs} ms` : "—";

  if (lastFinishResult) {
    const r = lastFinishResult;
    els.root.textContent = `node=${r.rootNodeId}  lo=${r.lo}  hi=${r.hi}  count=${r.count}  verified=${r.verified}`;
  } else {
    els.root.textContent = "—";
  }

  // Button states.
  els.btnNext.disabled = !booted || state.finishing;
  els.btnFinish.disabled =
    !booted || state.finishing || (state.nextLeafIndex === 0 && state.peaks.length === 0);
  els.btnReset.disabled = !booted;
}

scheduler.subscribe(renderReadouts);

els.btnNext.addEventListener("click", () => {
  if (els.btnNext.disabled) return;
  const nodeId = scheduler.submitLeaf();
  event("zkp.action.next.click", { node_id: nodeId });
});

els.btnReset.addEventListener("click", () => {
  if (els.btnReset.disabled) return;
  event("zkp.action.reset.click");
  lastFinishResult = null;
  scheduler.reset();
});

els.btnFinish.addEventListener("click", async () => {
  if (els.btnFinish.disabled) return;
  event("zkp.action.finish.click");
  try {
    const result = await scheduler.finish();
    lastFinishResult = result;
    event("zkp.finish.done", {
      root_node_id: result.rootNodeId,
      verified: result.verified,
      lo: result.lo,
      hi: result.hi,
      count: result.count,
    });
    renderReadouts(scheduler.snapshot());
  } catch (err) {
    eventErr("zkp.finish.failed", { message: err?.message ?? String(err) });
  }
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
    eventErr("zkp.scheduler.boot.failed", { message: err?.message ?? String(err) });
  });
