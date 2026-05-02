// Binary streaming PCD scheduler. Maintains MMR peaks (right-spine), a
// worker pool (v1: K=1), a FIFO job queue, and a Finish cascade that
// merges remaining peaks into a single root and host-verifies it.
//
// Promotion rule (standard MMR streaming): after every node is proved,
// if the top two peaks have equal `count`, pop them and enqueue a merge.
// Repeats until the top two have unequal counts.
//
// Finish rule: after `finish()` is called, drain in-flight, then
// repeatedly merge peaks[0] and peaks[1] (left-to-right; the merge AIR
// permits unequal-count children as long as ranges are contiguous, which
// they always are by construction). When peaks.length === 1, host-verify
// and resolve the finish promise with the root's public outputs.

import { event, eventErr } from "./log.mjs";

export const NODE_KIND = Object.freeze({ LEAF: "leaf", MERGE: "merge" });
export const NODE_STATE = Object.freeze({
  QUEUED: "queued",
  PROVING: "proving",
  PROVED: "proved",
  VERIFIED: "verified",
  FAILED: "failed",
});

class Worker_ {
  constructor(slot, scriptUrl) {
    this.slot = slot;
    this.busy = false;
    this.currentJobId = null;
    this.currentNodeId = null;
    this.currentOp = null;
    this.startedAt = null;
    this.worker = new Worker(scriptUrl, { type: "module" });
  }
  terminate() {
    this.worker.terminate();
  }
}

export function createScheduler({ workerScriptUrl, poolSize = 1 } = {}) {
  // ─── state ──────────────────────────────────────────────────────────────
  const pool = [];
  const queue = [];
  const nodes = new Map(); // nodeId -> node record
  const peaks = []; // array of nodeIds, ordered left-to-right by lo
  const inflight = new Map(); // jobId -> { workerSlot, nodeId, op, startedAt }
  const listeners = new Set();
  let nextNodeId = 0;
  let nextLeafIndex = 0;
  let nextJobId = 0;
  let finishing = false;
  let finishResolve = null;
  let finishReject = null;
  let initPromise = null;

  // ─── pub/sub ────────────────────────────────────────────────────────────
  function notify() {
    const snapshot = serializeState();
    for (const listener of listeners) {
      try {
        listener(snapshot);
      } catch (err) {
        eventErr("zkp.scheduler.listener.failed", { message: err?.message ?? String(err) });
      }
    }
  }
  function subscribe(listener) {
    listeners.add(listener);
    listener(serializeState());
    return () => listeners.delete(listener);
  }
  function serializeState() {
    return {
      poolSize: pool.length,
      workersBusy: pool.filter((w) => w.busy).length,
      workers: pool.map((w) => ({
        slot: w.slot,
        busy: w.busy,
        op: w.currentOp,
        nodeId: w.currentNodeId,
        elapsedMs: w.startedAt == null ? null : performance.now() - w.startedAt,
      })),
      queueLength: queue.length,
      inflight: inflight.size,
      nodes: Array.from(nodes.values()).map((n) => ({ ...n })),
      peaks: peaks.slice(),
      nextLeafIndex,
      finishing,
    };
  }

  // ─── worker management ──────────────────────────────────────────────────
  function init() {
    if (initPromise) return initPromise;
    if (poolSize < 1) {
      throw new Error(`poolSize must be >= 1, got ${poolSize}`);
    }
    initPromise = (async () => {
      const ready = [];
      for (let slot = 0; slot < poolSize; slot++) {
        const w = new Worker_(slot, workerScriptUrl);
        w.worker.addEventListener("message", (ev) => onWorkerMessage(slot, ev));
        w.worker.addEventListener("error", (ev) => onWorkerError(slot, ev));
        pool.push(w);
        ready.push(
          new Promise((resolve) => {
            const onMsg = (ev) => {
              if (ev.data?.kind === "ready") {
                w.worker.removeEventListener("message", onMsg);
                resolve();
              }
            };
            w.worker.addEventListener("message", onMsg);
            // Boot: send any message; the worker calls ensureReady on first
            // event. We use a benign "init" so the worker can no-op after.
            w.worker.postMessage({ kind: "init", jobId: -1 });
            // No timeout — the harness's own page-load watchdog catches stalls.
          }),
        );
      }
      await Promise.all(ready);
      event("zkp.scheduler.ready", { pool_size: pool.length });
      notify();
    })();
    return initPromise;
  }

  // ─── core dispatch ──────────────────────────────────────────────────────
  function dispatch() {
    while (queue.length > 0) {
      const slot = pool.findIndex((w) => !w.busy);
      if (slot < 0) return;
      const job = queue.shift();
      const w = pool[slot];
      w.busy = true;
      w.currentJobId = job.jobId;
      w.currentNodeId = job.nodeId;
      w.currentOp = job.kind;
      w.startedAt = performance.now();
      const node = nodes.get(job.nodeId);
      if (node) {
        node.state = NODE_STATE.PROVING;
        node.workerSlot = slot;
      }
      inflight.set(job.jobId, {
        workerSlot: slot,
        nodeId: job.nodeId,
        op: job.kind,
        startedAt: w.startedAt,
      });
      const message = { ...job };
      w.worker.postMessage(message);
      event("zkp.scheduler.dispatched", {
        node_id: job.nodeId,
        job_id: job.jobId,
        op: job.kind,
        worker_slot: slot,
      });
    }
  }

  function onWorkerMessage(slot, ev) {
    const data = ev.data;
    if (!data) return;
    if (data.kind === "ready") {
      // Ready handshake handled inside init(); ignore here.
      return;
    }
    if (data.kind === "error") {
      const job = inflight.get(data.jobId);
      inflight.delete(data.jobId);
      const w = pool[slot];
      const nodeId = w.currentNodeId;
      releaseWorker(slot);
      const node = nodeId != null ? nodes.get(nodeId) : null;
      if (node) {
        node.state = NODE_STATE.FAILED;
        node.errorMessage = data.message;
      }
      eventErr("zkp.scheduler.job.failed", {
        worker_slot: slot,
        job_id: data.jobId,
        node_id: nodeId,
        op: job?.op,
        message: data.message,
      });
      // If we're finishing, propagate the failure.
      if (finishing && finishReject) {
        const reject = finishReject;
        finishResolve = null;
        finishReject = null;
        finishing = false;
        notify();
        reject(new Error(`worker job failed: ${data.message}`));
        return;
      }
      notify();
      return;
    }
    if (data.kind === "done") {
      handleJobDone(slot, data);
      return;
    }
    eventErr("zkp.scheduler.message.unknown", { kind: data.kind });
  }
  function onWorkerError(slot, ev) {
    eventErr("zkp.scheduler.worker.error", {
      worker_slot: slot,
      message: ev?.message ?? String(ev),
    });
  }

  function releaseWorker(slot) {
    const w = pool[slot];
    w.busy = false;
    w.currentJobId = null;
    w.currentNodeId = null;
    w.currentOp = null;
    w.startedAt = null;
  }

  // ─── job-completion handlers ────────────────────────────────────────────
  function handleJobDone(slot, data) {
    inflight.delete(data.jobId);
    releaseWorker(slot);
    if (data.op === "leaf" || data.op === "merge") {
      handleProveDone(data.op, data.result);
    } else if (data.op === "verify") {
      handleVerifyDone(data.result);
    } else if (data.op === "forget" || data.op === "reset") {
      // No state change beyond worker release.
    }
    dispatch();
    maybeAdvanceFinish();
    if (queue.length === 0 && inflight.size === 0) {
      event("zkp.scheduler.idle", {});
    }
    notify();
  }

  function handleProveDone(opKind, result) {
    const node = nodes.get(result.node_id);
    if (!node) {
      eventErr("zkp.scheduler.node.unknown", { node_id: result.node_id, op: opKind });
      return;
    }
    node.state = NODE_STATE.PROVED;
    node.lo = result.lo;
    node.hi = result.hi;
    node.count = result.count;
    node.proveMs = result.prove_ms;
    node.proofSizeBytes = result.proof_size_bytes;
    node.workerSlot = null;
    if (opKind === "leaf") {
      event("zkp.scheduler.leaf.proved", {
        node_id: node.nodeId,
        index: node.index,
        prove_ms: node.proveMs,
        size_bytes: node.proofSizeBytes,
      });
    } else {
      event("zkp.scheduler.merge.proved", {
        node_id: node.nodeId,
        left_id: node.leftId,
        right_id: node.rightId,
        lo: node.lo,
        hi: node.hi,
        count: node.count,
        prove_ms: node.proveMs,
        size_bytes: node.proofSizeBytes,
      });
    }
    // Push the new peak (replacing its children if any), then promote.
    peaks.push(node.nodeId);
    promote();
  }

  function handleVerifyDone(result) {
    const node = nodes.get(result.node_id);
    if (!node) return;
    node.state = NODE_STATE.VERIFIED;
    node.verifyMs = result.verify_ms;
    event("zkp.scheduler.verify.done", {
      node_id: node.nodeId,
      verify_ms: node.verifyMs,
    });
    if (finishing && finishResolve && peaks.length === 1 && peaks[0] === node.nodeId) {
      const resolve = finishResolve;
      finishResolve = null;
      finishReject = null;
      finishing = false;
      event("zkp.scheduler.finished", {
        root_node_id: node.nodeId,
        verified: true,
        lo: node.lo,
        hi: node.hi,
        count: node.count,
      });
      resolve({
        rootNodeId: node.nodeId,
        verified: true,
        lo: node.lo,
        hi: node.hi,
        count: node.count,
      });
    }
  }

  // ─── MMR promotion (streaming rule) ─────────────────────────────────────
  function promote() {
    while (peaks.length >= 2) {
      const rightId = peaks[peaks.length - 1];
      const leftId = peaks[peaks.length - 2];
      const right = nodes.get(rightId);
      const left = nodes.get(leftId);
      if (!right || !left) break;
      if (right.count !== left.count) break;
      // Pop both; create the merge node; queue the merge job.
      peaks.pop();
      peaks.pop();
      enqueueMerge(leftId, rightId);
    }
  }

  // ─── public API ─────────────────────────────────────────────────────────
  function submitLeaf() {
    const nodeId = nextNodeId++;
    const index = nextLeafIndex++;
    const jobId = nextJobId++;
    nodes.set(nodeId, {
      nodeId,
      kind: NODE_KIND.LEAF,
      state: NODE_STATE.QUEUED,
      index,
      lo: null,
      hi: null,
      count: null,
      leftId: null,
      rightId: null,
      parentId: null,
      proveMs: null,
      verifyMs: null,
      proofSizeBytes: null,
      workerSlot: null,
      errorMessage: null,
    });
    queue.push({ kind: "leaf", jobId, nodeId, index });
    event("zkp.scheduler.leaf.queued", { node_id: nodeId, index });
    dispatch();
    notify();
    return nodeId;
  }

  function enqueueMerge(leftId, rightId) {
    const nodeId = nextNodeId++;
    const jobId = nextJobId++;
    nodes.set(nodeId, {
      nodeId,
      kind: NODE_KIND.MERGE,
      state: NODE_STATE.QUEUED,
      index: null,
      lo: null,
      hi: null,
      count: null,
      leftId,
      rightId,
      parentId: null,
      proveMs: null,
      verifyMs: null,
      proofSizeBytes: null,
      workerSlot: null,
      errorMessage: null,
    });
    // Mark children as having a parent (for visualization).
    const left = nodes.get(leftId);
    const right = nodes.get(rightId);
    if (left) left.parentId = nodeId;
    if (right) right.parentId = nodeId;
    queue.push({ kind: "merge", jobId, nodeId, leftId, rightId });
    event("zkp.scheduler.merge.queued", {
      node_id: nodeId,
      left_id: leftId,
      right_id: rightId,
    });
    dispatch();
    return nodeId;
  }

  function maybeAdvanceFinish() {
    if (!finishing) return;
    if (inflight.size > 0 || queue.length > 0) return;
    if (peaks.length > 1) {
      const leftId = peaks.shift();
      const rightId = peaks.shift();
      enqueueMerge(leftId, rightId);
      return;
    }
    if (peaks.length === 1) {
      const rootId = peaks[0];
      const root = nodes.get(rootId);
      if (root && root.state === NODE_STATE.PROVED) {
        const jobId = nextJobId++;
        queue.push({ kind: "verify", jobId, nodeId: rootId });
        dispatch();
      }
    }
  }

  function finish() {
    if (finishing) {
      throw new Error("scheduler is already finishing");
    }
    if (peaks.length === 0 && queue.length === 0 && inflight.size === 0) {
      throw new Error("nothing to finish: no leaves submitted");
    }
    finishing = true;
    event("zkp.scheduler.finish.start", { peaks: peaks.length });
    const promise = new Promise((resolve, reject) => {
      finishResolve = resolve;
      finishReject = reject;
    });
    notify();
    maybeAdvanceFinish();
    return promise;
  }

  function reset() {
    queue.length = 0;
    nodes.clear();
    peaks.length = 0;
    inflight.clear();
    nextNodeId = 0;
    nextLeafIndex = 0;
    nextJobId = 0;
    if (finishReject) {
      const reject = finishReject;
      finishResolve = null;
      finishReject = null;
      reject(new Error("scheduler reset before finish completed"));
    }
    finishing = false;
    for (const w of pool) {
      w.busy = false;
      w.currentJobId = null;
      w.currentNodeId = null;
      w.currentOp = null;
      w.startedAt = null;
      w.worker.postMessage({ kind: "reset", jobId: nextJobId++ });
    }
    event("zkp.scheduler.reset", {});
    notify();
  }

  function snapshot() {
    return serializeState();
  }

  return {
    init,
    submitLeaf,
    finish,
    reset,
    subscribe,
    snapshot,
  };
}
