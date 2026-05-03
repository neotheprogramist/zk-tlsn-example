// Binary streaming PCD scheduler — bytes-based, stateless workers.
//
// The wasm module exposes Prover/Verifier classes. Workers instantiate
// them per request and discard them; ALL proof state lives on the main
// thread, in `proofBytes: Map<nodeId, Uint8Array>`. Merging a pair of
// peaks just sends both child bytes to whichever worker is idle — there
// is no notion of a proof being "owned" by a particular worker, and no
// cross-worker transfer step.
//
// Click Next ⇒ leaf job to thread pool ⇒ on prove, MMR promote() may
// enqueue a merge ⇒ on merge prove, promote() may enqueue more. The
// scheduler does no proving work itself; it only routes tasks.
//
// Tree-construction audit (invariants this scheduler preserves):
//   - Binarity: every internal node has exactly 2 children.
//   - Leaves enter `peaks` strictly in submission order (leaf indices
//     0,1,2,...). Without this, promote()'s "equal count" rule would fold
//     the wrong pair when leaves prove out of order across workers.
//   - MMR streaming rule: top two peaks fold iff equal `count`.
//   - Verify cascade: when the user clicks Verify, any remaining peaks fold
//     left-to-right (the merge AIR allows unequal counts as long as ranges
//     are contiguous, which holds by construction) until peaks.length === 1,
//     then host-verify the root.

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
  const pool = [];
  const queue = [];
  const nodes = new Map(); // nodeId -> node record
  const peaks = []; // nodeIds, sorted by lo ascending
  const inflight = new Map(); // jobId -> { workerSlot, nodeId, op, startedAt }
  const proofBytes = new Map(); // nodeId -> Uint8Array (the serialized proof)
  const leafNodeByIndex = new Map(); // leafIndex -> nodeId
  const provedLeaves = new Set(); // proved-but-not-yet-promoted (out-of-order)
  const listeners = new Set();
  let nextNodeId = 0;
  let nextLeafIndex = 0;
  let nextLeafToPromote = 0;
  let nextJobId = 0;
  let verifying = false;
  let verifyResolve = null;
  let verifyReject = null;
  let initPromise = null;

  function notify() {
    const snapshot = serializeState();
    for (const listener of listeners) listener(snapshot);
  }

  function requireNode(nodeId, where) {
    const node = nodes.get(nodeId);
    if (!node) throw new Error(`${where}: unknown node_id=${nodeId}`);
    return node;
  }

  function requireBytes(nodeId, where) {
    const bytes = proofBytes.get(nodeId);
    if (!bytes) throw new Error(`${where}: missing proof bytes for node_id=${nodeId}`);
    return bytes;
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
      verifying,
    };
  }

  function init() {
    if (initPromise) return initPromise;
    if (poolSize < 1) {
      throw new Error(`poolSize must be >= 1, got ${poolSize}`);
    }
    initPromise = (async () => {
      const ready = [];
      for (let slot = 0; slot < poolSize; slot++) {
        ready.push(spawnWorker(slot));
      }
      await Promise.all(ready);
      event("zkp.scheduler.ready", { pool_size: pool.length });
      notify();
    })();
    return initPromise;
  }

  function spawnWorker(slot) {
    const w = new Worker_(slot, workerScriptUrl);
    w.worker.addEventListener("message", (ev) => onWorkerMessage(slot, ev));
    w.worker.addEventListener("error", (ev) => onWorkerError(slot, ev));
    pool.push(w);
    return new Promise((resolve) => {
      const onMsg = (ev) => {
        if (ev.data?.kind === "ready") {
          w.worker.removeEventListener("message", onMsg);
          resolve();
        }
      };
      w.worker.addEventListener("message", onMsg);
      w.worker.postMessage({ kind: "init", jobId: -1 });
    });
  }

  // FIFO dispatch over the queue: each job picks any idle worker. There are
  // no per-job affinity constraints because every worker can run any op.
  function dispatch() {
    while (queue.length > 0) {
      const slot = pool.findIndex((w) => !w.busy);
      if (slot < 0) return;
      const job = queue.shift();
      assignJob(slot, job);
    }
  }

  function assignJob(slot, job) {
    const w = pool[slot];
    w.busy = true;
    w.currentJobId = job.jobId;
    w.currentNodeId = job.nodeId;
    w.currentOp = job.kind;
    w.startedAt = performance.now();
    if (job.kind === "leaf" || job.kind === "merge") {
      const node = requireNode(job.nodeId, "assignJob");
      node.state = NODE_STATE.PROVING;
      node.workerSlot = slot;
    }
    inflight.set(job.jobId, {
      workerSlot: slot,
      nodeId: job.nodeId,
      op: job.kind,
      startedAt: w.startedAt,
    });

    let message;
    let transfer = [];
    if (job.kind === "leaf") {
      message = { kind: "leaf", jobId: job.jobId, index: job.index };
    } else if (job.kind === "merge") {
      // Consume children's bytes: merge will produce a fresh proof for the
      // parent and the children are no longer reachable (they're not in
      // peaks anymore). Transfer is zero-copy; the main-thread reference
      // becomes neutered post-postMessage, which is exactly what we want.
      const left = requireBytes(job.leftId, "assignJob.merge.left");
      const right = requireBytes(job.rightId, "assignJob.merge.right");
      proofBytes.delete(job.leftId);
      proofBytes.delete(job.rightId);
      message = { kind: "merge", jobId: job.jobId, left, right };
      transfer = [left.buffer, right.buffer];
    } else if (job.kind === "verify") {
      // Verify is read-only: clone the bytes so a follow-up attempt (or a
      // viz redraw) can still inspect the root proof. The clone is only
      // ~50KB–1MB and runs once per session.
      const original = requireBytes(job.nodeId, "assignJob.verify");
      const bytes = new Uint8Array(original);
      message = { kind: "verify", jobId: job.jobId, bytes };
      transfer = [bytes.buffer];
    } else {
      throw new Error(`assignJob: unknown job kind=${job.kind}`);
    }

    w.worker.postMessage(message, transfer);
    event("zkp.scheduler.dispatched", {
      node_id: job.nodeId,
      job_id: job.jobId,
      op: job.kind,
      worker_slot: slot,
    });
  }

  function onWorkerMessage(slot, ev) {
    const data = ev.data;
    if (!data) return;
    if (data.kind === "ready") return;
    if (data.kind === "error") {
      inflight.delete(data.jobId);
      const nodeId = pool[slot].currentNodeId;
      releaseWorker(slot);
      const node = requireNode(nodeId, "onWorkerMessage.error");
      node.state = NODE_STATE.FAILED;
      node.errorMessage = data.message;
      eventErr("zkp.scheduler.job.failed", {
        worker_slot: slot,
        job_id: data.jobId,
        node_id: nodeId,
        op: data.op,
        message: data.message,
      });
      if (verifying && verifyReject) {
        const reject = verifyReject;
        verifyResolve = null;
        verifyReject = null;
        verifying = false;
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
    throw new Error(`onWorkerMessage: unknown message kind=${data.kind}`);
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

  function handleJobDone(slot, data) {
    const flight = inflight.get(data.jobId);
    inflight.delete(data.jobId);
    releaseWorker(slot);
    const elapsedMs = flight ? Math.round(performance.now() - flight.startedAt) : null;
    switch (data.op) {
      case "leaf":
        handleLeafDone(slot, flight, elapsedMs, data.result);
        break;
      case "merge":
        handleMergeDone(slot, flight, elapsedMs, data.result);
        break;
      case "verify":
        handleVerifyDone(flight, elapsedMs, data.result);
        break;
      default:
        throw new Error(`handleJobDone: unknown op=${data.op}`);
    }
    dispatch();
    maybeAdvanceVerify();
    if (queue.length === 0 && inflight.size === 0) {
      event("zkp.scheduler.idle", {});
    }
    notify();
  }

  function handleLeafDone(slot, flight, elapsedMs, result) {
    const nodeId = flight.nodeId;
    const node = requireNode(nodeId, "handleLeafDone");
    node.lo = result.lo;
    node.hi = result.hi;
    node.count = result.count;
    node.proveMs = elapsedMs;
    node.proofSizeBytes = result.proofSizeBytes;
    node.workerSlot = null;
    node.state = NODE_STATE.PROVED;
    proofBytes.set(nodeId, result.bytes);
    event("zkp.scheduler.leaf.proved", {
      node_id: nodeId,
      index: node.index,
      prove_ms: elapsedMs,
      size_bytes: node.proofSizeBytes,
      worker_slot: slot,
    });
    // Promote leaves to peaks STRICTLY in submission order. Without this,
    // out-of-order parallel leaf completion would corrupt the MMR shape
    // (promote() folds the two top peaks; if they're not contiguous-by-
    // construction, the merge AIR rejects via ContiguityViolated).
    provedLeaves.add(nodeId);
    promoteReadyLeaves();
  }

  function promoteReadyLeaves() {
    while (true) {
      const nodeId = leafNodeByIndex.get(nextLeafToPromote);
      if (nodeId == null) break;
      if (!provedLeaves.has(nodeId)) break;
      provedLeaves.delete(nodeId);
      nextLeafToPromote++;
      insertPeak(nodeId);
    }
    promote();
  }

  // Insert a finished node into `peaks` so that peaks remains strictly
  // sorted by `lo`. With parallel merges across workers, merges can finish
  // in any order — but `promote()`'s "top two adjacent peaks" rule and the
  // merge AIR's contiguity constraint both require peaks to be ordered.
  function insertPeak(nodeId) {
    const node = requireNode(nodeId, "insertPeak");
    let i = 0;
    while (i < peaks.length && requireNode(peaks[i], "insertPeak.peer").lo < node.lo) i++;
    peaks.splice(i, 0, nodeId);
  }

  function handleMergeDone(slot, flight, elapsedMs, result) {
    const nodeId = flight.nodeId;
    const node = requireNode(nodeId, "handleMergeDone");
    node.state = NODE_STATE.PROVED;
    node.lo = result.lo;
    node.hi = result.hi;
    node.count = result.count;
    node.proveMs = elapsedMs;
    node.proofSizeBytes = result.proofSizeBytes;
    node.workerSlot = null;
    proofBytes.set(nodeId, result.bytes);
    event("zkp.scheduler.merge.proved", {
      node_id: nodeId,
      left_id: node.leftId,
      right_id: node.rightId,
      lo: node.lo,
      hi: node.hi,
      count: node.count,
      prove_ms: elapsedMs,
      size_bytes: node.proofSizeBytes,
      worker_slot: slot,
    });
    insertPeak(nodeId);
    promote();
  }

  function handleVerifyDone(flight, elapsedMs, result) {
    const nodeId = flight.nodeId;
    const node = requireNode(nodeId, "handleVerifyDone");
    node.state = NODE_STATE.VERIFIED;
    node.verifyMs = elapsedMs;
    event("zkp.scheduler.verify.done", {
      node_id: nodeId,
      verify_ms: elapsedMs,
    });
    if (verifying && verifyResolve && peaks.length === 1 && peaks[0] === nodeId) {
      const resolve = verifyResolve;
      verifyResolve = null;
      verifyReject = null;
      verifying = false;
      event("zkp.scheduler.verified", {
        root_node_id: nodeId,
        verified: result.verified,
        lo: result.lo,
        hi: result.hi,
        count: result.count,
      });
      resolve({
        rootNodeId: nodeId,
        verified: result.verified,
        lo: result.lo,
        hi: result.hi,
        count: result.count,
      });
    }
  }

  // MMR promotion (streaming rule, parallel-safe).
  // Standard serial MMR streaming pops the top two peaks when their counts
  // match. With parallel completion, multiple leaves/merges may land in
  // `peaks` between two promote() calls — the foldable pair may not be the
  // top two, and there may be more than one foldable pair simultaneously.
  //
  // Scan all adjacent pairs LEFT-to-right; fold the first that is BOTH
  // equal-count AND range-contiguous (left.hi + 1 === right.lo). Restart
  // after each fold.
  //
  // Direction matters: left-to-right matches the canonical MMR shape that
  // serial insertion would produce. With three equal-count peaks [a, b, c]
  // in a row, serial MMR would have folded (a,b) first (leaving [a-b, c]),
  // because b entered peaks while c didn't yet exist. Right-to-left would
  // pick (b, c) and strand `a`, producing a non-canonical (deeper) tree.
  function promote() {
    let changed = true;
    while (changed) {
      changed = false;
      for (let i = 0; i < peaks.length - 1; i++) {
        const left = requireNode(peaks[i], "promote.left");
        const right = requireNode(peaks[i + 1], "promote.right");
        if (right.count !== left.count) continue;
        if (left.hi + 1 !== right.lo) continue;
        const [leftId, rightId] = peaks.splice(i, 2);
        enqueueMerge(leftId, rightId);
        changed = true;
        break;
      }
    }
  }

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
    leafNodeByIndex.set(index, nodeId);
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
    requireNode(leftId, "enqueueMerge.left").parentId = nodeId;
    requireNode(rightId, "enqueueMerge.right").parentId = nodeId;
    event("zkp.scheduler.merge.queued", {
      node_id: nodeId,
      left_id: leftId,
      right_id: rightId,
    });
    queue.push({ kind: "merge", jobId, nodeId, leftId, rightId });
    dispatch();
    // Notify so the viz can render the new merge node (and any
    // worker-state transition triggered by `dispatch`) immediately.
    // Without this, a merge enqueued from the verify-cascade path stays
    // invisible until the merge worker completes and `handleJobDone`
    // fires the next notify.
    notify();
    return nodeId;
  }

  function maybeAdvanceVerify() {
    if (!verifying) return;
    if (inflight.size > 0 || queue.length > 0) return;
    if (peaks.length > 1) {
      // Cascade: fold leftmost two peaks regardless of count match. The
      // merge AIR allows unequal counts as long as ranges are contiguous,
      // which is invariant by construction (peaks are ordered left-to-right
      // and contiguous because every leaf entered in submission order).
      const leftId = peaks.shift();
      const rightId = peaks.shift();
      enqueueMerge(leftId, rightId);
      return;
    }
    if (peaks.length === 1) {
      const rootId = peaks[0];
      const root = requireNode(rootId, "maybeAdvanceVerify");
      if (root.state !== NODE_STATE.PROVED) {
        throw new Error(
          `maybeAdvanceVerify: root node_id=${rootId} state=${root.state}, expected PROVED`,
        );
      }
      queue.push({ kind: "verify", jobId: nextJobId++, nodeId: rootId });
      dispatch();
    }
  }

  function verify() {
    if (verifying) {
      throw new Error("scheduler is already verifying");
    }
    if (peaks.length === 0 && queue.length === 0 && inflight.size === 0) {
      throw new Error("nothing to verify: no leaves submitted");
    }
    verifying = true;
    event("zkp.scheduler.verify.start", { peaks: peaks.length });
    const promise = new Promise((resolve, reject) => {
      verifyResolve = resolve;
      verifyReject = reject;
    });
    // Advance first (may enqueue a cascade merge or the verify job),
    // then notify — so the snapshot the viz sees already includes the
    // new node and worker-busy state.
    maybeAdvanceVerify();
    notify();
    return promise;
  }

  function reset() {
    queue.length = 0;
    nodes.clear();
    peaks.length = 0;
    inflight.clear();
    proofBytes.clear();
    leafNodeByIndex.clear();
    provedLeaves.clear();
    nextNodeId = 0;
    nextLeafIndex = 0;
    nextLeafToPromote = 0;
    nextJobId = 0;
    if (verifyReject) {
      const reject = verifyReject;
      verifyResolve = null;
      verifyReject = null;
      reject(new Error("scheduler reset before verify completed"));
    }
    verifying = false;
    for (const w of pool) {
      w.busy = false;
      w.currentJobId = null;
      w.currentNodeId = null;
      w.currentOp = null;
      w.startedAt = null;
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
    verify,
    reset,
    subscribe,
    snapshot,
  };
}
