// Per-Action proving scheduler. Forks the same idea as zkp.scheduler.mjs
// (worker pool + binary merge fold) but works per-Action instead of one
// global MMR:
//
//   for each submitted Action:
//     - leafSpecs is an ordered list; allocate worker jobs to prove each
//       leaf concurrently across the pool.
//     - when all leaves are proved, fold pairwise left-to-right (binary
//       reduction) until one root proof remains.
//     - emit `vault.action.proved` and run a final verify on the root.
//
// Multiple Actions can be in-flight simultaneously; they share the pool.

import { event, eventErr } from "./log.mjs";
import { startWorker } from "./flow.mjs";

export const NODE_STATE = Object.freeze({
  QUEUED: "queued",
  PROVING: "proving",
  PROVED: "proved",
  VERIFIED: "verified",
  FAILED: "failed",
});

export const NODE_KIND = Object.freeze({
  LEAF: "leaf",
  MERGE: "merge",
});

export function createScheduler({ workerScriptUrl, poolSize }) {
  if (!Number.isInteger(poolSize) || poolSize < 1) {
    throw new Error(`poolSize must be a positive integer (got ${poolSize})`);
  }

  const workers = [];
  const idleWorkers = [];
  const jobQueue = [];
  let nextJobId = 1;
  const inflight = new Map();

  const actions = new Map(); // actionId -> ActionState
  const listeners = new Set();

  function snapshot() {
    return {
      poolSize,
      workersBusy: workers.length - idleWorkers.length,
      actions: Array.from(actions.values()).map((a) => ({
        actionId: a.actionId,
        flow: a.flow,
        state: a.state,
        nodes: a.nodes.map((n) => ({ ...n, proofBytes: undefined })), // strip bytes from snapshot
        startedAt: a.startedAt,
        finishedAt: a.finishedAt,
        error: a.error,
      })),
    };
  }

  function notify() {
    const snap = snapshot();
    for (const l of listeners) {
      try {
        l(snap);
      } catch (err) {
        console.error("vault.scheduler listener threw:", err);
      }
    }
  }

  function subscribe(fn) {
    listeners.add(fn);
    fn(snapshot());
    return () => listeners.delete(fn);
  }

  async function init() {
    const readinessPromises = [];
    for (let slot = 0; slot < poolSize; slot++) {
      const w = startWorker(workerScriptUrl, (msg) => handleMessage(slot, msg));
      w.__slot = slot;
      workers.push(w);
      readinessPromises.push(
        new Promise((resolve, reject) => {
          w.__resolveReady = resolve;
          w.__rejectReady = reject;
        }),
      );
      w.postMessage({ kind: "init", jobId: nextJobId++ });
    }
    await Promise.all(readinessPromises);
    for (const w of workers) idleWorkers.push(w);
    notify();
  }

  function handleMessage(slot, msg) {
    const w = workers[slot];
    if (msg.kind === "ready") {
      w.__resolveReady?.();
      w.__resolveReady = null;
      return;
    }
    if (msg.kind === "error" && msg.jobId == null) {
      eventErr("vault.worker.error", { slot, message: msg.message });
      return;
    }
    const job = inflight.get(msg.jobId);
    if (!job) {
      eventErr("vault.scheduler.orphan_message", { slot, jobId: msg.jobId, kind: msg.kind });
      return;
    }
    inflight.delete(msg.jobId);
    idleWorkers.push(w);
    if (msg.kind === "error") {
      job.reject(new Error(msg.message));
    } else {
      job.resolve(msg.result);
    }
    pump();
    notify();
  }

  function pump() {
    while (idleWorkers.length > 0 && jobQueue.length > 0) {
      const w = idleWorkers.shift();
      const job = jobQueue.shift();
      inflight.set(job.jobId, job);
      w.postMessage(job.payload, job.transfer ?? []);
    }
  }

  function enqueueJob(payload, transfer) {
    return new Promise((resolve, reject) => {
      const jobId = nextJobId++;
      jobQueue.push({ jobId, payload: { ...payload, jobId }, transfer, resolve, reject });
      pump();
    });
  }

  async function proveLeaf(leafIndex, airKindTag, publicInputsJson, witnessJson) {
    return enqueueJob({ kind: "leaf", leafIndex, airKindTag, publicInputsJson, witnessJson });
  }

  async function proveMerge(left, right) {
    return enqueueJob({ kind: "merge", left, right }, [left.buffer, right.buffer]);
  }

  async function verifyBytes(bytes, publicInputsJson) {
    return enqueueJob({ kind: "verify", bytes, publicInputsJson });
  }

  /**
   * Submit an ActionPlan to be proved. Returns a Promise resolving to
   * the action's terminal state. The promise rejects only on internal
   * scheduler errors; per-leaf failures resolve the action as FAILED.
   *
   * onUpdate (optional) is invoked synchronously every time the action's
   * node-array mutates (state changes).
   */
  async function submitAction(plan, { onUpdate } = {}) {
    const actionState = {
      actionId: plan.actionId,
      flow: plan.flow,
      state: "running",
      startedAt: performance.now(),
      finishedAt: null,
      nodes: plan.leafSpecs.map((spec) => ({
        id: `a${plan.actionId}-leaf${spec.leafIndex}`,
        kind: NODE_KIND.LEAF,
        air: spec.air,
        leafIndex: spec.leafIndex,
        state: NODE_STATE.QUEUED,
        startedAt: null,
        finishedAt: null,
        proofSizeBytes: null,
        publicInputs: spec.publicInputs,
        privateWitness: spec.privateWitness,
        digestHi: null,
        digestLo: null,
        proofBytes: null,
      })),
      rootNodeId: null,
      error: null,
    };
    actions.set(plan.actionId, actionState);
    notify();
    event("vault.action.queued", {
      action_id: plan.actionId,
      flow: plan.flow,
      kinds_touched: JSON.stringify(plan.kindsTouched),
      leaf_count: plan.leafSpecs.length,
    });

    function tick() {
      onUpdate?.(actionState);
      notify();
    }

    try {
      // Prove all leaves concurrently.
      const leafPromises = actionState.nodes.map(async (node) => {
        node.state = NODE_STATE.PROVING;
        node.startedAt = performance.now();
        tick();
        event("vault.air.prove.start", {
          action_id: plan.actionId,
          air: node.air,
          leaf_index: node.leafIndex,
        });
        try {
          const piJson = JSON.stringify(node.publicInputs);
          if (!node.privateWitness) {
            throw new Error(`leaf ${node.id} (${node.air}) missing privateWitness`);
          }
          const witnessJson = JSON.stringify(node.privateWitness);
          const result = await proveLeaf(
            node.leafIndex,
            mapAirToTag(node.air),
            piJson,
            witnessJson,
          );
          node.state = NODE_STATE.PROVED;
          node.finishedAt = performance.now();
          node.proofSizeBytes = result.proofSizeBytes;
          node.proofBytes = result.bytes;
          node.digestHi = result.digestHi;
          node.digestLo = result.digestLo;
          event("vault.air.prove.done", {
            action_id: plan.actionId,
            air: node.air,
            leaf_index: node.leafIndex,
            prove_ms: Math.round(node.finishedAt - node.startedAt),
            size_bytes: result.proofSizeBytes,
          });
          tick();
        } catch (err) {
          node.state = NODE_STATE.FAILED;
          node.finishedAt = performance.now();
          eventErr("vault.air.prove.failed", {
            action_id: plan.actionId,
            air: node.air,
            leaf_index: node.leafIndex,
            message: err.message,
          });
          tick();
          throw err;
        }
      });
      await Promise.all(leafPromises);

      // Binary fold left-to-right. Each merge consumes two adjacent nodes.
      let pending = actionState.nodes.slice();
      while (pending.length > 1) {
        const left = pending.shift();
        const right = pending.shift();
        const mergeNode = {
          id: `a${plan.actionId}-merge${actionState.nodes.length}`,
          kind: NODE_KIND.MERGE,
          air: "actionRoot",
          leafIndex: null,
          leftId: left.id,
          rightId: right.id,
          state: NODE_STATE.PROVING,
          startedAt: performance.now(),
          finishedAt: null,
          proofSizeBytes: null,
          publicInputs: null,
          digestHi: null,
          digestLo: null,
          proofBytes: null,
        };
        actionState.nodes.push(mergeNode);
        tick();
        event("vault.air.merge.start", {
          action_id: plan.actionId,
          left: left.id,
          right: right.id,
        });
        const result = await proveMerge(left.proofBytes, right.proofBytes);
        // After transfer, left/right proofBytes were detached; clear refs.
        left.proofBytes = null;
        right.proofBytes = null;
        mergeNode.state = NODE_STATE.PROVED;
        mergeNode.finishedAt = performance.now();
        mergeNode.proofSizeBytes = result.proofSizeBytes;
        mergeNode.proofBytes = result.bytes;
        mergeNode.digestHi = result.digestHi;
        mergeNode.digestLo = result.digestLo;
        event("vault.air.merge.done", {
          action_id: plan.actionId,
          node_id: mergeNode.id,
          prove_ms: Math.round(mergeNode.finishedAt - mergeNode.startedAt),
          size_bytes: result.proofSizeBytes,
        });
        tick();
        pending.unshift(mergeNode);
      }

      const root = pending[0];
      actionState.rootNodeId = root.id;
      // Verify the root.
      const verify = await verifyBytes(root.proofBytes, null);
      if (!verify.verified) throw new Error("root verification returned verified=false");
      root.state = NODE_STATE.VERIFIED;
      root.proofBytes = null;
      actionState.state = "done";
      actionState.finishedAt = performance.now();
      event("vault.action.done", {
        action_id: plan.actionId,
        flow: plan.flow,
        root_node_id: root.id,
        duration_ms: Math.round(actionState.finishedAt - actionState.startedAt),
        leaf_count: plan.leafSpecs.length,
      });
      tick();
      return { ok: true, state: actionState };
    } catch (err) {
      actionState.state = "failed";
      actionState.error = err.message;
      actionState.finishedAt = performance.now();
      eventErr("vault.action.failed", {
        action_id: plan.actionId,
        flow: plan.flow,
        message: actionState.error,
      });
      tick();
      return { ok: false, state: actionState };
    }
  }

  function clearAction(actionId) {
    actions.delete(actionId);
    notify();
  }

  function clearAll() {
    actions.clear();
    notify();
  }

  return { init, subscribe, snapshot, submitAction, clearAction, clearAll };
}

const AIR_NAME_TO_TAG = Object.freeze({
  compliance: 0,
  conservationFungible: 1,
  offerCreate: 2,
  offerSolve: 3,
  offerCancel: 4,
  userKey: 5,
  actionRoot: 6,
});

function mapAirToTag(name) {
  const tag = AIR_NAME_TO_TAG[name];
  if (tag == null) throw new Error(`unknown air name: ${name}`);
  return tag;
}
