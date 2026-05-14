// In-memory vault state.
//
// Tracks:
//   - identities (username -> { nk, userkey_salt })
//   - resources  (uid -> ResourceRecord) — only the *live* set; nullified
//     resources are removed from this map and their nf recorded.
//   - nullifiers (Set<hex>) — the toy substitute for the IMT.
//   - actions    (array of ActionRecord) — completed and pending.
//
// Subscribe pattern mirrors zkp.scheduler.mjs's: register a listener with
// `subscribe(fn)`, receive the full snapshot on each mutation.

import {
  deriveNk,
  deriveUserkeySalt,
  deriveCommitment,
  freshRho,
  freshRseed,
  toHex,
} from "./vault.auth.mjs";

const CANONICAL_USDC_LABEL = "vault.usdc";

let nextResourceUid = 1;
let nextActionId = 1;

/**
 * @typedef {Object} ResourceRecord
 * @property {string} uid
 * @property {string} kind            - canonical kind label, e.g. "vault.usdc"
 * @property {"erc20" | "offer"} kindFamily
 * @property {number|null} amount     - for erc20 only
 * @property {object|null} offerState - for offer only
 * @property {"userkey" | "offer-self"} ownerKindFamily
 * @property {string} ownerUsername   - userkey-owned only
 * @property {string} ownerSaltHex
 * @property {string} rhoHex
 * @property {string} rseedHex
 * @property {string} commitmentHex
 */

export function createStore() {
  const state = {
    identities: new Map(),
    resources: new Map(),
    nullifiers: new Set(),
    registeredKinds: new Set([CANONICAL_USDC_LABEL, "vault.eth"]),
    actions: [],
    pendingActions: 0,
    completedActions: 0,
    failedActions: 0,
  };
  const listeners = new Set();

  function notify() {
    for (const l of listeners) {
      try {
        l(snapshot());
      } catch (err) {
        console.error("vault state listener threw:", err);
      }
    }
  }

  function subscribe(fn) {
    listeners.add(fn);
    fn(snapshot());
    return () => listeners.delete(fn);
  }

  function snapshot() {
    return {
      identities: Array.from(state.identities.entries()).map(([username, v]) => ({
        username,
        nkHex: toHex(v.nk),
        userkeySaltHex: toHex(v.userkeySalt),
      })),
      resources: Array.from(state.resources.values()),
      nullifiers: Array.from(state.nullifiers),
      registeredKinds: Array.from(state.registeredKinds),
      actions: state.actions.slice(),
      pendingActions: state.pendingActions,
      completedActions: state.completedActions,
      failedActions: state.failedActions,
    };
  }

  async function addIdentity(username) {
    if (state.identities.has(username)) return state.identities.get(username);
    const nk = await deriveNk(username);
    const userkeySalt = await deriveUserkeySalt(nk);
    state.identities.set(username, { nk, userkeySalt });
    notify();
    return { nk, userkeySalt };
  }

  function getIdentity(username) {
    const id = state.identities.get(username);
    if (!id) throw new Error(`no identity registered for ${username}`);
    return id;
  }

  function registerKind(label) {
    if (state.registeredKinds.has(label)) return false;
    state.registeredKinds.add(label);
    notify();
    return true;
  }

  async function mintErc20({ kindLabel, amount, ownerUsername }) {
    if (!state.identities.has(ownerUsername)) {
      throw new Error(`unknown identity ${ownerUsername}`);
    }
    if (!state.registeredKinds.has(kindLabel)) {
      throw new Error(`unregistered kind ${kindLabel}`);
    }
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new Error(`amount must be a positive integer (got ${amount})`);
    }
    const owner = state.identities.get(ownerUsername);
    const rho = freshRho();
    const rseed = freshRseed();
    const preimage = {
      logic: "erc20",
      label: kindLabel,
      valueRef: { amount },
      ownerKind: "userkey",
      ownerSaltHex: toHex(owner.userkeySalt),
      rhoHex: toHex(rho),
      rseedHex: toHex(rseed),
    };
    const cm = await deriveCommitment(preimage);
    const uid = `r${nextResourceUid++}`;
    const record = {
      uid,
      kind: kindLabel,
      kindFamily: "erc20",
      amount,
      offerState: null,
      ownerKindFamily: "userkey",
      ownerUsername,
      ownerSaltHex: toHex(owner.userkeySalt),
      rhoHex: toHex(rho),
      rseedHex: toHex(rseed),
      commitmentHex: toHex(cm),
      preimage,
    };
    state.resources.set(uid, record);
    notify();
    return record;
  }

  function isFungibleFeeKind(kindLabel) {
    return kindLabel === CANONICAL_USDC_LABEL;
  }

  function consume(uid, nfHex) {
    const record = state.resources.get(uid);
    if (!record) throw new Error(`resource ${uid} not live`);
    state.resources.delete(uid);
    state.nullifiers.add(nfHex);
    return record;
  }

  function create(record) {
    state.resources.set(record.uid, record);
  }

  function nextUid() {
    return `r${nextResourceUid++}`;
  }

  function recordAction(action) {
    state.actions.push(action);
    if (state.actions.length > 200) state.actions.shift();
    notify();
  }

  function setPendingDelta(delta) {
    state.pendingActions = Math.max(0, state.pendingActions + delta);
    notify();
  }

  function setCompleted(success) {
    if (success) state.completedActions += 1;
    else state.failedActions += 1;
    notify();
  }

  function reset() {
    state.resources.clear();
    state.nullifiers.clear();
    state.actions.length = 0;
    state.pendingActions = 0;
    state.completedActions = 0;
    state.failedActions = 0;
    nextResourceUid = 1;
    nextActionId = 1;
    notify();
  }

  function nextActionIdAndAllocate() {
    return nextActionId++;
  }

  function getResource(uid) {
    const r = state.resources.get(uid);
    if (!r) throw new Error(`resource ${uid} is not live`);
    return r;
  }

  return {
    subscribe,
    snapshot,
    addIdentity,
    getIdentity,
    registerKind,
    mintErc20,
    isFungibleFeeKind,
    consume,
    create,
    nextUid,
    recordAction,
    setPendingDelta,
    setCompleted,
    reset,
    nextActionIdAndAllocate,
    getResource,
    CANONICAL_USDC_LABEL,
  };
}
