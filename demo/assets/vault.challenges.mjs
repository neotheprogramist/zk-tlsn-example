// Pluggable Offer-challenge registry. Each entry describes one challenge
// family the Offer logic supports. Adding a new challenge is one struct
// in this map plus (in a future revision) one in-circuit constraint set
// on the Rust side. The toy currently double-checks the witness in JS
// for instant UX rejection; the OfferSolve AIR's circuit enforces the
// constraint on the proof side (see vault/src/leaf_circuits.rs).

import { toHex } from "./vault.auth.mjs";
import init, { poseidonHash } from "/assets/wasm/vault.js";

const enc = new TextEncoder();

let wasmReady = null;
async function ensureWasm() {
  if (!wasmReady) wasmReady = init();
  return wasmReady;
}

async function challengePublicHash(challengeId, declaration) {
  await ensureWasm();
  const payload = enc.encode(challengeId + " " + JSON.stringify(declaration));
  const limbs = Array.from(payload);
  const outJson = poseidonHash(JSON.stringify(limbs));
  const outLimbs = JSON.parse(outJson);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = outLimbs[i] | 0;
    out[4 * i] = v & 0xff;
    out[4 * i + 1] = (v >> 8) & 0xff;
    out[4 * i + 2] = (v >> 16) & 0xff;
    out[4 * i + 3] = (v >> 24) & 0xff;
  }
  return out;
}

const x_plus_1_eq_2 = {
  id: "x_plus_1_eq_2",
  title: "x + 1 = 2",
  description: "Solver provides x such that x + 1 == 2.",
  paramSchema: [],
  witnessSchema: [{ name: "x", kind: "number" }],
  declaration: () => ({ equation: "x + 1 == 2" }),
  verify: (_decl, witness) => Number(witness.x) + 1 === 2,
};

const sum_eq_n = {
  id: "sum_eq_n",
  title: "x + y = N",
  description: "Solver provides x and y such that x + y == N.",
  paramSchema: [{ name: "n", kind: "number" }],
  witnessSchema: [
    { name: "x", kind: "number" },
    { name: "y", kind: "number" },
  ],
  declaration: (params) => ({ equation: "x + y == N", n: Number(params.n) }),
  verify: (decl, witness) => Number(witness.x) + Number(witness.y) === Number(decl.n),
};

const product_eq_n = {
  id: "product_eq_n",
  title: "x * y = N",
  description: "Solver provides x > 1 and y > 1 such that x * y == N.",
  paramSchema: [{ name: "n", kind: "number" }],
  witnessSchema: [
    { name: "x", kind: "number" },
    { name: "y", kind: "number" },
  ],
  declaration: (params) => ({ equation: "x * y == N (factor)", n: Number(params.n) }),
  verify: (decl, witness) => {
    const x = Number(witness.x);
    const y = Number(witness.y);
    return x > 1 && y > 1 && x * y === Number(decl.n);
  },
};

// TLSN-based challenge: solver proves (via an out-of-band TLSN session) that
// they executed a bank transfer matching the offer's declaration. The
// challenge itself stores no in-circuit constraint — verify() returns true
// because the real check lives in the TLSN gate in vault.handlers.mjs
// (Etap A: hardcoded JS stub, Etap B: real TLSN proving + verifier).
const tlsn_transfer = {
  id: "tlsn_transfer",
  title: "TLSN bank transfer",
  description:
    "Solver must prove via TLSN that they executed a bank transfer to the offer creator's bank account for exactly `price` USD. The recipient bank user-id is derived from the creator's vault identity at offer-creation time (see bankUserIdFor) and stored in the declaration as `expectedToUserId`. Both values are bound in the offerSolveTlsnTransfer circuit.",
  paramSchema: [{ name: "price", kind: "number" }],
  witnessSchema: [],
  // `expectedToUserId` is injected into `params` by the offer-creation
  // handler before calling this; it is not user-picked.
  declaration: (params) => ({
    price: Number(params.price ?? 0),
    expectedToUserId: Number(params.expectedToUserId ?? 0),
  }),
  // The real verification happens in the TLSN gate + in-circuit policy
  // check; the JS-side hook is a no-op so buildSolveOffer's
  // challenge.verify() call always passes.
  verify: () => true,
};

// Demo bank ledger (`demo/src/ledger.rs`) seeds users in fixed insertion
// order with sequential u64 IDs starting at 1: alice=1, bob=2, treasury=3.
// `tlsn_transfer` derives the offer's `expectedToUserId` from the active
// vault identity at offer-creation time, so the user doesn't have to type
// their own bank account number into the offer form.
const BANK_USER_IDS_BY_USERNAME = { alice: 1, bob: 2, treasury: 3 };

export function bankUserIdFor(username) {
  const id = BANK_USER_IDS_BY_USERNAME[username];
  if (id == null) {
    throw new Error(`no bank user_id mapped for vault identity ${username}`);
  }
  return id;
}

const REGISTRY = new Map([
  [x_plus_1_eq_2.id, x_plus_1_eq_2],
  [sum_eq_n.id, sum_eq_n],
  [product_eq_n.id, product_eq_n],
  [tlsn_transfer.id, tlsn_transfer],
]);

export function listChallenges() {
  return Array.from(REGISTRY.values());
}

export function getChallenge(id) {
  const c = REGISTRY.get(id);
  if (!c) throw new Error(`unknown challenge id: ${id}`);
  return c;
}

export async function computeChallengePublicHash(challengeId, declaration) {
  return toHex(await challengePublicHash(challengeId, declaration));
}
