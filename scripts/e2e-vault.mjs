#!/usr/bin/env node
// E2E: drive /vault in headed Chromium and assert against the structured
// event stream emitted by the page (`vault.*` events) and the rendered DOM.
//
// Coverage:
//   - Happy paths (H1-H6) — every user-facing flow through real UI buttons
//   - Error paths (E1-E5) — every inline-validation surface
//
// Each scenario starts from a clean vault via the in-page "reset vault"
// button, so a failure mid-suite does not corrupt later scenarios.
//
// Hard assertions per scenario:
//   - Exact resource balances per (owner, kind) — JSON-equality, not subset
//   - Nullifier count grew by the exact number of consumed resources
//   - Balance conservation: sum(live erc20 amounts) == sum(minted) this scenario
//   - Proving tree leaves match the EXPECTED_LEAVES_BY_FLOW table exactly
//   - Every viz-action reaches data-state="done" before assertions run
//   - Each leaf has plausible prove_ms / size_bytes
//   - Error paths: inline .field-error surfaces the expected substring AND
//     no state mutation occurs

import fs from "node:fs";
import path from "node:path";

import {
  SERVICE_ADDR,
  assertEquals,
  assertInRange,
  installPageErrorForwarder,
  launchHeadedChromium,
  runCleanup,
  setupBrowserCapture,
  startDemoBinary,
  waitForEvent,
} from "./lib/harness.mjs";

const POOL = Number(process.env.VAULT_E2E_POOL ?? "4");
const ACTION_TIMEOUT_MS = Number(process.env.VAULT_E2E_ACTION_TIMEOUT_MS ?? "600000");
const STEP_TIMEOUT_MS = Number(process.env.VAULT_E2E_STEP_TIMEOUT_MS ?? "60000");
const PROVE_MS_MIN = 50;
const PROVE_MS_MAX = 600_000;
const PROOF_SIZE_MIN = 1_000;
const PROOF_SIZE_MAX = 1_500_000;

const USDC = "vault.usdc";
const ETH = "vault.eth";

function tag(label) {
  return `\x1b[36m[vault-e2e]\x1b[0m ${label}`;
}

// ─── DOM scrapers (use Locator.all() + per-handle getAttribute; no $$eval) ─

async function readResources(page) {
  const handles = await page.locator('[data-role="resource-row"]').all();
  const out = [];
  for (const h of handles) {
    const [
      uid,
      kind,
      kindFamily,
      owner,
      ownerKindFamily,
      amount,
      offerInstance,
      offerChallenge,
      offerLockedAmount,
      offerCreator,
    ] = await Promise.all([
      h.getAttribute("data-uid"),
      h.getAttribute("data-kind"),
      h.getAttribute("data-kind-family"),
      h.getAttribute("data-owner"),
      h.getAttribute("data-owner-kind-family"),
      h.getAttribute("data-amount"),
      h.getAttribute("data-offer-instance"),
      h.getAttribute("data-offer-challenge"),
      h.getAttribute("data-offer-locked-amount"),
      h.getAttribute("data-offer-creator"),
    ]);
    out.push({
      uid,
      kind,
      kindFamily,
      owner,
      ownerKindFamily,
      amount: amount != null ? Number(amount) : null,
      offerInstance,
      offerChallenge,
      offerLockedAmount: offerLockedAmount != null ? Number(offerLockedAmount) : null,
      offerCreator,
    });
  }
  return out;
}

async function readNfCount(page) {
  const v = await page.locator('[data-role="nf-count"]').getAttribute("data-count");
  return Number(v ?? "0");
}

async function readTrees(page) {
  const cards = await page.locator('[data-role="viz-action"]').all();
  const out = [];
  for (const card of cards) {
    const [actionId, flow, state] = await Promise.all([
      card.getAttribute("data-action-id"),
      card.getAttribute("data-flow"),
      card.getAttribute("data-state"),
    ]);
    const nodes = await card.locator('[data-role="viz-node"]').all();
    const leafKinds = [];
    for (const n of nodes) {
      leafKinds.push(await n.getAttribute("data-air"));
    }
    out.push({ actionId, flow, state, leafKinds });
  }
  return out;
}

// ─── UI helpers ────────────────────────────────────────────────────────────

async function setIdentity(page, username) {
  await page.locator('[data-role="identity"]').selectOption(username);
}

async function mintResource(page, { kind, amount, owner }) {
  await page.locator('[data-role="mint-kind"]').selectOption(kind);
  await page.locator('[data-role="mint-amount"]').fill(String(amount));
  await page.locator('[data-role="mint-owner"]').selectOption(owner);
  const wait = waitForEvent({
    page,
    event: "vault.resource.minted",
    predicate: (f) => f.kind === kind && f.amount === amount && f.owner === owner,
    timeoutMs: STEP_TIMEOUT_MS,
    label: `vault.resource.minted ${kind}/${amount}/${owner}`,
  });
  await page.locator('[data-role="mint"]').click();
  return await wait;
}

async function clearAllSelections(page) {
  const rows = await page.locator('[data-role="resource-row"]').all();
  for (const row of rows) {
    const cb = row.locator('[data-role="resource-select"]');
    if (await cb.isChecked()) {
      await cb.uncheck();
    }
  }
}

async function selectResources(page, uids) {
  await clearAllSelections(page);
  for (const uid of uids) {
    const row = page.locator(`[data-role="resource-row"][data-uid="${uid}"]`);
    await row.locator('[data-role="resource-select"]').check();
  }
}

async function clickTab(page, tabName) {
  await page.locator(`[data-action-tab="${tabName}"]`).click();
}

async function setTransferOutputs(page, outputs) {
  const rowCount = await page.locator('[data-role="transfer-output-row"]').count();
  for (let i = rowCount - 1; i > 0; i--) {
    await page.locator('[data-role="transfer-output-row"]').nth(i).locator("button").click();
  }
  for (let i = 1; i < outputs.length; i++) {
    await page.locator('[data-role="transfer-add-output"]').click();
  }
  for (let i = 0; i < outputs.length; i++) {
    const row = page.locator('[data-role="transfer-output-row"]').nth(i);
    await row
      .locator('[data-role="transfer-output-recipient"]')
      .selectOption(outputs[i].recipientUsername);
    await row.locator('[data-role="transfer-output-amount"]').fill(String(outputs[i].amount));
  }
}

async function setOfferChallengeParams(page, params) {
  for (const [name, value] of Object.entries(params)) {
    await page
      .locator(`[data-role="offer-challenge-param"][data-field-name="${name}"]`)
      .fill(String(value));
  }
}

async function setSolveWitness(page, witness) {
  for (const [name, value] of Object.entries(witness)) {
    await page.waitForSelector(`[data-role="solve-witness-input"][data-field-name="${name}"]`);
    await page
      .locator(`[data-role="solve-witness-input"][data-field-name="${name}"]`)
      .fill(String(value));
  }
}

async function findUsdcUid(page, owner, atLeastAmount) {
  const all = await readResources(page);
  const candidate = all.find(
    (r) => r.kind === USDC && r.owner === owner && (r.amount ?? 0) >= atLeastAmount,
  );
  return candidate?.uid ?? null;
}

function waitActionDone(page, flow) {
  return waitForEvent({
    page,
    event: "vault.action.done",
    predicate: (f) => f.flow === flow,
    errorEvents: ["vault.action.failed", "vault.action.submit.failed", "runtime.page.error"],
    timeoutMs: ACTION_TIMEOUT_MS,
    label: `vault.action.done flow=${flow}`,
  });
}

function waitSubmitFailed(page, flow) {
  return waitForEvent({
    page,
    event: "vault.action.submit.failed",
    predicate: (f) => f.flow === flow,
    timeoutMs: STEP_TIMEOUT_MS,
    label: `vault.action.submit.failed flow=${flow}`,
  });
}

// After waitActionDone resolves the store mutation may not yet be reflected
// in the DOM (the renderer subscribes to the store, which fires notify after
// recordAction). Wait for the newest viz-action card to reach data-state="done"
// before scraping resources.
async function waitVizDone(page, flow) {
  await page.waitForFunction(
    (expectedFlow) => {
      const cards = document.querySelectorAll('[data-role="viz-action"]');
      if (cards.length === 0) return false;
      const latest = cards[0];
      return (
        latest.getAttribute("data-flow") === expectedFlow &&
        latest.getAttribute("data-state") === "done"
      );
    },
    flow,
    { timeout: ACTION_TIMEOUT_MS },
  );
}

// ─── Inline-error helpers ──────────────────────────────────────────────────

async function getFieldErrorNear(page, inputDataRole) {
  const slot = page
    .locator(".field", { has: page.locator(`[data-role="${inputDataRole}"]`) })
    .locator(".field-error");
  if ((await slot.count()) === 0) return "";
  return (await slot.first().textContent()) ?? "";
}

async function getFormError(page, errorDataRole) {
  return (await page.locator(`[data-role="${errorDataRole}"]`).textContent()) ?? "";
}

// ─── Balance helpers ───────────────────────────────────────────────────────

function balancesByOwner(resources, kind) {
  const groups = new Map();
  for (const r of resources) {
    if (r.kind !== kind) continue;
    const key = r.owner ?? `(${r.ownerKindFamily ?? "anon"})`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r.amount);
  }
  for (const arr of groups.values()) arr.sort((a, b) => a - b);
  return groups;
}

function canonicalJson(obj) {
  // Stable stringify: sort top-level keys so order doesn't matter to equality.
  const keys = Object.keys(obj).sort();
  const sorted = {};
  for (const k of keys) sorted[k] = obj[k];
  return JSON.stringify(sorted);
}

function assertBalances(label, resources, kind, expected) {
  const got = balancesByOwner(resources, kind);
  const expectedSorted = {};
  for (const k of Object.keys(expected)) {
    expectedSorted[k] = expected[k].slice().sort((a, b) => a - b);
  }
  const flat = Object.fromEntries([...got.entries()].map(([k, v]) => [k, v]));
  const aJson = canonicalJson(expectedSorted);
  const bJson = canonicalJson(flat);
  if (aJson !== bJson) {
    throw new Error(`${label}: expected balances ${aJson}, got ${bJson}`);
  }
}

function totalLiveAmount(resources) {
  return resources.filter((r) => r.kindFamily === "erc20").reduce((s, r) => s + (r.amount ?? 0), 0);
}

function assertConservation(label, resources, totalMinted) {
  // Every action burns 0 value — fees are 1 USDC to the aggregator, locked
  // resources are still owned (offer-self) — so live total must equal minted.
  const live = totalLiveAmount(resources);
  if (live !== totalMinted) {
    throw new Error(
      `${label}: conservation violated. minted=${totalMinted}, live=${live}, diff=${totalMinted - live}`,
    );
  }
}

// ─── Tree-shape assertion ──────────────────────────────────────────────────

function expectTreeShape(tree, expected) {
  const got = {};
  for (const k of tree.leafKinds) got[k] = (got[k] ?? 0) + 1;
  const sortKey = (o) => Object.keys(o).sort();
  const eJson = JSON.stringify(expected, sortKey(expected));
  const gJson = JSON.stringify(got, sortKey(got));
  if (eJson !== gJson) {
    throw new Error(
      `tree #${tree.actionId} (${tree.flow}): expected leaves ${eJson}, got ${gJson}`,
    );
  }
  if (tree.state !== "done") {
    throw new Error(`tree #${tree.actionId} (${tree.flow}): state=${tree.state}, expected done`);
  }
}

// Expected node counts (LEAVES + actionRoot merge nodes combined, since both
// surface in viz-node DOM and the test scrapes via [data-role="viz-node"]).
// Binary fold reduces N leaves with N-1 merges, every merge labelled actionRoot.
// Keys match the camelCase AIR wire format (see vault/src/air.rs::name).
const LEAVES = {
  // 3 leaves (compliance + conservation + userKey) → 2 merges
  transferSingleKind: {
    compliance: 1,
    conservationFungible: 1,
    userKey: 1,
    actionRoot: 2,
  },
  // 4 leaves (compliance + 2 × conservation + userKey) → 3 merges
  transferMultiKind: {
    compliance: 1,
    conservationFungible: 2,
    userKey: 1,
    actionRoot: 3,
  },
  // 5 leaves (compliance + 2 × conservation + offer* + userKey) → 4 merges
  createOffer: {
    compliance: 1,
    conservationFungible: 2,
    offerCreate: 1,
    userKey: 1,
    actionRoot: 4,
  },
  solveOffer: {
    compliance: 1,
    conservationFungible: 2,
    offerSolve: 1,
    userKey: 1,
    actionRoot: 4,
  },
  cancelOffer: {
    compliance: 1,
    conservationFungible: 2,
    offerCancel: 1,
    userKey: 1,
    actionRoot: 4,
  },
};

// ─── Reset between scenarios ───────────────────────────────────────────────

async function resetVault(page) {
  const wait = waitForEvent({
    page,
    event: "vault.reset",
    timeoutMs: STEP_TIMEOUT_MS,
    label: "vault.reset",
  });
  await page.locator('[data-role="reset"]').click();
  await wait;
  await page.waitForFunction(
    () => document.querySelectorAll('[data-role="resource-row"]').length === 0,
    { timeout: STEP_TIMEOUT_MS },
  );
  const nf = await readNfCount(page);
  if (nf !== 0) throw new Error(`reset: expected nf-count=0, got ${nf}`);
}

// Tracks the cumulative mint total per scenario so conservation can be checked.
class MintLedger {
  constructor() {
    this.total = 0;
  }
  add(amount) {
    this.total += amount;
  }
}

// ─── Submit-button-disabled-while-pending assertion ────────────────────────

async function assertButtonDisabledDuring(page, dataRole, asyncOp) {
  let observedDisabled = false;
  const poll = setInterval(async () => {
    try {
      const isDisabled = await page.locator(`[data-role="${dataRole}"]`).isDisabled();
      if (isDisabled) observedDisabled = true;
    } catch {
      // ignore — page may have navigated mid-poll
    }
  }, 50);
  try {
    await asyncOp();
  } finally {
    clearInterval(poll);
  }
  if (!observedDisabled) {
    throw new Error(`expected ${dataRole} to be disabled at some point during the action`);
  }
}

// ─── Scenarios ─────────────────────────────────────────────────────────────

async function scenarioH1_mintTransferSingleKind(page) {
  // Mint two USDC resources for alice (transfer input + fee), transfer
  // 60 USDC alice → bob. Same-kind (USDC) transfer + USDC fee →
  // 1 conservation leaf. The fee resource must be distinct from inputs.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 100, owner: "alice" });
  ledger.add(100);
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);

  const r0 = await readResources(page);
  const aliceInput = r0.find((r) => r.kind === USDC && r.owner === "alice" && r.amount === 100).uid;
  const aliceFee = r0.find((r) => r.kind === USDC && r.owner === "alice" && r.amount === 5).uid;

  await clickTab(page, "transfer");
  await selectResources(page, [aliceInput]);
  await setTransferOutputs(page, [{ recipientUsername: "bob", amount: 60 }]);
  await page.locator('[data-role="transfer-fee-resource"]').selectOption(aliceFee);

  const done = waitActionDone(page, "transfer");
  await assertButtonDisabledDuring(page, "transfer-submit", async () => {
    await page.locator('[data-role="transfer-submit"]').click();
    await done;
  });
  await waitVizDone(page, "transfer");

  const resources = await readResources(page);
  // alice: 100 → bob 60 + alice 40 change. Fee resource 5 → fee 1 + alice 4 change.
  assertBalances("H1.usdc", resources, USDC, {
    alice: [4, 40],
    bob: [60],
    "(aggregator)": [1],
  });
  assertEquals("H1.nf_growth", 2, await readNfCount(page));
  assertConservation("H1", resources, ledger.total);

  const trees = await readTrees(page);
  assertEquals("H1.tree_count", 1, trees.length);
  expectTreeShape(trees[0], LEAVES.transferSingleKind);
}

async function scenarioH2_mintTransferMultiKind(page) {
  // Mint 100 USDC + 50 ETH (alice). Transfer 25 ETH alice → bob, fee USDC.
  // Multi-kind → 2 conservation leaves (ETH + USDC).
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 100, owner: "alice" });
  ledger.add(100);
  await mintResource(page, { kind: ETH, amount: 50, owner: "alice" });
  ledger.add(50);

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceUsdc = await findUsdcUid(page, "alice", 1);

  await clickTab(page, "transfer");
  await selectResources(page, [aliceEth]);
  await setTransferOutputs(page, [{ recipientUsername: "bob", amount: 25 }]);
  await page.locator('[data-role="transfer-fee-resource"]').selectOption(aliceUsdc);

  const done = waitActionDone(page, "transfer");
  await page.locator('[data-role="transfer-submit"]').click();
  await done;
  await waitVizDone(page, "transfer");

  const resources = await readResources(page);
  assertBalances("H2.eth", resources, ETH, { alice: [25], bob: [25] });
  assertBalances("H2.usdc", resources, USDC, { alice: [99], "(aggregator)": [1] });
  assertEquals("H2.nf_growth", 2, await readNfCount(page));
  assertConservation("H2", resources, ledger.total);

  const trees = await readTrees(page);
  assertEquals("H2.tree_count", 1, trees.length);
  expectTreeShape(trees[0], LEAVES.transferMultiKind);
}

async function scenarioH3_createSolveTrivialChallenge(page) {
  // Alice creates an offer locking 100 ETH with challenge x+1=2.
  // Bob solves with x=1 and receives 100 ETH.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  ledger.add(5);
  await mintResource(page, { kind: ETH, amount: 100, owner: "alice" });
  ledger.add(100);

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceFee1 = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("100");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee1);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const r1 = await readResources(page);
  const offers = r1.filter((r) => r.kindFamily === "offer");
  assertEquals("H3.offer_count_after_create", 1, offers.length);
  assertEquals("H3.offer_challenge", "x_plus_1_eq_2", offers[0].offerChallenge);
  const offerUid = offers[0].uid;

  await setIdentity(page, "bob");
  await clickTab(page, "solve_offer");
  await page.locator('[data-role="solve-offer-select"]').selectOption(offerUid);
  await setSolveWitness(page, { x: 1 });
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="solve-fee-resource"]').selectOption(bobFee);
  const solve = waitActionDone(page, "solve_offer");
  await page.locator('[data-role="solve-submit"]').click();
  await solve;
  await waitVizDone(page, "solve_offer");

  const r2 = await readResources(page);
  assertBalances("H3.eth", r2, ETH, { bob: [100] });
  assertBalances("H3.usdc", r2, USDC, { alice: [4], bob: [4], "(aggregator)": [1, 1] });
  assertEquals("H3.no_offers_left", 0, r2.filter((r) => r.kindFamily === "offer").length);
  // 2 consumed in create (eth input + usdc fee) + 3 consumed in solve
  // (offer + locked + bob's usdc fee) = 5 nullifiers
  assertEquals("H3.nf_growth", 5, await readNfCount(page));
  assertConservation("H3", r2, ledger.total);

  const trees = await readTrees(page);
  assertEquals("H3.tree_count", 2, trees.length);
  expectTreeShape(trees[0], LEAVES.solveOffer);
  expectTreeShape(trees[1], LEAVES.createOffer);
}

async function scenarioH4_createSolveWithRefund(page) {
  // Variant of create+solve where alice locks only part of her ETH and gets
  // a refund. Exercises the refund_amount > 0 code path in buildCreateOffer.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  ledger.add(5);
  await mintResource(page, { kind: ETH, amount: 80, owner: "alice" });
  ledger.add(80);

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  // Lock 60, refund 20 to alice. 60 + 20 = 80 = totalIn.
  await page.locator('[data-role="offer-locked-amount"]').fill("60");
  await page.locator('[data-role="offer-refund-amount"]').fill("20");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const offerUid = (await readResources(page)).find((r) => r.kindFamily === "offer").uid;

  await setIdentity(page, "bob");
  await clickTab(page, "solve_offer");
  await page.locator('[data-role="solve-offer-select"]').selectOption(offerUid);
  await setSolveWitness(page, { x: 1 });
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="solve-fee-resource"]').selectOption(bobFee);
  const solve = waitActionDone(page, "solve_offer");
  await page.locator('[data-role="solve-submit"]').click();
  await solve;
  await waitVizDone(page, "solve_offer");

  const r2 = await readResources(page);
  // Alice keeps the 20 ETH refund; bob receives the 60 ETH that was locked.
  assertBalances("H4.eth", r2, ETH, { alice: [20], bob: [60] });
  assertEquals("H4.no_offers_left", 0, r2.filter((r) => r.kindFamily === "offer").length);
  // 2 consumed in create + 3 in solve = 5 nullifiers
  assertEquals("H4.nf_growth", 5, await readNfCount(page));
  assertConservation("H4", r2, ledger.total);
}

async function scenarioH5_createCancel(page) {
  // Alice creates an offer locking 30 ETH, then cancels it. ETH returns.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);
  await mintResource(page, { kind: ETH, amount: 30, owner: "alice" });
  ledger.add(30);

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceFee1 = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("30");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee1);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const offerUid = (await readResources(page)).find((r) => r.kindFamily === "offer").uid;

  await clickTab(page, "cancel_offer");
  await page.locator('[data-role="cancel-offer-select"]').selectOption(offerUid);
  const aliceFee2 = await findUsdcUid(page, "alice", 1);
  await page.locator('[data-role="cancel-fee-resource"]').selectOption(aliceFee2);
  const cancel = waitActionDone(page, "cancel_offer");
  await page.locator('[data-role="cancel-submit"]').click();
  await cancel;
  await waitVizDone(page, "cancel_offer");

  const r2 = await readResources(page);
  assertBalances("H5.eth", r2, ETH, { alice: [30] });
  assertEquals("H5.no_offers_left", 0, r2.filter((r) => r.kindFamily === "offer").length);
  // 2 consumed in create + 3 in cancel = 5 nullifiers
  assertEquals("H5.nf_growth", 5, await readNfCount(page));
  assertConservation("H5", r2, ledger.total);

  const trees = await readTrees(page);
  expectTreeShape(trees[0], LEAVES.cancelOffer);
  expectTreeShape(trees[1], LEAVES.createOffer);
}

async function scenarioH7_createSolveSumEqN(page) {
  // Parametrized challenge sum_eq_n with n=10; bob solves with x=3, y=7.
  // Exercises the OfferSolveSumEqN circuit dispatch end-to-end.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  ledger.add(5);
  await mintResource(page, { kind: ETH, amount: 50, owner: "alice" });
  ledger.add(50);

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("50");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("sum_eq_n");
  await setOfferChallengeParams(page, { n: 10 });
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const offerUid = (await readResources(page)).find((r) => r.kindFamily === "offer").uid;

  await setIdentity(page, "bob");
  await clickTab(page, "solve_offer");
  await page.locator('[data-role="solve-offer-select"]').selectOption(offerUid);
  await setSolveWitness(page, { x: 3, y: 7 });
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="solve-fee-resource"]').selectOption(bobFee);
  const solve = waitActionDone(page, "solve_offer");
  await page.locator('[data-role="solve-submit"]').click();
  await solve;
  await waitVizDone(page, "solve_offer");

  const r2 = await readResources(page);
  assertBalances("H7.eth", r2, ETH, { bob: [50] });
  assertEquals("H7.no_offers_left", 0, r2.filter((r) => r.kindFamily === "offer").length);
  // 2 consumed in create + 3 in solve = 5 nullifiers
  assertEquals("H7.nf_growth", 5, await readNfCount(page));
  assertConservation("H7", r2, ledger.total);
}

async function scenarioH6_multiInputTransfer(page) {
  // Three ETH inputs (10+15+25=50) → bob 18 + charlie 20 + alice 12 change.
  const ledger = new MintLedger();
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  ledger.add(5);
  for (const amt of [10, 15, 25]) {
    await mintResource(page, { kind: ETH, amount: amt, owner: "alice" });
    ledger.add(amt);
  }

  const r0 = await readResources(page);
  const ethUids = r0.filter((r) => r.kind === ETH && r.owner === "alice").map((r) => r.uid);
  assertEquals("H6.three_eth_inputs", 3, ethUids.length);

  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "transfer");
  await selectResources(page, ethUids);
  await setTransferOutputs(page, [
    { recipientUsername: "bob", amount: 18 },
    { recipientUsername: "charlie", amount: 20 },
  ]);
  await page.locator('[data-role="transfer-fee-resource"]').selectOption(aliceFee);

  const done = waitActionDone(page, "transfer");
  await page.locator('[data-role="transfer-submit"]').click();
  await done;
  await waitVizDone(page, "transfer");

  const r1 = await readResources(page);
  assertBalances("H6.eth", r1, ETH, { alice: [12], bob: [18], charlie: [20] });
  assertBalances("H6.usdc", r1, USDC, { alice: [4], "(aggregator)": [1] });
  assertEquals("H6.nf_growth", 4, await readNfCount(page));
  assertConservation("H6", r1, ledger.total);

  const trees = await readTrees(page);
  expectTreeShape(trees[0], LEAVES.transferMultiKind);
}

// ─── Error-path scenarios ──────────────────────────────────────────────────

async function scenarioE1_transferNoFee(page) {
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 100, owner: "alice" });
  const aliceUsdc = await findUsdcUid(page, "alice", 100);

  await clickTab(page, "transfer");
  await selectResources(page, [aliceUsdc]);
  await setTransferOutputs(page, [{ recipientUsername: "bob", amount: 50 }]);
  // No fee selection.

  const fail = waitSubmitFailed(page, "transfer");
  await page.locator('[data-role="transfer-submit"]').click();
  const fields = await fail;
  if (
    !String(fields.message ?? "")
      .toLowerCase()
      .includes("usdc")
  ) {
    throw new Error(`E1: expected message mentioning USDC, got ${fields.message}`);
  }
  const inlineErr = await getFieldErrorNear(page, "transfer-fee-resource");
  if (!inlineErr.toLowerCase().includes("usdc")) {
    throw new Error(
      `E1: expected inline error near fee dropdown to mention USDC, got "${inlineErr}"`,
    );
  }
  const resources = await readResources(page);
  assertBalances("E1.no_mutation", resources, USDC, { alice: [100] });
  assertEquals("E1.no_nullifiers", 0, await readNfCount(page));
}

async function scenarioE2_transferNoInputs(page) {
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 100, owner: "alice" });
  const aliceUsdc = await findUsdcUid(page, "alice", 100);

  await clickTab(page, "transfer");
  // No selectResources call.
  await setTransferOutputs(page, [{ recipientUsername: "bob", amount: 10 }]);
  await page.locator('[data-role="transfer-fee-resource"]').selectOption(aliceUsdc);

  const fail = waitSubmitFailed(page, "transfer");
  await page.locator('[data-role="transfer-submit"]').click();
  const fields = await fail;
  if (
    !String(fields.message ?? "")
      .toLowerCase()
      .includes("erc20 resource")
  ) {
    throw new Error(`E2: expected "erc20 resource" in message, got ${fields.message}`);
  }
  const formErr = await getFormError(page, "transfer-error");
  if (!formErr.toLowerCase().includes("erc20 resource")) {
    throw new Error(
      `E2: expected form-level transfer-error to mention "erc20 resource", got "${formErr}"`,
    );
  }
  const resources = await readResources(page);
  assertBalances("E2.no_mutation", resources, USDC, { alice: [100] });
  assertEquals("E2.no_nullifiers", 0, await readNfCount(page));
}

async function scenarioE3_solveWrongWitness(page) {
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  await mintResource(page, { kind: ETH, amount: 10, owner: "alice" });

  const r0 = await readResources(page);
  const aliceEth = r0.find((r) => r.kind === ETH && r.owner === "alice").uid;
  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("10");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const offerUid = (await readResources(page)).find((r) => r.kindFamily === "offer").uid;

  await setIdentity(page, "bob");
  await clickTab(page, "solve_offer");
  await page.locator('[data-role="solve-offer-select"]').selectOption(offerUid);
  await setSolveWitness(page, { x: 2 });
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="solve-fee-resource"]').selectOption(bobFee);

  const fail = waitSubmitFailed(page, "solve_offer");
  await page.locator('[data-role="solve-submit"]').click();
  const fields = await fail;
  if (!String(fields.message ?? "").includes("witness does not satisfy")) {
    throw new Error(`E3: expected 'witness does not satisfy', got ${fields.message}`);
  }
  const formErr = await getFormError(page, "solve-error");
  if (!formErr.includes("witness does not satisfy")) {
    throw new Error(`E3: expected form-level solve-error, got "${formErr}"`);
  }
  const liveOffers = (await readResources(page)).filter((r) => r.kindFamily === "offer");
  assertEquals("E3.offer_still_live", 1, liveOffers.length);
}

async function scenarioE4_cancelByNonCreator(page) {
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  await mintResource(page, { kind: ETH, amount: 10, owner: "alice" });

  const aliceEth = (await readResources(page)).find(
    (r) => r.kind === ETH && r.owner === "alice",
  ).uid;
  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("10");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  const offerUid = (await readResources(page)).find((r) => r.kindFamily === "offer").uid;

  await setIdentity(page, "bob");
  await clickTab(page, "cancel_offer");
  await page.locator('[data-role="cancel-offer-select"]').selectOption(offerUid);
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="cancel-fee-resource"]').selectOption(bobFee);

  const fail = waitSubmitFailed(page, "cancel_offer");
  await page.locator('[data-role="cancel-submit"]').click();
  const fields = await fail;
  if (!String(fields.message ?? "").includes("only the creator")) {
    throw new Error(`E4: expected 'only the creator', got ${fields.message}`);
  }
  const formErr = await getFormError(page, "cancel-error");
  if (!formErr.includes("only the creator")) {
    throw new Error(`E4: expected form-level cancel-error, got "${formErr}"`);
  }
  const liveOffers = (await readResources(page)).filter((r) => r.kindFamily === "offer");
  assertEquals("E4.offer_still_live", 1, liveOffers.length);
}

async function scenarioE5_solveNoOfferSelected(page) {
  await setIdentity(page, "alice");
  await mintResource(page, { kind: USDC, amount: 5, owner: "alice" });
  await mintResource(page, { kind: USDC, amount: 5, owner: "bob" });
  await mintResource(page, { kind: ETH, amount: 10, owner: "alice" });

  const aliceEth = (await readResources(page)).find(
    (r) => r.kind === ETH && r.owner === "alice",
  ).uid;
  const aliceFee = await findUsdcUid(page, "alice", 1);
  await clickTab(page, "create_offer");
  await selectResources(page, [aliceEth]);
  await page.locator('[data-role="offer-locked-amount"]').fill("10");
  await page.locator('[data-role="offer-refund-amount"]').fill("0");
  await page.locator('[data-role="offer-challenge"]').selectOption("x_plus_1_eq_2");
  await page.locator('[data-role="offer-fee-resource"]').selectOption(aliceFee);
  const create = waitActionDone(page, "create_offer");
  await page.locator('[data-role="offer-create-submit"]').click();
  await create;
  await waitVizDone(page, "create_offer");

  await setIdentity(page, "bob");
  await clickTab(page, "solve_offer");
  // Do NOT select an offer.
  const bobFee = await findUsdcUid(page, "bob", 1);
  await page.locator('[data-role="solve-fee-resource"]').selectOption(bobFee);

  const fail = waitSubmitFailed(page, "solve_offer");
  await page.locator('[data-role="solve-submit"]').click();
  const fields = await fail;
  if (
    !String(fields.message ?? "")
      .toLowerCase()
      .includes("offer")
  ) {
    throw new Error(`E5: expected message mentioning 'offer', got ${fields.message}`);
  }
  const inlineErr = await getFieldErrorNear(page, "solve-offer-select");
  if (!inlineErr.toLowerCase().includes("offer")) {
    throw new Error(`E5: expected inline error near offer select, got "${inlineErr}"`);
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────

const SCENARIOS = [
  ["H1 · mint + transfer (single-kind)", scenarioH1_mintTransferSingleKind],
  ["H2 · mint + transfer (multi-kind)", scenarioH2_mintTransferMultiKind],
  ["H3 · create + solve (trivial challenge)", scenarioH3_createSolveTrivialChallenge],
  ["H4 · create + solve (with refund)", scenarioH4_createSolveWithRefund],
  ["H5 · create + cancel", scenarioH5_createCancel],
  ["H6 · multi-input transfer", scenarioH6_multiInputTransfer],
  ["H7 · create + solve (parametrized sum_eq_n)", scenarioH7_createSolveSumEqN],
  ["E1 · transfer with no fee selected", scenarioE1_transferNoFee],
  ["E2 · transfer with no inputs selected", scenarioE2_transferNoInputs],
  ["E3 · solve with wrong witness", scenarioE3_solveWrongWitness],
  ["E4 · cancel by non-creator", scenarioE4_cancelByNonCreator],
  ["E5 · solve with no offer selected", scenarioE5_solveNoOfferSelected],
];

try {
  for (const name of ["zktls_bg.wasm", "zkp_bg.wasm", "vault_bg.wasm"]) {
    const p = path.join(process.cwd(), "demo/assets/wasm", name);
    if (!fs.existsSync(p)) {
      throw new Error(`missing ${p}. Build the wasm first — see README.md`);
    }
  }

  await startDemoBinary();

  console.log(tag("launching headed Chromium..."));
  const browser = await launchHeadedChromium();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const browserCapture = setupBrowserCapture(page);
  await installPageErrorForwarder(page);

  console.log(tag(`navigating to /vault?pool=${POOL} ...`));
  await page.goto(`https://${SERVICE_ADDR}/vault?pool=${POOL}`, { waitUntil: "load" });
  await waitForEvent({
    page,
    event: "vault.scheduler.booted",
    timeoutMs: 60_000,
    label: "vault.scheduler.booted",
  });
  console.log(tag("scheduler booted."));

  const scenarioResults = [];
  for (const [name, fn] of SCENARIOS) {
    await resetVault(page);
    console.log(tag(`scenario: ${name}`));
    const t0 = Date.now();
    await fn(page);
    scenarioResults.push({ name, ms: Date.now() - t0 });
    console.log(tag(`  pass (${scenarioResults.at(-1).ms}ms)`));
  }

  // ─── Cross-cutting assertions over the entire run ────────────────────────

  const proveDone = browserCapture.console.findEvents({ event: "vault.air.prove.done" });
  for (const e of proveDone) {
    assertInRange(
      `prove_ms[${e.fields.air}#${e.fields.action_id}-${e.fields.leaf_index}]`,
      e.fields.prove_ms,
      PROVE_MS_MIN,
      PROVE_MS_MAX,
    );
    assertInRange(
      `size_bytes[${e.fields.air}#${e.fields.action_id}-${e.fields.leaf_index}]`,
      e.fields.size_bytes,
      PROOF_SIZE_MIN,
      PROOF_SIZE_MAX,
    );
  }
  if (proveDone.length < 20) {
    throw new Error(`expected ≥ 20 vault.air.prove.done events; got ${proveDone.length}`);
  }

  const submitFailures = browserCapture.console.countEvent({
    event: "vault.action.submit.failed",
  });
  if (submitFailures !== 5) {
    throw new Error(`expected 5 submit failures (one per E-scenario), got ${submitFailures}`);
  }

  const resets = browserCapture.console.countEvent({ event: "vault.reset" });
  if (resets !== SCENARIOS.length) {
    throw new Error(`expected ${SCENARIOS.length} reset events, got ${resets}`);
  }

  const doneActions = browserCapture.console.countEvent({ event: "vault.action.done" });
  if (doneActions < 14) {
    throw new Error(`expected ≥ 14 successful actions, got ${doneActions}`);
  }

  browserCapture.expectNoRequestFailures();

  console.log(
    JSON.stringify(
      {
        pass: true,
        pool: POOL,
        scenarios: scenarioResults.length,
        actions_completed: doneActions,
        submit_failures: submitFailures,
        prove_done_events: proveDone.length,
        per_scenario_ms: scenarioResults,
      },
      null,
      2,
    ),
  );
  process.exit(0);
} catch (err) {
  console.error(`\x1b[31m[vault-e2e] FAIL\x1b[0m: ${err.message}`);
  if (err.stack) console.error(err.stack);
  process.exit(1);
} finally {
  await runCleanup();
}
