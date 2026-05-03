#!/usr/bin/env node
// E2E: drive /zkp in headed Chromium and assert against the structured event
// stream emitted by the WASM prover (via web_sys::console), the JS scheduler
// (`demo/assets/zkp.scheduler.mjs`), and the JS page (`demo/assets/log.mjs`).
// All assertions are structural — no magic prefixes; the harness parses the
// shared `{ts} LEVEL event_name k=v` grammar via parseEventLine.
//
// Architecture under test: N equivalent workers; any worker can prove leaves
// OR merges. Workers are stateless across jobs — proof bytes live on the
// main thread and are postMessage'd to whichever worker is idle. Independent
// merges (e.g. on disjoint subtrees) run in parallel across workers. The
// test forces pool size to 4 via `?pool=4` so the assertions are independent
// of the host's hardwareConcurrency.
//
// N=4 is the minimum that exercises the merge-of-merges recursion gate;
// override with ZKP_E2E_LEAVES.

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

const LEAVES = Number(process.env.ZKP_E2E_LEAVES ?? "4");
const POOL = Number(process.env.ZKP_E2E_POOL ?? "4");
const VERIFY_TIMEOUT_MS = Number(process.env.ZKP_E2E_VERIFY_TIMEOUT_MS ?? "300000");
const STEP_TIMEOUT_MS = Number(process.env.ZKP_E2E_STEP_TIMEOUT_MS ?? "60000");
const PROOF_SIZE_MIN_BYTES = 5_000;
const PROOF_SIZE_MAX_BYTES = 1_500_000;
const PROVE_MS_MAX = 600_000;
const ALLOWED_BACKEND_ERROR_PATTERN = /demo\.ledger\.connection\.error.*tls handshake eof/;

try {
  if (!Number.isInteger(LEAVES) || LEAVES < 2) {
    throw new Error(`ZKP_E2E_LEAVES must be an integer ≥ 2 (got ${LEAVES})`);
  }
  if (!Number.isInteger(POOL) || POOL < 1) {
    throw new Error(`ZKP_E2E_POOL must be an integer ≥ 1 (got ${POOL})`);
  }

  for (const name of ["zktls_bg.wasm", "zkp_bg.wasm"]) {
    const p = path.join(process.cwd(), "demo/assets/wasm", name);
    if (!fs.existsSync(p)) throw new Error(`missing ${p}. Build the wasm first — see README.md`);
  }

  const { log: backend } = await startDemoBinary();

  console.log("[harness] launching headed Chromium via Playwright...");
  const browser = await launchHeadedChromium();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const browserCapture = setupBrowserCapture(page);
  await installPageErrorForwarder(page);

  console.log(`[harness] navigating to /zkp?pool=${POOL} ...`);
  await page.goto(`https://${SERVICE_ADDR}/zkp?pool=${POOL}`, { waitUntil: "load" });
  await waitForEvent({
    page,
    event: "zkp.scheduler.booted",
    timeoutMs: 30_000,
    label: "zkp.scheduler.booted",
  });
  console.log(`[harness] scheduler booted, queueing ${LEAVES} leaves...`);

  // ─── Click Next N times rapidly (non-blocking) ─────────────────────────
  // Set up leaf-proved waiters BEFORE any click so we don't miss events
  // for fast leaves. With N parallel workers, leaves can prove in any
  // order; we assert on shape, not order.
  const leafProvedWaits = [];
  for (let i = 0; i < LEAVES; i++) {
    leafProvedWaits.push(
      waitForEvent({
        page,
        event: "zkp.scheduler.leaf.proved",
        predicate: (f) => f.node_id === i,
        errorEvents: ["zkp.scheduler.job.failed", "runtime.page.error", "zkp.verify.failed"],
        timeoutMs: STEP_TIMEOUT_MS * LEAVES,
        label: `zkp.scheduler.leaf.proved node_id=${i}`,
      }),
    );
  }
  for (let i = 0; i < LEAVES; i++) {
    await page.locator('[data-role="next"]').click();
  }
  console.log("[harness] all Next clicks submitted; awaiting leaf proofs...");

  const leafResults = await Promise.all(leafProvedWaits);
  for (const f of leafResults) {
    assertEquals(`leaf.proved[${f.node_id}].node_id present`, true, Number.isInteger(f.node_id));
    assertInRange(`leaf.proved[node=${f.node_id}].prove_ms`, f.prove_ms, 0, PROVE_MS_MAX);
    assertInRange(
      `leaf.proved[node=${f.node_id}].size_bytes`,
      f.size_bytes,
      PROOF_SIZE_MIN_BYTES,
      PROOF_SIZE_MAX_BYTES,
    );
  }

  // ─── Click Verify, await the root ──────────────────────────────────────
  console.log("[harness] clicking Verify, awaiting root verification...");
  const verifiedWait = waitForEvent({
    page,
    event: "zkp.scheduler.verified",
    errorEvents: ["zkp.scheduler.job.failed", "runtime.page.error", "zkp.verify.failed"],
    timeoutMs: VERIFY_TIMEOUT_MS,
    label: "zkp.scheduler.verified",
  });
  await page.locator('[data-role="verify"]').click();
  const verified = await verifiedWait;
  assertEquals("verified.verified", true, verified.verified);
  assertEquals("verified.lo", 0, verified.lo);
  assertEquals("verified.hi", LEAVES - 1, verified.hi);
  assertEquals("verified.count", LEAVES, verified.count);
  console.log(
    `[harness] ✓ root verified: lo=${verified.lo} hi=${verified.hi} count=${verified.count}`,
  );

  // ─── Backend tracing assertions ────────────────────────────────────────
  // zkp runs entirely in the browser; backend just serves files.
  backend.expectEventInOrder([{ event: "demo.service.listening" }]);
  backend.expectEventAbsent({ event: "zktls.notarize.transcript.received" });
  for (const item of backend.items) {
    if (!/ ERROR /.test(item.text)) continue;
    if (ALLOWED_BACKEND_ERROR_PATTERN.test(item.text)) continue;
    throw new Error(`unexpected backend ERROR line: ${item.text}`);
  }

  // ─── Browser console assertions ────────────────────────────────────────
  // Page boot + scheduler booted + N leaf clicks + N leaf.proved + N-1
  // merge.proved + 1 verified. Failures count must be zero.
  browserCapture.console.expectEventInOrder([
    { event: "zkp.page.loading" },
    { event: "zkp.scheduler.ready" },
    { event: "zkp.scheduler.booted" },
    { event: "zkp.action.next.click" },
    { event: "zkp.scheduler.leaf.queued", fields: { index: 0 } },
  ]);
  browserCapture.console.expectEventCount({ event: "zkp.action.next.click" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.leaf.queued" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.leaf.proved" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.merge.proved" }, LEAVES - 1);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.verified" }, 1);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.job.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "zkp.verify.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "runtime.page.error" }, 0);
  for (const item of browserCapture.console.items) {
    if (item.type === "pageerror") {
      throw new Error(`unexpected page error: ${item.text}`);
    }
  }
  browserCapture.expectNoRequestFailures();

  // ─── Per-merge ordering: each merge.proved arrives after both children
  // are proved (leaves) or merged. Merge can only run once both children's
  // proofs are on the merge's target worker, but the *proof* must exist
  // before that, so leaf.proved / merge.proved precedence is the right
  // ordering invariant.
  const mergeEvents = browserCapture.console.findEvents({
    event: "zkp.scheduler.merge.proved",
  });
  const proofReadyAt = new Map(); // node_id -> position when proved
  let pos = 0;
  for (const item of browserCapture.console.items) {
    const e = item._parsed;
    if (!e) continue;
    if (e.event === "zkp.scheduler.leaf.proved" || e.event === "zkp.scheduler.merge.proved") {
      proofReadyAt.set(e.fields.node_id, pos);
    }
    pos++;
  }
  for (const m of mergeEvents) {
    const here = proofReadyAt.get(m.fields.node_id);
    const left = proofReadyAt.get(m.fields.left_id);
    const right = proofReadyAt.get(m.fields.right_id);
    if (left == null || right == null || here == null) {
      throw new Error(
        `merge ${m.fields.node_id} missing position(s): left=${left} right=${right} here=${here}`,
      );
    }
    if (left >= here || right >= here) {
      throw new Error(
        `merge ${m.fields.node_id} reported done before its children left=${m.fields.left_id}@${left} right=${m.fields.right_id}@${right} here=${here}`,
      );
    }
  }

  // ─── Parallelism: leaves prove on multiple workers ─────────────────────
  const leafSlotsUsed = new Set();
  for (const e of browserCapture.console.findEvents({ event: "zkp.scheduler.leaf.proved" })) {
    if (Number.isInteger(e.fields.worker_slot)) leafSlotsUsed.add(e.fields.worker_slot);
  }
  const expectedMinLeafSlots = Math.min(LEAVES, POOL);
  if (leafSlotsUsed.size < expectedMinLeafSlots) {
    throw new Error(
      `expected ≥ ${expectedMinLeafSlots} distinct worker slots for leaf.proved, observed ${leafSlotsUsed.size} (slots: ${[...leafSlotsUsed].sort().join(",")})`,
    );
  }

  // ─── Parallelism: merges also distribute across workers (when there's
  // enough independent merge work). With LEAVES=4 and POOL≥2, the two
  // level-1 merges (merge(0,1) and merge(2,3)) are independent and SHOULD
  // run on different workers. Don't enforce when there's only 1 merge.
  const mergeSlotsUsed = new Set();
  for (const m of mergeEvents) {
    if (Number.isInteger(m.fields.worker_slot)) mergeSlotsUsed.add(m.fields.worker_slot);
  }
  // We expect at least 2 distinct merge worker slots when there are ≥ 2
  // independent merges and the pool has ≥ 2 workers. With LEAVES leaves,
  // there are LEAVES/2 (rounded down) independent level-1 merges.
  const independentMergesAtLeaf = Math.floor(LEAVES / 2);
  const expectedMinMergeSlots = Math.min(independentMergesAtLeaf, POOL, 2);
  if (POOL >= 2 && independentMergesAtLeaf >= 2 && mergeSlotsUsed.size < expectedMinMergeSlots) {
    throw new Error(
      `expected ≥ ${expectedMinMergeSlots} distinct worker slots for merge.proved, observed ${mergeSlotsUsed.size} (slots: ${[...mergeSlotsUsed].sort().join(",")})`,
    );
  }

  const leafProveEvents = browserCapture.console.findEvents({
    event: "zkp.scheduler.leaf.proved",
  });

  // ─── Final summary ─────────────────────────────────────────────────────
  const summary = {
    flow: "zkp-mmr-streaming-pcd",
    leaves: LEAVES,
    pool_size: POOL,
    distinct_leaf_slots_used: leafSlotsUsed.size,
    distinct_merge_slots_used: mergeSlotsUsed.size,
    leaf_prove_ms: leafProveEvents.map((e) => e.fields.prove_ms),
    leaf_size_bytes: leafProveEvents.map((e) => e.fields.size_bytes),
    merge_count: mergeEvents.length,
    merge_prove_ms: mergeEvents.map((m) => m.fields.prove_ms),
    merge_worker_slots: mergeEvents.map((m) => m.fields.worker_slot),
    root: { lo: verified.lo, hi: verified.hi, count: verified.count, verified: verified.verified },
  };
  console.log("\nzkp MMR streaming-PCD flow: PASS");
  console.log(JSON.stringify(summary, null, 2));
  await runCleanup();
  process.exit(0);
} catch (error) {
  console.error(`\nzkp MMR streaming-PCD flow: FAIL — ${error.message}`);
  await runCleanup();
  process.exit(1);
}
