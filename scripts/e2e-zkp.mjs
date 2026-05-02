#!/usr/bin/env node
// E2E: drive /zkp in headed Chromium and assert against the structured event
// stream emitted by the WASM prover (via web_sys::console), the JS scheduler
// (`demo/assets/zkp.scheduler.mjs`), and the JS page (`demo/assets/log.mjs`).
// All assertions are structural — no magic prefixes; the harness parses the
// shared `{ts} LEVEL event_name k=v` grammar via parseEventLine.
//
// v1 architecture: single-worker pool (K=1). The test clicks Next N times
// rapidly to verify queueing is non-blocking, then clicks Finish and asserts
// the root proves a contiguous range with verified=true. N=4 is the minimum
// that exercises the merge-of-merges recursion gate; override with
// ZKP_E2E_LEAVES.

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
const FINISH_TIMEOUT_MS = Number(process.env.ZKP_E2E_FINISH_TIMEOUT_MS ?? "300000");
const STEP_TIMEOUT_MS = Number(process.env.ZKP_E2E_STEP_TIMEOUT_MS ?? "60000");
const PROOF_SIZE_MIN_BYTES = 5_000;
const PROOF_SIZE_MAX_BYTES = 1_500_000;
const PROVE_MS_MAX = 600_000;
const ALLOWED_BACKEND_ERROR_PATTERN = /demo\.ledger\.connection\.error.*tls handshake eof/;

try {
  if (!Number.isInteger(LEAVES) || LEAVES < 2) {
    throw new Error(`ZKP_E2E_LEAVES must be an integer ≥ 2 (got ${LEAVES})`);
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

  console.log("[harness] navigating to /zkp...");
  await page.goto(`https://${SERVICE_ADDR}/zkp`, { waitUntil: "load" });
  await waitForEvent({
    page,
    event: "zkp.scheduler.booted",
    timeoutMs: 30_000,
    label: "zkp.scheduler.booted",
  });
  console.log(`[harness] scheduler booted, queueing ${LEAVES} leaves...`);

  // ─── Click Next N times rapidly (non-blocking) ─────────────────────────
  // Set up the leaf-proved waiter BEFORE any click so we don't miss events
  // for fast leaves (Promise.all over per-index waiters).
  const leafProvedWaits = [];
  for (let i = 0; i < LEAVES; i++) {
    leafProvedWaits.push(
      waitForEvent({
        page,
        event: "zkp.scheduler.leaf.proved",
        predicate: (f) => f.index === i,
        errorEvents: ["zkp.scheduler.job.failed", "runtime.page.error", "zkp.finish.failed"],
        timeoutMs: STEP_TIMEOUT_MS * LEAVES,
        label: `zkp.scheduler.leaf.proved index=${i}`,
      }),
    );
  }
  for (let i = 0; i < LEAVES; i++) {
    await page.locator('[data-role="next"]').click();
  }
  console.log("[harness] all Next clicks submitted; awaiting leaf proofs...");

  // Wait for ALL leaves to prove (in any order; FIFO + K=1 means they finish
  // in submission order, but the assertion is shape-only).
  const leafResults = await Promise.all(leafProvedWaits);
  for (const f of leafResults) {
    assertEquals(`leaf.proved[${f.index}].node_id present`, true, Number.isInteger(f.node_id));
    assertInRange(`leaf.proved[${f.index}].prove_ms`, f.prove_ms, 0, PROVE_MS_MAX);
    assertInRange(
      `leaf.proved[${f.index}].size_bytes`,
      f.size_bytes,
      PROOF_SIZE_MIN_BYTES,
      PROOF_SIZE_MAX_BYTES,
    );
  }

  // ─── Click Finish, await the root ──────────────────────────────────────
  console.log("[harness] clicking Finish, awaiting root verification...");
  const finishedWait = waitForEvent({
    page,
    event: "zkp.scheduler.finished",
    errorEvents: ["zkp.scheduler.job.failed", "runtime.page.error", "zkp.finish.failed"],
    timeoutMs: FINISH_TIMEOUT_MS,
    label: "zkp.scheduler.finished",
  });
  await page.locator('[data-role="finish"]').click();
  const finished = await finishedWait;
  assertEquals("finished.verified", true, finished.verified);
  assertEquals("finished.lo", 0, finished.lo);
  assertEquals("finished.hi", LEAVES - 1, finished.hi);
  assertEquals("finished.count", LEAVES, finished.count);
  console.log(
    `[harness] ✓ root verified: lo=${finished.lo} hi=${finished.hi} count=${finished.count}`,
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
  // merge.proved + 1 finished. Failures count must be zero.
  browserCapture.console.expectEventInOrder([
    { event: "zkp.page.loading" },
    { event: "zkp.scheduler.ready" },
    { event: "zkp.scheduler.booted" },
    { event: "zkp.action.next.click" },
    { event: "zkp.scheduler.leaf.queued", fields: { index: 0 } },
    { event: "zkp.scheduler.leaf.proved", fields: { index: 0 } },
  ]);
  browserCapture.console.expectEventCount({ event: "zkp.action.next.click" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.leaf.queued" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.leaf.proved" }, LEAVES);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.merge.proved" }, LEAVES - 1);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.finished" }, 1);
  browserCapture.console.expectEventCount({ event: "zkp.scheduler.job.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "zkp.finish.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "runtime.page.error" }, 0);
  for (const item of browserCapture.console.items) {
    if (item.type === "pageerror") {
      throw new Error(`unexpected page error: ${item.text}`);
    }
  }
  browserCapture.expectNoRequestFailures();

  // ─── Per-merge ordering: each merge.proved arrives after both child
  // *.proved events. Using event order in the browser console as ground truth.
  const mergeEvents = browserCapture.console.findEvents({
    event: "zkp.scheduler.merge.proved",
  });
  const provedTimestamps = new Map(); // node_id -> position
  let pos = 0;
  for (const item of browserCapture.console.items) {
    const e = item._parsed;
    if (!e) continue;
    if (e.event === "zkp.scheduler.leaf.proved" || e.event === "zkp.scheduler.merge.proved") {
      provedTimestamps.set(e.fields.node_id, pos);
    }
    pos++;
  }
  for (const m of mergeEvents) {
    const here = provedTimestamps.get(m.node_id);
    const left = provedTimestamps.get(m.left_id);
    const right = provedTimestamps.get(m.right_id);
    if (left == null || right == null || here == null) {
      throw new Error(
        `merge ${m.node_id} missing position(s): left=${left} right=${right} here=${here}`,
      );
    }
    if (left >= here || right >= here) {
      throw new Error(
        `merge ${m.node_id} reported done before its children left=${m.left_id}@${left} right=${m.right_id}@${right} here=${here}`,
      );
    }
  }

  // ─── Final summary ─────────────────────────────────────────────────────
  const summary = {
    flow: "zkp-mmr-streaming-pcd",
    leaves: LEAVES,
    pool_size: 1,
    leaf_prove_ms: leafResults.map((f) => f.prove_ms),
    leaf_size_bytes: leafResults.map((f) => f.size_bytes),
    merge_count: mergeEvents.length,
    merge_prove_ms: mergeEvents.map((m) => m.prove_ms),
    root: { lo: finished.lo, hi: finished.hi, count: finished.count, verified: finished.verified },
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
