#!/usr/bin/env node
// E2E: drive /zkp in headed Chromium and assert against the structured event
// stream emitted by both the WASM prover (via web_sys::console) and the JS
// page (via demo/assets/log.mjs). All assertions are structural — no magic
// prefixes; the harness parses the shared `{ts} LEVEL event_name k=v`
// grammar via parseEventLine.

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

const STEPS = Number(process.env.ZKP_E2E_STEPS ?? "3");
const STEP_TIMEOUT_MS = Number(process.env.ZKP_E2E_STEP_TIMEOUT_MS ?? "180000");
const PROOF_SIZE_MIN_BYTES = 5_000;
const PROOF_SIZE_MAX_BYTES = 1_000_000;
const STEP_TIME_MAX_MS = 600_000;
// `demo.ledger.connection.error error=tls handshake eof` is Chrome's TCP probe.
const ALLOWED_BACKEND_ERROR_PATTERN = /demo\.ledger\.connection\.error.*tls handshake eof/;

const proofDone = (page, predicate, label) =>
  waitForEvent({
    page,
    event: "zkp.proof.done",
    errorEvents: ["zkp.proof.failed", "runtime.page.error"],
    predicate,
    label,
    timeoutMs: STEP_TIMEOUT_MS,
  });

try {
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
    event: "zkp.worker.ready",
    timeoutMs: 30_000,
    label: "zkp.worker.ready",
  });
  console.log("[harness] worker ready, starting recursion...");

  // ─── Base proof ────────────────────────────────────────────────────────
  console.log('[harness] clicking "Generate base proof"...');
  const baseDone = proofDone(page, (f) => f.kind === "base", "zkp.proof.done kind=base");
  await page.locator('[data-role="base"]').click();
  const base = await baseDone;
  assertEquals("base.counter", 0, base.counter);
  assertEquals("base.steps_proven", 1, base.steps_proven);
  assertEquals("base.verified", true, base.verified);
  assertInRange(
    "base.proof_size_bytes",
    base.proof_size_bytes,
    PROOF_SIZE_MIN_BYTES,
    PROOF_SIZE_MAX_BYTES,
  );
  assertInRange("base.prove_ms", base.prove_ms, 0, STEP_TIME_MAX_MS);
  assertInRange("base.verify_ms", base.verify_ms, 0, STEP_TIME_MAX_MS);
  console.log(
    `[harness] ✓ base counter=0 prove_ms=${base.prove_ms} verify_ms=${base.verify_ms} size=${base.proof_size_bytes}`,
  );

  // ─── Inductive steps ──────────────────────────────────────────────────
  const stepResults = [];
  for (let i = 1; i <= STEPS; i++) {
    const stepDone = proofDone(
      page,
      (f) => f.kind === "step" && f.counter === i,
      `zkp.proof.done kind=step counter=${i}`,
    );
    console.log(`[harness] clicking "Increment" then "Prove" for step ${i - 1}→${i}...`);
    await page.locator('[data-role="increment"]').click();
    await page.locator('[data-role="prove"]').click();
    const step = await stepDone;
    assertEquals(`step${i}.counter`, i, step.counter);
    assertEquals(`step${i}.prev_counter`, i - 1, step.prev_counter);
    assertEquals(`step${i}.steps_proven`, i + 1, step.steps_proven);
    assertEquals(`step${i}.verified`, true, step.verified);
    assertInRange(
      `step${i}.proof_size_bytes`,
      step.proof_size_bytes,
      PROOF_SIZE_MIN_BYTES,
      PROOF_SIZE_MAX_BYTES,
    );
    assertInRange(`step${i}.prove_ms`, step.prove_ms, 0, STEP_TIME_MAX_MS);
    assertInRange(`step${i}.verify_ms`, step.verify_ms, 0, STEP_TIME_MAX_MS);
    stepResults.push(step);
    console.log(
      `[harness] ✓ step ${i - 1}→${i} prove_ms=${step.prove_ms} verify_ms=${step.verify_ms} size=${step.proof_size_bytes}`,
    );
  }

  // ─── Page state grid agrees with the result chain ─────────────────────
  const stateText = await page.locator('[data-role="state"]').textContent();
  if (!stateText.includes(String(STEPS))) {
    throw new Error(`page state did not reach ${STEPS}: ${stateText}`);
  }

  // ─── Uniform recursion check (informational) ──────────────────────────
  if (stepResults.length >= 3) {
    const tail = stepResults.slice(1).map((r) => r.prove_ms);
    const mean = tail.reduce((a, b) => a + b, 0) / tail.length;
    const max = Math.max(...tail);
    const min = Math.min(...tail);
    if (max > mean * 1.5 || min < mean * 0.5) {
      console.warn(
        `[harness] ⚠️ steps 2+ prove time variance is unexpectedly wide: min=${min} mean=${mean.toFixed(0)} max=${max}`,
      );
    } else {
      console.log(
        `[harness] uniform-recursion check ok (steps 2+: min=${min} mean=${mean.toFixed(0)} max=${max})`,
      );
    }
  }

  // ─── Backend tracing assertions ─────────────────────────────────────────
  // zkp runs entirely in the browser; the backend just serves static assets
  // and the page itself, so we only assert the service is up and clean.
  backend.expectEventInOrder([{ event: "demo.service.listening" }]);
  // No MPC-TLS path on this flow.
  backend.expectEventAbsent({ event: "zktls.notarize.transcript.received" });
  // Backend errors: only the harmless Chrome TCP-probe handshake EOF.
  for (const item of backend.items) {
    if (!/ ERROR /.test(item.text)) continue;
    if (ALLOWED_BACKEND_ERROR_PATTERN.test(item.text)) continue;
    throw new Error(`unexpected backend ERROR line: ${item.text}`);
  }

  // ─── Browser console assertions ─────────────────────────────────────────
  // Page boot + base proof — structural events emitted by both the WASM
  // prover (zkp.prove.*) and the JS layer (zkp.action.*, zkp.proof.done).
  browserCapture.console.expectEventInOrder([
    { event: "zkp.page.loading" },
    { event: "zkp.worker.ready" },
    { event: "zkp.action.prove_base.click" },
    { event: "zkp.prove.base.start" },
    { event: "zkp.prove.base.done" },
    { event: "zkp.verify.done" },
    { event: "zkp.proof.done", fields: { kind: "base" } },
  ]);
  for (let i = 1; i <= STEPS; i++) {
    browserCapture.console.expectEventInOrder([
      { event: "zkp.action.increment.click", fields: { pending: i } },
      { event: "zkp.action.prove_step.click", fields: { prev_counter: i - 1, counter: i } },
      { event: "zkp.prove.step.start", fields: { prev_counter: i - 1 } },
      { event: "zkp.prove.step.done", fields: { prev_counter: i - 1, counter: i } },
      { event: "zkp.verify.done" },
      { event: "zkp.proof.done", fields: { kind: "step", counter: i } },
    ]);
  }
  browserCapture.console.expectEventCount({ event: "zkp.proof.done", fields: { kind: "base" } }, 1);
  browserCapture.console.expectEventCount(
    { event: "zkp.proof.done", fields: { kind: "step" } },
    STEPS,
  );
  browserCapture.console.expectEventCount({ event: "zkp.proof.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "runtime.page.error" }, 0);
  for (const item of browserCapture.console.items) {
    if (item.type === "pageerror") {
      throw new Error(`unexpected page error: ${item.text}`);
    }
  }
  browserCapture.expectNoRequestFailures();

  // ─── Final summary ─────────────────────────────────────────────────────
  const summary = {
    flow: "zkp-recursive-counter",
    final_counter: STEPS,
    base_prove_ms: base.prove_ms,
    base_verify_ms: base.verify_ms,
    base_size_bytes: base.proof_size_bytes,
    step_count: STEPS,
    step_prove_ms: stepResults.map((r) => r.prove_ms),
    step_verify_ms: stepResults.map((r) => r.verify_ms),
    step_size_bytes: stepResults.map((r) => r.proof_size_bytes),
  };
  console.log("\nzkp recursive flow: PASS");
  console.log(JSON.stringify(summary, null, 2));
  await runCleanup();
  process.exit(0);
} catch (error) {
  console.error(`\nzkp recursive flow: FAIL — ${error.message}`);
  await runCleanup();
  process.exit(1);
}
