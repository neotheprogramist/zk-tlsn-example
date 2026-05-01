#!/usr/bin/env node
// E2E: drive /zkp in headed Chromium and assert everything we can observe —
// the per-step JSON results, the backend tracing output (limited; zkp runs
// entirely in the browser), and the browser DevTools Protocol console stream.

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
  waitForConsoleResult,
} from "./lib/harness.mjs";

const STEPS = Number(process.env.ZKP_E2E_STEPS ?? "3");
const STEP_TIMEOUT_MS = Number(process.env.ZKP_E2E_STEP_TIMEOUT_MS ?? "180000");
const PROOF_SIZE_MIN_BYTES = 5_000;
const PROOF_SIZE_MAX_BYTES = 500_000;
const STEP_TIME_MAX_MS = 600_000;
const ALLOWED_BACKEND_ERROR_PATTERN = /Connection error error=tls handshake eof/; // Chrome's TCP probe

const wait = (page, predicate, label) =>
  waitForConsoleResult({
    page,
    resultPrefix: "ZKP_RESULT",
    errorPrefix: "ZKP_ERROR",
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
  await installPageErrorForwarder(page, "ZKP_ERROR");

  console.log("[harness] navigating to /zkp...");
  await page.goto(`https://${SERVICE_ADDR}/zkp`, { waitUntil: "load" });
  await page.waitForFunction(
    () => document.querySelector('[data-role="status"]')?.textContent?.includes("ready"),
    null,
    { timeout: 30_000 },
  );
  console.log("[harness] worker ready, starting recursion...");

  // ─── Base proof ────────────────────────────────────────────────────────
  console.log('[harness] clicking "Generate base proof"...');
  const baseDone = wait(page, (r) => r.kind === "base", "base ZKP_RESULT");
  await page.locator('[data-role="base"]').click();
  const base = await baseDone;
  assertEquals("base.counter", 0, base.counter);
  assertEquals("base.steps_proven", 1, base.steps_proven);
  assertInRange(
    "base.proof_size_bytes",
    base.proof_size_bytes,
    PROOF_SIZE_MIN_BYTES,
    PROOF_SIZE_MAX_BYTES,
  );
  assertInRange("base.prove_ms", base.prove_ms, 0, STEP_TIME_MAX_MS);
  console.log(`[harness] ✓ base counter=0 prove_ms=${base.prove_ms} size=${base.proof_size_bytes}`);

  // ─── Inductive steps ──────────────────────────────────────────────────
  const stepResults = [];
  for (let i = 1; i <= STEPS; i++) {
    const stepDone = wait(page, (r) => r.kind === "step" && r.counter === i, `step ${i - 1}→${i}`);
    console.log(`[harness] clicking "Increment" then "Prove" for step ${i - 1}→${i}...`);
    await page.locator('[data-role="increment"]').click();
    await page.locator('[data-role="prove"]').click();
    const step = await stepDone;
    assertEquals(`step${i}.counter`, i, step.counter);
    assertEquals(`step${i}.prev_counter`, i - 1, step.prev_counter);
    assertEquals(`step${i}.steps_proven`, i + 1, step.steps_proven);
    assertInRange(
      `step${i}.proof_size_bytes`,
      step.proof_size_bytes,
      PROOF_SIZE_MIN_BYTES,
      PROOF_SIZE_MAX_BYTES,
    );
    assertInRange(`step${i}.prove_ms`, step.prove_ms, 0, STEP_TIME_MAX_MS);
    stepResults.push(step);
    console.log(
      `[harness] ✓ step ${i - 1}→${i} prove_ms=${step.prove_ms} size=${step.proof_size_bytes}`,
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
  backend.expectInOrder([
    [/service: listening on https:\/\//, "service listening"],
    [/listening \[HTTP\/3\.0\] on https:\/\/127\.0\.0\.1:8444/, "salvo HTTP/3"],
    [/listening \[HTTP\/1\.1\] on https:\/\/127\.0\.0\.1:8444/, "salvo HTTP/1.1"],
  ]);
  // No MPC-TLS path on this flow.
  backend.expectAbsent(/starting MPC-TLS/, "starting MPC-TLS (must not appear)");
  backend.expectAbsent(
    /Received notarization transcript/,
    "notarization transcript (must not appear)",
  );
  // Backend errors: only the harmless Chrome TCP-probe handshake EOF.
  for (const item of backend.items) {
    if (!/ ERROR /.test(item.text)) continue;
    if (ALLOWED_BACKEND_ERROR_PATTERN.test(item.text)) continue;
    throw new Error(`unexpected backend ERROR line: ${item.text}`);
  }

  // ─── Browser console assertions ─────────────────────────────────────────
  // Page boot + base proof.
  browserCapture.console.expectInOrder([
    [/loading wasm…/, "main: loading wasm"],
    [/worker ready \(wasm init/, "worker ready"],
    [/→ prove_base/, "main: prove_base click"],
    [/zkp: prove_base start/, "worker: prove_base start"],
    [/zkp: prove_base done ms=\d+ size=\d+/, "worker: prove_base done"],
    [/^ZKP_RESULT \{"kind":"base"/, "ZKP_RESULT base"],
  ]);
  // Per-step ordering: each step must increment from prev counter and emit a
  // matching ZKP_RESULT.
  for (let i = 1; i <= STEPS; i++) {
    browserCapture.console.expectInOrder([
      [new RegExp(`\\+ increment \\(pending ${i}\\)`), `main: increment to ${i}`],
      [new RegExp(`→ prove_step ${i - 1}→${i}`), `main: prove_step ${i - 1}→${i}`],
      [new RegExp(`zkp: prove_step from n=${i - 1} start`), `worker: prove_step from n=${i - 1}`],
      [
        new RegExp(`zkp: prove_step n=${i - 1}->${i} done ms=\\d+ size=\\d+`),
        `worker: prove_step n=${i - 1}->${i} done`,
      ],
      [
        new RegExp(`step ${i - 1}→${i} \\(verifies step-shape\\): prove .* size .* B`),
        `main: step ${i - 1}→${i} done`,
      ],
      [new RegExp(`^ZKP_RESULT \\{"kind":"step","counter":${i},`), `ZKP_RESULT step counter=${i}`],
    ]);
  }
  // Result counts + zero errors.
  browserCapture.console.expectCount(/^ZKP_RESULT \{"kind":"base"/, 1, "ZKP_RESULT base count");
  browserCapture.console.expectCount(/^ZKP_RESULT \{"kind":"step"/, STEPS, "ZKP_RESULT step count");
  browserCapture.console.expectCount(/^ZKP_ERROR /, 0, "ZKP_ERROR count");
  browserCapture.console.expectAbsent(/^ZKP_ERROR /, "ZKP_ERROR line");
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
    base_size_bytes: base.proof_size_bytes,
    step_count: STEPS,
    step_prove_ms: stepResults.map((r) => r.prove_ms),
    step_size_bytes: stepResults.map((r) => r.proof_size_bytes),
  };
  console.log("ZKP_E2E_RESULT " + JSON.stringify(summary));
  console.log("\nzkp recursive flow: PASS");
  console.log(JSON.stringify(summary, null, 2));
  await runCleanup();
  process.exit(0);
} catch (error) {
  console.error(`\nzkp recursive flow: FAIL — ${error.message}`);
  await runCleanup();
  process.exit(1);
}
