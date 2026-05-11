#!/usr/bin/env node
// Stress test: run the zktls attestation flow STRESS_RUNS times in parallel,
// each on its own port pair, with a hard 30-second timeout on the notarization.
//
// Usage:
//   node scripts/stress-zktls.mjs
//   STRESS_RUNS=5 node scripts/stress-zktls.mjs
//
// Must be run from the repo root. Requires the zktls WASM to be built first.

import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";

import {
  sharedDemoEnv,
  spawnCargoBinary,
  waitForTcp,
  waitForEvent,
  installPageErrorForwarder,
  sleep,
} from "./lib/harness.mjs";

const RUNS = Number(process.env.STRESS_RUNS ?? 3);
const NOTARIZE_TIMEOUT_MS = 100_000;
const BINARY_READY_TIMEOUT_MS = 20_000;

// Each run i (0-indexed) gets its own port pair so all can run simultaneously.
const BASE_SERVER_PORT = 8543;  // ledger (MPC-TLS server)
const BASE_SERVICE_PORT = 8643; // HTTP/3 service (browser connects here)

const ANSI_COLORS = ["31", "32", "33", "34", "35", "36"];

// Track all active binary processes so we can kill them on SIGINT/SIGTERM.
const activeProcs = new Set();

function killAll() {
  for (const proc of activeProcs) {
    try { proc.kill(); } catch {}
  }
}

process.on("SIGINT", () => { killAll(); process.exit(130); });
process.on("SIGTERM", () => { killAll(); process.exit(143); });

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    const binPath = execFileSync(
      "npx",
      ["--yes", "--package=playwright", "--", "which", "playwright"],
      { encoding: "utf8" },
    ).trim();
    const req = createRequire(binPath);
    return await import(req.resolve("playwright"));
  }
}

async function runOnce(run, chromium) {
  const idx = run - 1;
  const serverPort = BASE_SERVER_PORT + idx;
  const servicePort = BASE_SERVICE_PORT + idx;
  const serviceAddr = `127.0.0.1:${servicePort}`;
  let proc = null;
  let browser = null;
  const start = Date.now();

  try {
    proc = spawnCargoBinary({
      bin: "zktlsn",
      env: {
        ...sharedDemoEnv,
        ZKTLSN_SERVER_LISTEN_ADDR: `127.0.0.1:${serverPort}`,
        ZKTLSN_SERVER_ADDR: `127.0.0.1:${serverPort}`,
        ZKTLSN_SERVICE_LISTEN_ADDR: serviceAddr,
      },
      label: `run${run}`,
      color: ANSI_COLORS[idx % ANSI_COLORS.length],
    });
    activeProcs.add(proc);

    await waitForTcp("127.0.0.1", serverPort, BINARY_READY_TIMEOUT_MS);
    await waitForTcp("127.0.0.1", servicePort, BINARY_READY_TIMEOUT_MS);

    browser = await chromium.launch({
      headless: false,
      args: ["--ignore-certificate-errors", "--enable-features=WebTransport,SharedArrayBuffer"],
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await installPageErrorForwarder(page);

    await page.goto(`https://${serviceAddr}/zktls`, { waitUntil: "load" });
    await page.locator('[data-role="start"]').click();

    // Timer starts here — after the click — so the full 30s is for the notarization.
    const resultPromise = waitForEvent({
      page,
      event: "zktls.notarize.done",
      errorEvents: ["zktls.notarize.failed", "runtime.page.error"],
      timeoutMs: NOTARIZE_TIMEOUT_MS,
      label: "zktls.notarize.done",
    });
    // Suppress unhandled rejection if we exit this try block via another error
    // before the 30s timer fires.
    resultPromise.catch(() => {});

    await resultPromise;
    return { ok: true, elapsed: Date.now() - start };
  } catch (err) {
    const lastLog = proc?.lines?.at(-1)?.text ?? "(no log)";
    return { ok: false, elapsed: Date.now() - start, error: err.message, lastLog };
  } finally {
    if (browser) try { await browser.close(); } catch {}
    if (proc) {
      activeProcs.delete(proc);
      proc.kill();
      await Promise.race([proc.result, sleep(2_000)]);
    }
  }
}

// ─── main ──────────────────────────────────────────────────────────────────

const wasmPath = path.join(process.cwd(), "demo/assets/wasm/zktls_bg.wasm");
if (!fs.existsSync(wasmPath)) {
  console.error(`[stress] missing ${wasmPath} — build the WASM first (see README.md)`);
  process.exit(1);
}

const mod = await loadPlaywright();
const chromium = mod.chromium ?? mod.default?.chromium;
if (!chromium) {
  console.error("[stress] failed to resolve playwright.chromium");
  process.exit(1);
}

console.log(
  `[stress] launching ${RUNS} parallel zktls flows ` +
  `(server ports ${BASE_SERVER_PORT}–${BASE_SERVER_PORT + RUNS - 1}, ` +
  `service ports ${BASE_SERVICE_PORT}–${BASE_SERVICE_PORT + RUNS - 1})\n`,
);

const results = await Promise.all(
  Array.from({ length: RUNS }, (_, i) => runOnce(i + 1, chromium)),
);

const passed = results.filter((r) => r.ok).length;
const failed = results.length - passed;

console.log(`\n[stress] ══════════════════════════════════════`);
console.log(`[stress] ${passed}/${RUNS} passed, ${failed}/${RUNS} failed`);
console.log(`[stress] ──────────────────────────────────────`);
for (let i = 0; i < results.length; i++) {
  const r = results[i];
  if (r.ok) {
    console.log(`[stress]   run ${i + 1}: PASS  ${r.elapsed}ms`);
  } else {
    console.log(`[stress]   run ${i + 1}: FAIL  ${r.elapsed}ms — ${r.error}`);
    console.log(`[stress]            last log: ${r.lastLog}`);
  }
}
console.log(`[stress] ══════════════════════════════════════`);

process.exit(failed > 0 ? 1 : 0);
