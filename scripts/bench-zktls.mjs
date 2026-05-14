#!/usr/bin/env node
// Benchmark: measure zktls E2E flow timing + network data sizes.
//
// Usage:
//   node scripts/bench-zktls.mjs
//
// Spawns a single zktlsn binary, drives the flow once through Playwright,
// and captures timing from console events + Network tab sizes.

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

const SERVER_PORT = 8543;
const SERVICE_PORT = 8643;
const SERVICE_ADDR = `127.0.0.1:${SERVICE_PORT}`;
const NOTARIZE_TIMEOUT_MS = 120_000;
const BINARY_READY_TIMEOUT_MS = 20_000;

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

async function captureEvents(page) {
  const events = [];
  page.on("console", (msg) => {
    const text = msg.text();
    // Match: YYYY-MM-DDTHH:MM:SS.sssZ  LEVEL event_name [fields]
    const match = text.match(
      /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+(INFO|WARN|ERROR)\s+([a-z0-9._]+)(.*)/,
    );
    if (match) {
      const [, ts, level, event_name, fields_str] = match;
      const fields = {};
      if (fields_str.trim()) {
        const fieldMatches = fields_str.matchAll(/\s+([a-z_]+)=([^\s]+)/g);
        for (const [, key, val] of fieldMatches) {
          try {
            fields[key] = JSON.parse(val);
          } catch {
            fields[key] = val;
          }
        }
      }
      events.push({ ts, level, event_name, fields });
    }
  });
  
  return events;
}

async function collectResourceTransfer(page) {
  return await page.evaluate(() => {
    const entries = performance.getEntriesByType("resource");
    const navigation = performance.getEntriesByType("navigation")[0] ?? null;
    const resources = entries.map((entry) => ({
      name: entry.name,
      initiatorType: entry.initiatorType,
      transferSize: entry.transferSize ?? 0,
      encodedBodySize: entry.encodedBodySize ?? 0,
      decodedBodySize: entry.decodedBodySize ?? 0,
    }));
    const resourceTransferBytes = resources.reduce((sum, entry) => sum + entry.transferSize, 0);
    const navigationTransferBytes = navigation?.transferSize ?? 0;
    const byInitiatorType = resources.reduce((acc, entry) => {
      const key = entry.initiatorType || "other";
      acc[key] = (acc[key] ?? 0) + entry.transferSize;
      return acc;
    }, {});
    return {
      navigation: navigation
        ? {
            name: navigation.name,
            transferSize: navigation.transferSize ?? 0,
            encodedBodySize: navigation.encodedBodySize ?? 0,
            decodedBodySize: navigation.decodedBodySize ?? 0,
          }
        : null,
      resources,
      resourceTransferBytes,
      navigationTransferBytes,
      totalHttpTransferBytes: resourceTransferBytes + navigationTransferBytes,
      byInitiatorType,
    };
  });
}

function analyzeEvents(events) {
  if (events.length === 0) {
    return { error: "No events captured" };
  }

  const parseTs = (ts) => new Date(ts).getTime();
  const t0 = parseTs(events[0].ts);
  const tEnd = parseTs(events[events.length - 1].ts);
  const totalMs = tEnd - t0;

  // Extract key stages
  const stageMap = {};
  const stages = [
    ["zktls.action.start.click", "zktls.worker.wasm.init.done", "wasm_init"],
    ["zktls.worker.pool.start", "zktls.worker.pool.ready", "worker_pool"],
    ["zktls.poseidon.circuits.load.start", "zktls.poseidon.circuits.load.done", "circuits"],
    ["zktls.transport.session.opening", "zktls.transport.session.ready", "webtransport_session"],
    ["zktls.transport.streams.creating", "zktls.transport.streams.preambles_written", "streams"],
    ["zktls.prover.prove_streams.start", "zktls.prover.prove_streams.done", "prover_prove"],
  ];

  for (const [start_name, end_name, label] of stages) {
    const startEv = events.find((e) => e.event_name === start_name);
    const endEv = events.find((e) => e.event_name === end_name);
    if (startEv && endEv) {
      const ms = parseTs(endEv.ts) - parseTs(startEv.ts);
      stageMap[label] = { ms, bytes: endEv.fields?.bytes ?? null };
    }
  }

  // Extract data sizes
  const circuitsEv = events.find((e) => e.event_name === "zktls.poseidon.circuits.load.done");
  const proverViewReq = events.find(
    (e) => e.event_name === "zktls.prover.view" && e.fields?.direction === "request",
  );
  const proverViewResp = events.find(
    (e) => e.event_name === "zktls.prover.view" && e.fields?.direction === "response",
  );

  const dataSizes = {
    circuits_bytes: circuitsEv?.fields?.bytes ?? 0,
    request_bytes: proverViewReq?.fields?.bytes ?? 0,
    response_bytes: proverViewResp?.fields?.bytes ?? 0,
  };

  return {
    total_ms: totalMs,
    stages: stageMap,
    data_sizes: dataSizes,
    event_count: events.length,
  };
}

async function runBench(chromium) {
  let proc = null;
  let browser = null;
  let resourceStats = null;

  try {
    console.log("[bench] spawning zktlsn binary...");
    proc = spawnCargoBinary({
      bin: "zktlsn",
      env: {
        ...sharedDemoEnv,
        ZKTLSN_SERVER_LISTEN_ADDR: `127.0.0.1:${SERVER_PORT}`,
        ZKTLSN_SERVER_ADDR: `127.0.0.1:${SERVER_PORT}`,
        ZKTLSN_SERVICE_LISTEN_ADDR: SERVICE_ADDR,
      },
      label: "bench",
      color: "36",
    });

    console.log("[bench] waiting for server ready...");
    await waitForTcp("127.0.0.1", SERVER_PORT, BINARY_READY_TIMEOUT_MS);
    await waitForTcp("127.0.0.1", SERVICE_PORT, BINARY_READY_TIMEOUT_MS);

    console.log("[bench] launching Chromium...");
    browser = await chromium.launch({
      headless: true,
      args: ["--ignore-certificate-errors", "--enable-features=WebTransport,SharedArrayBuffer"],
    });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    
    const events = await captureEvents(page);
    await installPageErrorForwarder(page);

    console.log(`[bench] navigating to https://${SERVICE_ADDR}/zktls...`);
    await page.goto(`https://${SERVICE_ADDR}/zktls`, { waitUntil: "load" });
    
    console.log("[bench] clicking 'Start attestation'...");
    await page.locator('[data-role="start"]').click();

    const resultPromise = waitForEvent({
      page,
      event: "zktls.notarize.done",
      errorEvents: ["zktls.notarize.failed", "runtime.page.error"],
      timeoutMs: NOTARIZE_TIMEOUT_MS,
      label: "zktls.notarize.done",
    });
    resultPromise.catch(() => {});

    console.log("[bench] waiting for notarization to complete...");
    await resultPromise;

    resourceStats = await collectResourceTransfer(page);

    return { ok: true, events, resourceStats };
  } catch (err) {
    return { ok: false, error: err.message };
  } finally {
    if (browser) try { await browser.close(); } catch {}
    if (proc) {
      proc.kill();
      await Promise.race([proc.result, sleep(2_000)]);
    }
  }
}

// ─── main ──────────────────────────────────────────────────────────────────

const wasmPath = path.join(process.cwd(), "demo/assets/wasm/zktls_bg.wasm");
if (!fs.existsSync(wasmPath)) {
  console.error(`[bench] missing ${wasmPath} — build the WASM first (see README.md)`);
  process.exit(1);
}

const mod = await loadPlaywright();
const chromium = mod.chromium ?? mod.default?.chromium;
if (!chromium) {
  console.error("[bench] failed to resolve playwright.chromium");
  process.exit(1);
}

console.log("[bench] starting zktls benchmark...\n");

const { ok, events, resourceStats, error } = await runBench(chromium);

if (!ok) {
  console.error(`\n[bench] FAILED: ${error}`);
  process.exit(1);
}

const analysis = analyzeEvents(events);

console.log("\n[bench] ══════════════════════════════════════════════════════════");
console.log(`[bench] Total time: ${analysis.total_ms}ms\n`);

console.log("[bench] Stage breakdown:");
for (const [stage, { ms, bytes }] of Object.entries(analysis.stages)) {
  const bytesSuffix = bytes !== null ? ` (${bytes} bytes)` : "";
  console.log(`[bench]   ${stage.padEnd(25)}: ${ms}ms${bytesSuffix}`);
}

console.log("\n[bench] Data sizes:");
for (const [name, bytes] of Object.entries(analysis.data_sizes)) {
  const mb = (bytes / 1e6).toFixed(1);
  console.log(`[bench]   ${name.padEnd(25)}: ${bytes} bytes (${mb}MB)`);
}

if (resourceStats) {
  console.log("\n[bench] HTTP resource transfer:");
  console.log(
    `[bench]   total_http_transfer_bytes  : ${resourceStats.totalHttpTransferBytes} bytes (${(resourceStats.totalHttpTransferBytes / 1e6).toFixed(1)}MB)`,
  );
  console.log(
    `[bench]   navigation_transfer_bytes  : ${resourceStats.navigationTransferBytes} bytes (${(resourceStats.navigationTransferBytes / 1e6).toFixed(1)}MB)`,
  );
  console.log(
    `[bench]   resource_transfer_bytes    : ${resourceStats.resourceTransferBytes} bytes (${(resourceStats.resourceTransferBytes / 1e6).toFixed(1)}MB)`,
  );

  console.log("\n[bench] HTTP transfer by initiatorType:");
  for (const [initiatorType, bytes] of Object.entries(resourceStats.byInitiatorType).sort(
    (a, b) => b[1] - a[1],
  )) {
    console.log(
      `[bench]   ${initiatorType.padEnd(18)}: ${bytes} bytes (${(bytes / 1e6).toFixed(1)}MB)`,
    );
  }

  const topResources = [...resourceStats.resources]
    .sort((a, b) => b.transferSize - a.transferSize)
    .slice(0, 10);
  console.log("\n[bench] Top network resources by transferSize:");
  for (const entry of topResources) {
    const shortName = entry.name.replace(/^https?:\/\/[^/]+/, "");
    console.log(
      `[bench]   ${entry.transferSize.toString().padEnd(10)} ${entry.initiatorType.padEnd(12)} ${shortName}`,
    );
  }
}

// Calculate total data transferred across the entire flow
const totalDataTransferred =
  (resourceStats?.totalHttpTransferBytes || 0) +
  (analysis.data_sizes.circuits_bytes || 0) +
  (analysis.data_sizes.request_bytes || 0) +
  (analysis.data_sizes.response_bytes || 0);

const httpMB = (resourceStats?.totalHttpTransferBytes || 0) / 1e6;
const circuitsMB = (analysis.data_sizes.circuits_bytes || 0) / 1e6;
const appMB = ((analysis.data_sizes.request_bytes || 0) + (analysis.data_sizes.response_bytes || 0)) / 1e6;
const totalMB = totalDataTransferred / 1e6;

console.log("\n[bench] ══════════════════════════════════════════════════════════");
console.log("[bench] Total data transferred (start to finish):");
console.log(`[bench]   HTTP assets           : ${(resourceStats?.totalHttpTransferBytes || 0).toLocaleString()} bytes (${httpMB.toFixed(1)}MB)`);
console.log(`[bench]   Circuit data (browser): ${(analysis.data_sizes.circuits_bytes || 0).toLocaleString()} bytes (${circuitsMB.toFixed(1)}MB)`);
console.log(`[bench]   Application protocol  : ${((analysis.data_sizes.request_bytes || 0) + (analysis.data_sizes.response_bytes || 0)).toLocaleString()} bytes (${appMB.toFixed(6)}MB)`);
console.log(`[bench]   ────────────────────────────────────────────────`);
console.log(`[bench]   TOTAL                 : ${totalDataTransferred.toLocaleString()} bytes (${totalMB.toFixed(1)}MB)`);

console.log("\n[bench] ══════════════════════════════════════════════════════════");
console.log("[bench] benchmark completed successfully");
process.exit(0);
