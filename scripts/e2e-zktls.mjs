#!/usr/bin/env node
// E2E: drive /zktls in headed Chromium and assert against the structured
// event stream emitted by both the WASM prover (via web_sys::console) and
// the JS page (via demo/assets/log.mjs). All assertions are structural —
// no magic prefixes; the harness parses the shared
// `{ts} LEVEL event_name k=v` grammar via parseEventLine.

import fs from "node:fs";
import path from "node:path";

import {
  SERVER_NAME,
  SERVICE_ADDR,
  TO_USER,
  TRANSFER_AMOUNT,
  assertEquals,
  installPageErrorForwarder,
  launchHeadedChromium,
  runCleanup,
  setupBrowserCapture,
  startDemoBinary,
  waitForEvent,
} from "./lib/harness.mjs";

const EXPECTED_COMMITMENT_COUNT = 2;
const EXPECTED_REQUEST_BYTES = 87; // GET /api/attestations/1 + content-type header
const EXPECTED_RESPONSE_BYTES = 312; // HTTP 200 + JSON body for tx_id=1, alice→treasury, amount=25
const EXPECTED_ATTESTATION_HASH_HASHES = 32; // ATTESTATION_LEN — see zktls::FiatTransferAttestation
// `demo.ledger.connection.error error=tls handshake eof` is Chrome's TCP probe.
const ALLOWED_BACKEND_ERROR_PATTERN = /demo\.ledger\.connection\.error.*tls handshake eof/;

try {
  const wasmPath = path.join(process.cwd(), "demo/assets/wasm/zktls_bg.wasm");
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`missing ${wasmPath}. Build the wasm first — see README.md`);
  }

  const { log: backend } = await startDemoBinary();

  console.log("[harness] launching headed Chromium via Playwright...");
  const browser = await launchHeadedChromium();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const browserCapture = setupBrowserCapture(page);
  await installPageErrorForwarder(page);

  const resultPromise = waitForEvent({
    page,
    event: "zktls.notarize.done",
    errorEvents: ["zktls.notarize.failed", "runtime.page.error"],
    label: "zktls.notarize.done",
  });

  console.log("[harness] navigating to /zktls...");
  await page.goto(`https://${SERVICE_ADDR}/zktls`, { waitUntil: "load" });
  console.log('[harness] clicking "Start attestation"...');
  await page.locator('[data-role="start"]').click();

  console.log("[harness] prover running, awaiting zktls.notarize.done (may take 20–60s)...");
  const result = await resultPromise;

  // ─── Result-event assertions ────────────────────────────────────────────
  assertEquals("flow", "notarize-wasm", result.flow);
  assertEquals("server_name", SERVER_NAME, result.server_name);
  assertEquals("to_username", TO_USER, result.to_username);
  assertEquals("amount", TRANSFER_AMOUNT, result.amount);
  assertEquals("eligible_for_mint", true, result.eligible_for_mint);
  assertEquals("commitment_count", EXPECTED_COMMITMENT_COUNT, result.commitment_count);

  // ─── Backend tracing assertions ─────────────────────────────────────────
  // Service + ledger boot.
  backend.expectEventInOrder([
    {
      event: "demo.transfer.seeded",
      fields: { tx_id: 1, from: "alice", to: "treasury", amount: 25 },
    },
    { event: "demo.service.listening" },
    {
      event: "demo.ledger.listening",
      fields: { listen_addr: "127.0.0.1:8443" },
    },
  ]);

  // MPC-TLS lifecycle.
  if (backend.countEvent({ event: "demo.ledger.connection.accepted" }) < 1) {
    throw new Error("expected ≥1 demo.ledger.connection.accepted event");
  }
  backend.expectEventCount(
    { event: "demo.ledger.attestations.lookup", fields: { tx_id: 1 } },
    1,
    "ledger /api/attestations hit",
  );

  // Notarization transcript fields match the JSON result.
  const transcript = backend.expectEvent(
    { event: "zktls.notarize.transcript.received" },
    "zktls.notarize.transcript.received",
  );
  assertEquals("transcript.server_name", SERVER_NAME, transcript.fields.server_name);
  assertEquals(
    "transcript.commitment_count",
    EXPECTED_COMMITMENT_COUNT,
    transcript.fields.commitment_count,
  );
  assertEquals("transcript.sent_len", EXPECTED_REQUEST_BYTES, transcript.fields.sent_len);
  assertEquals("transcript.received_len", EXPECTED_RESPONSE_BYTES, transcript.fields.received_len);

  // verifier-view banners (now structured: zktls.verifier.view direction=… bytes=…).
  backend.expectEventCount(
    {
      event: "zktls.verifier.view",
      fields: { direction: "request", bytes: EXPECTED_REQUEST_BYTES },
    },
    1,
    "zktls.verifier.view direction=request",
  );
  const responseView = backend.expectEvent(
    {
      event: "zktls.verifier.view",
      fields: { direction: "response", bytes: EXPECTED_RESPONSE_BYTES },
    },
    "zktls.verifier.view direction=response",
  );

  // Verifier-view RESPONSE body must show exactly ATTESTATION_LEN '#' after
  // `"attestation":` — the structural pin that says the redacted-body grammar
  // produced the right ranges and the commit set covered the full 32-char
  // attestation block.
  const body = String(responseView.fields.body ?? "");
  const hashRun = body.match(/"attestation":·(#+)/);
  if (!hashRun) {
    throw new Error(`verifier-view body has no #-run after "attestation":\n${body}`);
  }
  assertEquals("attestation hash count", EXPECTED_ATTESTATION_HASH_HASHES, hashRun[1].length);
  if (!body.includes(`"toUsername":"${TO_USER}"`)) {
    throw new Error(`verifier-view body missing revealed toUsername=${TO_USER}`);
  }
  if (!body.includes(`"eligibleForMint":true`)) {
    throw new Error(`verifier-view body missing revealed eligibleForMint=true`);
  }

  // Final verifier outcome.
  backend.expectEventCount(
    { event: "zktls.verifier.outcome.sent", fields: { success: true } },
    1,
    "zktls.verifier.outcome.sent success=true",
  );

  // Backend errors: only the harmless Chrome TCP-probe handshake EOF.
  for (const item of backend.items) {
    if (!/ ERROR /.test(item.text)) continue;
    if (ALLOWED_BACKEND_ERROR_PATTERN.test(item.text)) continue;
    throw new Error(`unexpected backend ERROR line: ${item.text}`);
  }

  // ─── Browser console assertions ─────────────────────────────────────────
  browserCapture.console.expectEventInOrder([
    { event: "zktls.action.start.click" },
    { event: "zktls.worker.wasm.init.start" },
    { event: "zktls.worker.wasm.init.done" },
    { event: "zktls.worker.pool.start" },
    { event: "zktls.worker.pool.ready" },
    { event: "zktls.transport.session.opening" },
    { event: "zktls.transport.session.ready" },
    { event: "zktls.transport.streams.creating" },
    { event: "zktls.transport.streams.preambles_written" },
    { event: "zktls.prover.constructing" },
    { event: "zktls.prover.prove_streams.start" },
    { event: "zktls.prover.prove_streams.done" },
    {
      event: "zktls.prover.view",
      fields: { direction: "request", bytes: EXPECTED_REQUEST_BYTES },
    },
    {
      event: "zktls.prover.view",
      fields: { direction: "response", bytes: EXPECTED_RESPONSE_BYTES },
    },
    { event: "zktls.transport.session.closed" },
    { event: "zktls.notarize.done" },
  ]);

  // The prover-view RESPONSE must contain the actual HTTP response that the
  // prover saw — full bytes, including the values the verifier didn't reveal
  // to itself.
  const proverResponse = browserCapture.console.expectEvent(
    {
      event: "zktls.prover.view",
      fields: { direction: "response", bytes: EXPECTED_RESPONSE_BYTES },
    },
    "zktls.prover.view direction=response",
  );
  const proverBody = String(proverResponse.fields.body ?? "");
  if (!proverBody.includes("HTTP/1.1 200 OK")) {
    throw new Error(`prover-view RESPONSE missing 'HTTP/1.1 200 OK': ${proverBody}`);
  }
  if (!proverBody.includes(`"toUsername":"${TO_USER}"`)) {
    throw new Error(`prover-view RESPONSE missing toUsername=${TO_USER}`);
  }
  if (!proverBody.includes(`"amount":${TRANSFER_AMOUNT}`)) {
    throw new Error(`prover-view RESPONSE missing amount=${TRANSFER_AMOUNT}`);
  }

  // No errors of any flavour reached the page console.
  browserCapture.console.expectEventCount({ event: "zktls.notarize.done" }, 1);
  browserCapture.console.expectEventCount({ event: "zktls.notarize.failed" }, 0);
  browserCapture.console.expectEventCount({ event: "runtime.page.error" }, 0);
  for (const item of browserCapture.console.items) {
    if (item.type === "pageerror") {
      throw new Error(`unexpected page error: ${item.text}`);
    }
  }
  browserCapture.expectNoRequestFailures();

  console.log("\nzktls flow: PASS");
  console.log(JSON.stringify(result, null, 2));
  await runCleanup();
  process.exit(0);
} catch (error) {
  console.error(`\nzktls flow: FAIL — ${error.message}`);
  await runCleanup();
  process.exit(1);
}
