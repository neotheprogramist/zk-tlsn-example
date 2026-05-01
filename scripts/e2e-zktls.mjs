#!/usr/bin/env node
// E2E: drive /zktls in headed Chromium and assert everything we can observe —
// the JSON result, the backend tracing output, and the browser DevTools
// Protocol console stream.

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
  waitForConsoleResult,
} from "./lib/harness.mjs";

const EXPECTED_COMMITMENT_COUNT = 2;
const EXPECTED_REQUEST_BYTES = 87; // GET /api/attestations/1 + content-type header
const EXPECTED_RESPONSE_BYTES = 312; // HTTP 200 + JSON body for tx_id=1, alice→treasury, amount=25
const EXPECTED_ATTESTATION_HASH_HASHES = 32; // ATTESTATION_LEN — see zktls::FiatTransferAttestation
const ALLOWED_BACKEND_ERROR_PATTERN = /Connection error error=tls handshake eof/; // Chrome's TCP probe

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
  await installPageErrorForwarder(page, "ZKTLS_ERROR");

  const resultPromise = waitForConsoleResult({
    page,
    resultPrefix: "ZKTLS_RESULT",
    errorPrefix: "ZKTLS_ERROR",
    label: "ZKTLS_RESULT",
  });

  console.log("[harness] navigating to /zktls...");
  await page.goto(`https://${SERVICE_ADDR}/zktls`, { waitUntil: "load" });
  console.log('[harness] clicking "Start attestation"...');
  await page.locator('[data-role="start"]').click();

  console.log("[harness] prover running, awaiting ZKTLS_RESULT (may take 20–60s)...");
  const result = await resultPromise;

  // ─── Result-JSON assertions ─────────────────────────────────────────────
  assertEquals("flow", "notarize-wasm", result.flow);
  assertEquals("server_name", SERVER_NAME, result.server_name);
  assertEquals("to_username", TO_USER, result.to_username);
  assertEquals("amount", TRANSFER_AMOUNT, result.amount);
  assertEquals("eligible_for_mint", true, result.eligible_for_mint);
  assertEquals("commitment_count", EXPECTED_COMMITMENT_COUNT, result.commitment_count);

  // ─── Backend tracing assertions ─────────────────────────────────────────
  // Service + ledger boot.
  backend.expectInOrder([
    [/seeded demo transfer.*tx_id=1.*from=alice.*to=treasury.*amount=25/, "ledger seed"],
    [/service: listening on https:\/\//, "service listening"],
    [/TLS demo server listening.*listen_addr=127\.0\.0\.1:8443/, "ledger TCP bind"],
    [/listening \[HTTP\/3\.0\] on https:\/\/127\.0\.0\.1:8444/, "salvo HTTP/3"],
    [/listening \[HTTP\/1\.1\] on https:\/\/127\.0\.0\.1:8444/, "salvo HTTP/1.1"],
  ]);

  // MPC-TLS lifecycle.
  backend.expectAtLeast(/Accepted connection addr=127\.0\.0\.1:/, 1, "ledger Accepted connection");
  backend.expectCount(/starting MPC-TLS/, 1, "starting MPC-TLS");
  backend.expectCount(/finished MPC-TLS/, 1, "finished MPC-TLS");
  backend.expectCount(/GET \/api\/attestations.*tx_id=1/, 1, "ledger /api/attestations hit");

  // Notarization transcript fields match the JSON result.
  const transcriptLine = backend.findText(
    /Received notarization transcript from prover/,
    "transcript receipt",
  );
  if (!transcriptLine.includes(`server_name=${SERVER_NAME}`)) {
    throw new Error(`transcript line missing server_name=${SERVER_NAME}: ${transcriptLine}`);
  }
  if (!transcriptLine.includes(`commitment_count=${EXPECTED_COMMITMENT_COUNT}`)) {
    throw new Error(
      `transcript line wrong commitment_count (expected ${EXPECTED_COMMITMENT_COUNT}): ${transcriptLine}`,
    );
  }
  const sentMatch = transcriptLine.match(/sent_len=(\d+)/);
  const recvMatch = transcriptLine.match(/received_len=(\d+)/);
  assertEquals(
    "transcript.sent_len",
    EXPECTED_REQUEST_BYTES,
    sentMatch ? Number(sentMatch[1]) : null,
  );
  assertEquals(
    "transcript.received_len",
    EXPECTED_RESPONSE_BYTES,
    recvMatch ? Number(recvMatch[1]) : null,
  );

  // verifier-view banners.
  backend.expectCount(
    new RegExp(`verifier-view REQUEST \\(${EXPECTED_REQUEST_BYTES} bytes;`),
    1,
    `verifier-view REQUEST (${EXPECTED_REQUEST_BYTES} bytes)`,
  );
  backend.expectCount(
    new RegExp(`verifier-view RESPONSE \\(${EXPECTED_RESPONSE_BYTES} bytes;`),
    1,
    `verifier-view RESPONSE (${EXPECTED_RESPONSE_BYTES} bytes)`,
  );

  // Verifier-view RESPONSE body must show exactly ATTESTATION_LEN '#' after
  // `"attestation":` — the structural pin that says the redacted-body grammar
  // produced the right ranges and the commit set covered the full 32-char
  // attestation block.
  const responseBodyLine = backend.findText(/"attestation":·#+/, "verifier-view attestation block");
  const hashRun = responseBodyLine.match(/"attestation":·(#+)/);
  if (!hashRun) {
    throw new Error(`verifier-view body has no #-run after "attestation":\n${responseBodyLine}`);
  }
  assertEquals("attestation hash count", EXPECTED_ATTESTATION_HASH_HASHES, hashRun[1].length);

  // Verifier-view RESPONSE must show the revealed fields.
  if (!responseBodyLine.includes(`"toUsername":"${TO_USER}"`)) {
    throw new Error(`verifier-view body missing revealed toUsername=${TO_USER}`);
  }
  if (!responseBodyLine.includes(`"eligibleForMint":true`)) {
    throw new Error(`verifier-view body missing revealed eligibleForMint=true`);
  }

  // Final verifier outcome.
  backend.expectCount(
    /Sending verification outcome.*success=true/,
    1,
    "verification outcome success=true",
  );

  // Backend errors: only the harmless Chrome TCP-probe handshake EOF.
  for (const item of backend.items) {
    if (!/ ERROR /.test(item.text)) continue;
    if (ALLOWED_BACKEND_ERROR_PATTERN.test(item.text)) continue;
    throw new Error(`unexpected backend ERROR line: ${item.text}`);
  }

  // ─── Browser console assertions ─────────────────────────────────────────
  browserCapture.console.expectInOrder([
    [/spawning prover worker/, "main: spawn worker"],
    [/initialising WASM/, "worker: wasm init"],
    [/starting web-spawn worker pool/, "worker: web-spawn"],
    [/opening WebTransport session/, "worker: WT open"],
    [/WebTransport session ready/, "worker: WT ready"],
    [/creating verifier \+ proxy bidi streams/, "worker: bidi streams"],
    [/role preambles written/, "worker: preambles"],
    [/constructing Prover/, "worker: Prover ctor"],
    [/running prover\.prove_streams/, "worker: prove_streams"],
    [
      new RegExp(`prover-view REQUEST \\(${EXPECTED_REQUEST_BYTES} bytes, full\\):`),
      `prover-view REQUEST (${EXPECTED_REQUEST_BYTES} bytes)`,
    ],
    [
      new RegExp(`prover-view RESPONSE \\(${EXPECTED_RESPONSE_BYTES} bytes, full\\):`),
      `prover-view RESPONSE (${EXPECTED_RESPONSE_BYTES} bytes)`,
    ],
    [/WebTransport session closed/, "worker: WT closed"],
    [/^ZKTLS_RESULT /, "ZKTLS_RESULT line"],
  ]);

  // The prover-view RESPONSE must contain the actual HTTP response that the
  // prover saw — full bytes, including the values the verifier didn't reveal
  // to itself.
  const proverResponse = browserCapture.console.findText(
    /prover-view RESPONSE \(\d+ bytes, full\):/,
    "prover-view RESPONSE block",
  );
  if (!proverResponse.includes("HTTP/1.1 200 OK")) {
    throw new Error(`prover-view RESPONSE missing 'HTTP/1.1 200 OK': ${proverResponse}`);
  }
  if (!proverResponse.includes(`"toUsername":"${TO_USER}"`)) {
    throw new Error(`prover-view RESPONSE missing toUsername=${TO_USER}`);
  }
  if (!proverResponse.includes(`"amount":${TRANSFER_AMOUNT}`)) {
    throw new Error(`prover-view RESPONSE missing amount=${TRANSFER_AMOUNT}`);
  }

  // No errors of any flavour reached the page console.
  browserCapture.console.expectCount(/^ZKTLS_RESULT /, 1, "ZKTLS_RESULT count");
  browserCapture.console.expectCount(/^ZKTLS_ERROR /, 0, "ZKTLS_ERROR count");
  browserCapture.console.expectAbsent(/^ZKTLS_ERROR /, "ZKTLS_ERROR line");
  for (const item of browserCapture.console.items) {
    if (item.type === "pageerror") {
      throw new Error(`unexpected page error: ${item.text}`);
    }
    if (item.type === "error" && !item.text.startsWith("ZKTLS_RESULT ")) {
      throw new Error(`unexpected console.error: ${item.text}`);
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
