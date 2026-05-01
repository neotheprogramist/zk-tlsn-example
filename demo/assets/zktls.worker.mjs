import init, { Prover, initialize } from "/assets/wasm/zktls.js";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

const post = (kind, payload = {}) => self.postMessage({ kind, ...payload });
const log = (line) => post("log", { line });

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

async function writePreamble(stream, line) {
  const writer = stream.writable.getWriter();
  await writer.write(new TextEncoder().encode(line));
  writer.releaseLock();
}

async function runProve(config) {
  log("initialising WASM");
  await init();
  log("starting web-spawn worker pool");
  await initialize();

  log("opening WebTransport session");
  const session = new WebTransport(config.connectUrl, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hexToBytes(config.certHashHex) }],
  });
  try {
    await session.ready;
    log("WebTransport session ready");

    log("creating verifier + proxy bidi streams");
    const verifierStream = await session.createBidirectionalStream();
    const proxyStream = await session.createBidirectionalStream();
    await writePreamble(verifierStream, "VERIFY\n");
    await writePreamble(proxyStream, `CONNECT ${config.serverHost}:${config.serverPort}\n`);
    log("role preambles written");

    log("constructing Prover");
    const prover = new Prover(
      JSON.stringify({
        server_name: config.serverName,
        server_cert_der: Array.from(hexToBytes(config.serverCertDerHex)),
        tx_id: Number(config.txId),
      }),
    );

    log("running prover.prove_streams(verifierStream, proxyStream)");
    const output = await prover.prove_streams(verifierStream, proxyStream);

    const decoder = new TextDecoder("utf-8", { fatal: false });
    log(
      `prover-view REQUEST (${output.sent.length} bytes, full):\n${decoder.decode(new Uint8Array(output.sent))}`,
    );
    log(
      `prover-view RESPONSE (${output.received.length} bytes, full):\n${decoder.decode(new Uint8Array(output.received))}`,
    );
    const body = JSON.parse(new TextDecoder().decode(new Uint8Array(output.response_body)).trim());

    return {
      flow: "notarize-wasm",
      server_name: config.serverName,
      to_username: body.toUsername,
      amount: Number(body.amount),
      eligible_for_mint: body.eligibleForMint === true,
      commitment_count: Number(output.commitment_count ?? 0),
    };
  } finally {
    try {
      await session.close({ closeCode: 0, reason: "notarize-done" });
      log("WebTransport session closed");
    } catch (err) {
      log("WebTransport session close failed: " + (err?.message || String(err)));
    }
  }
}

self.addEventListener("message", async (ev) => {
  if (ev.data?.kind !== "start") return;
  try {
    const result = await runProve(ev.data.config);
    post("result", { result });
  } catch (err) {
    post("error", { message: err?.stack || err?.message || String(err) });
  }
});
