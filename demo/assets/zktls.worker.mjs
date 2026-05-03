import init, { Prover, initialize } from "/assets/wasm/zktls.js";
import { event } from "./log.mjs";
import { installWorkerErrorForwarder } from "./flow.mjs";

installWorkerErrorForwarder();

const ATTESTATION_LEN = 32;
const MAX_SENT_DATA = 1 << 12;
const MAX_RECV_DATA = 1 << 14;

const post = (kind, payload = {}) => self.postMessage({ kind, ...payload });

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

function buildProverInputs(config) {
  return {
    server_name: config.serverName,
    server_cert_der: Array.from(hexToBytes(config.serverCertDerHex)),
    max_sent_data: MAX_SENT_DATA,
    max_recv_data: MAX_RECV_DATA,
    request_method: "GET",
    request_uri: `/api/attestations/${config.txId}`,
    request_headers: [
      ["content-type", "application/json"],
      ["Connection", "close"],
    ],
    request_reveal_config: {
      reveal_headers: ["content-type"],
      commit_headers: ["connection"],
      reveal_body_fields: [],
      commit_body_fields: [],
      reveal_keys_commit_values: [],
    },
    response_reveal_config: {
      reveal_headers: [],
      commit_headers: [],
      reveal_body_fields: [
        { Quoted: ".toUsername" },
        { Unquoted: ".eligibleForMint" },
      ],
      commit_body_fields: [],
      reveal_keys_commit_values: [
        { keypath: ".attestation", commitment_length: ATTESTATION_LEN },
      ],
    },
  };
}

async function runProve(config) {
  event("zktls.worker.wasm.init.start");
  await init();
  event("zktls.worker.wasm.init.done");
  event("zktls.worker.pool.start");
  await initialize();
  event("zktls.worker.pool.ready");

  event("zktls.transport.session.opening");
  const session = new WebTransport(config.connectUrl, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hexToBytes(config.certHashHex) }],
  });
  try {
    await session.ready;
    event("zktls.transport.session.ready");

    event("zktls.transport.streams.creating");
    const verifierStream = await session.createBidirectionalStream();
    const proxyStream = await session.createBidirectionalStream();
    await writePreamble(verifierStream, "VERIFY\n");
    await writePreamble(proxyStream, `CONNECT ${config.serverHost}:${config.serverPort}\n`);
    event("zktls.transport.streams.preambles_written");

    event("zktls.prover.constructing");
    const prover = new Prover();
    const inputsJson = JSON.stringify(buildProverInputs(config));

    event("zktls.prover.prove_streams.start");
    const output = await prover.prove_streams(inputsJson, verifierStream, proxyStream);
    event("zktls.prover.prove_streams.done");

    const decoder = new TextDecoder("utf-8", { fatal: false });
    event("zktls.prover.view", {
      direction: "request",
      bytes: output.sent.length,
      body: decoder.decode(new Uint8Array(output.sent)),
    });
    event("zktls.prover.view", {
      direction: "response",
      bytes: output.received.length,
      body: decoder.decode(new Uint8Array(output.received)),
    });
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
      event("zktls.transport.session.closed");
    } catch (err) {
      event("zktls.transport.session.close_failed", {
        message: err?.message || String(err),
      });
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
