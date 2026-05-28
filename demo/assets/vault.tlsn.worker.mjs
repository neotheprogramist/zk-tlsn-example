// Vault TLSN worker — wraps the zktls WASM Prover for the /vault page's
// tlsn_transfer offer challenge. Same MPC-TLS proving flow as the standalone
// /zktls demo, but talks to the demo service via the VERIFY_VAULT role (so the
// server runs the vault-specific policy: expected recipient + minimum price)
// and reveals the fields the vault host code needs (.toUsername, .amount,
// .txId) plus a commitment to .attestation (for the future Etap C ZK proof).

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
    serverName: config.serverName,
    serverCertDer: Array.from(hexToBytes(config.serverCertDerHex)),
    maxSentData: MAX_SENT_DATA,
    maxRecvData: MAX_RECV_DATA,
    requestMethod: "GET",
    requestUri: `/api/attestations/${config.txId}`,
    requestHeaders: [
      ["content-type", "application/json"],
      ["Connection", "close"],
    ],
    requestRevealConfig: {
      revealHeaders: ["content-type"],
      commitHeaders: ["connection"],
      revealBodyFields: [],
      commitBodyFields: [],
      revealKeysCommitValues: [],
    },
    responseRevealConfig: {
      revealHeaders: [],
      commitHeaders: [],
      revealBodyFields: [
        { quoted: ".toUsername" },
        { unquoted: ".amount" },
        { unquoted: ".txId" },
      ],
      commitBodyFields: [],
      revealKeysCommitValues: [{ keypath: ".attestation", commitmentLength: ATTESTATION_LEN }],
    },
  };
}

async function runProve(config) {
  event("vault.tlsn.worker.wasm.init.start");
  await init();
  event("vault.tlsn.worker.wasm.init.done");
  await initialize();
  event("vault.tlsn.worker.pool.ready");

  event("vault.tlsn.transport.session.opening");
  const session = new WebTransport(config.connectUrl, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hexToBytes(config.certHashHex) }],
  });
  try {
    await session.ready;
    event("vault.tlsn.transport.session.ready");

    event("vault.tlsn.transport.streams.creating");
    const verifierStream = await session.createBidirectionalStream();
    const proxyStream = await session.createBidirectionalStream();
    // Vault-specific preamble: tells the demo service to run the
    // parametrised verifier against expectedToUser + price.
    await writePreamble(
      verifierStream,
      `VERIFY_VAULT ${config.expectedToUser} ${config.price}\n`,
    );
    await writePreamble(proxyStream, `CONNECT ${config.serverHost}:${config.serverPort}\n`);
    event("vault.tlsn.transport.streams.preambles_written");

    const prover = new Prover();
    const inputsJson = JSON.stringify(buildProverInputs(config));

    event("vault.tlsn.prover.prove_streams.start");
    const output = await prover.prove_streams(inputsJson, verifierStream, proxyStream);
    event("vault.tlsn.prover.prove_streams.done");

    // The server's success frame travels via prover.prove_streams' verifier
    // path and is returned to the WASM Prover before resolve. The JS Prover
    // wrapper returns just the prover-side output; we therefore parse the
    // attested body fields out of the response_body bytes for echo-back.
    const body = JSON.parse(new TextDecoder().decode(new Uint8Array(output.responseBody)).trim());

    return {
      flow: "tlsn-vault",
      serverName: config.serverName,
      txId: Number(body.txId),
      toUsername: String(body.toUsername),
      amount: Number(body.amount),
      commitmentCount: Number(output.commitmentCount ?? 0),
    };
  } finally {
    try {
      await session.close({ closeCode: 0, reason: "vault-tlsn-done" });
      event("vault.tlsn.transport.session.closed");
    } catch (err) {
      event("vault.tlsn.transport.session.close_failed", {
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
