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
      revealBodyFields: [{ quoted: ".toUsername" }, { unquoted: ".eligibleForMint" }],
      commitBodyFields: [],
      revealKeysCommitValues: [{ keypath: ".attestation", commitmentLength: ATTESTATION_LEN }],
    },
  };
}

// Vite automatically inlines spawn.js as a data: URL when bundling, which
// eliminates all HTTP requests for Rayon thread Workers. Without a bundler,
// Salvo serves spawn.js over HTTPS from disk — Rayon can spawn 8-16+ threads
// simultaneously, each needing spawn.js, but HTTP/1.1's 6-connection limit
// causes some fetches to be cancelled (ERR:ABORTED) → thread never starts → deadlock.
//
// This function replicates what Vite does at build time: fetch spawn.js once,
// rewrite its relative imports to absolute URLs (required when running from a
// blob URL which has no directory context), then create a blob URL. The Worker
// constructor is patched so all subsequent spawn Workers use the blob URL
// (served from browser memory, no network round-trip).
async function installSpawnBlobPatch() {
  const ZKTLS_ABS = new URL("/assets/wasm/zktls.js", location.origin).href;

  // Dynamically find spawn.js path from zktls.js so the hash in the path
  // doesn't need to be updated manually after each WASM rebuild.
  const zktlsText = await fetch(ZKTLS_ABS).then((r) => r.text());
  const match = zktlsText.match(/['"](\.[^'"]*web-spawn[^'"]*spawn\.js)['"]/);
  if (!match) throw new Error("could not find spawn.js path in zktls.js");
  const SPAWN_PATH = new URL(match[1], ZKTLS_ABS).href;

  let text = await fetch(SPAWN_PATH).then((r) => r.text());

  // Fix relative zktls.js import → absolute URL (blob URLs have no directory).
  text = text
    .replaceAll("'../../../zktls.js'", `'${ZKTLS_ABS}'`)
    .replaceAll('"../../../zktls.js"', `"${ZKTLS_ABS}"`);

  // Replace `new URL('./spawn.js', import.meta.url)` with `new URL(import.meta.url)`.
  // When running as a blob Worker, import.meta.url IS the blob URL itself, so
  // thread Workers spawned by Rayon's spawner also receive the blob URL — no HTTP.
  text = text.replaceAll(
    "new URL(\n        './spawn.js',\n        import.meta.url\n    )",
    "new URL(import.meta.url)",
  );

  const blob = new Blob([text], { type: "application/javascript" });
  const blobUrl = URL.createObjectURL(blob);

  const OriginalWorker = self.Worker;
  self.Worker = class extends OriginalWorker {
    constructor(url, options) {
      // Intercept any Worker pointing at spawn.js (HTTP or blob variants).
      const s = String(url);
      if (s.includes("/spawn.js") || s.includes("web-spawn")) {
        super(blobUrl, options);
      } else {
        super(url, options);
      }
    }
  };
}

async function runProve(config) {
  event("zktls.worker.wasm.init.start");
  await init();
  event("zktls.worker.wasm.init.done");

  await installSpawnBlobPatch();

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
    const body = JSON.parse(new TextDecoder().decode(new Uint8Array(output.responseBody)).trim());

    return {
      flow: "notarize-wasm",
      serverName: config.serverName,
      toUsername: body.toUsername,
      amount: Number(body.amount),
      eligibleForMint: body.eligibleForMint === true,
      commitmentCount: Number(output.commitmentCount ?? 0),
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
