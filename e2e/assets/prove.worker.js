self.addEventListener('error', (ev) => {
    const detail = [
        ev.message || null,
        ev.filename ? `at ${ev.filename}:${ev.lineno}:${ev.colno}` : null,
        ev.error ? (ev.error.stack || ev.error.message || String(ev.error)) : null,
    ].filter(Boolean).join(' | ');
    self.postMessage({ kind: 'error', message: 'worker self error: ' + (detail || '(no detail)') });
});
self.addEventListener('unhandledrejection', (ev) => {
    const r = ev.reason;
    self.postMessage({ kind: 'error', message: 'worker unhandledrejection: ' + (r?.stack || r?.message || String(r)) });
});

import init, { Prover, initialize } from '/assets/wasm/tlsnotary.js';

const MAX_SENT_DATA = 4096;
const MAX_RECV_DATA = 16384;

function hexToBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (clean.length % 2 !== 0) throw new Error('hex string has odd length');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}

function post(kind, payload) {
    self.postMessage({ kind, ...payload });
}

function log(line) {
    post('log', { line });
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
        request: {
            method: 'GET',
            uri: `/api/attestations/${config.txId}`,
            headers: [
                ['content-type', 'application/json'],
                ['Connection', 'close'],
            ],
        },
        request_reveal: {
            reveal_headers: ['content-type'],
            commit_headers: ['connection'],
            reveal_body_fields: [],
            commit_body_fields: [],
            reveal_keys_commit_values: [],
        },
        response_reveal: {
            reveal_headers: [],
            commit_headers: [],
            reveal_body_fields: [
                { Quoted: '.toUsername' },
                { Unquoted: '.eligibleForMint' },
            ],
            commit_body_fields: [],
            reveal_keys_commit_values: [
                { keypath: '.attestation', commitment_length: 32 },
            ],
        },
        hash_alg: 'blake3',
    };
}

function parseResponseBody(bodyBytes) {
    const text = new TextDecoder().decode(new Uint8Array(bodyBytes));
    return JSON.parse(text.trim());
}

async function runProve(config) {
    log('initialising WASM');
    await init();

    log('starting web-spawn worker pool');
    await initialize();

    log('opening WebTransport session');
    const session = new WebTransport(config.connectUrl, {
        serverCertificateHashes: [
            { algorithm: 'sha-256', value: hexToBytes(config.certHashHex) },
        ],
    });
    await session.ready;
    log('WebTransport session ready');

    log('creating verifier + proxy bidi streams');
    const verifierStream = await session.createBidirectionalStream();
    const proxyStream = await session.createBidirectionalStream();

    await writePreamble(verifierStream, 'VERIFY\n');
    await writePreamble(proxyStream, `CONNECT ${config.serverHost}:${config.serverPort}\n`);
    log('role preambles written');

    log('constructing Prover');
    const prover = new Prover(JSON.stringify(buildProverInputs(config)));

    log('running prover.prove(verifierStream, proxyStream)');
    const output = await prover.prove(verifierStream, proxyStream);

    log('prover returned, parsing response body');
    const body = parseResponseBody(output.response_body);

    return {
        flow: 'notarize-wasm',
        server_name: config.serverName,
        to_username: body.toUsername,
        amount: Number(body.amount),
        eligible_for_mint: body.eligibleForMint === true,
        commitment_count: Number(output.commitment_count ?? 0),
    };
}

self.addEventListener('message', async (ev) => {
    if (ev.data?.kind !== 'start') return;
    try {
        const result = await runProve(ev.data.config);
        post('result', { result });
    } catch (err) {
        post('error', { message: err?.stack || err?.message || String(err) });
    }
});
