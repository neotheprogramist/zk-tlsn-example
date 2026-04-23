#!/usr/bin/env node
// Flow 1: TLSN attestation only.
// Spawns the demo server and the QUIC verifier service, then runs the notarize
// client which creates a transfer, opens a TLSN session via the verifier, and
// reads back the AttestOnly outcome. Asserts the revealed transcript matches.

import {
    assertEquals,
    parseResultLine,
    runCargoBinary,
    sleep,
    spawnCargoBinary,
    spawnProcess,
    waitForTcp,
    waitForUdp,
} from './lib/run-binary.mjs';

const SERVER_ADDR = '127.0.0.1:8443';
const SERVER_PORT = 8443;
const SERVER_NAME = 'localhost';
const SERVER_CERT_PATH = '.data/tls/server-cert.pem';
const SERVER_KEY_PATH = '.data/tls/server-key.pem';

const VERIFIER_ADDR = '[::1]:5000';
const VERIFIER_PORT = 5000;
const QUIC_CERT_PATH = '.data/quic/verifier-cert.pem';
const QUIC_KEY_PATH = '.data/quic/verifier-key.pem';

const FROM_USER = 'alice';
const TO_USER = 'treasury';
const TRANSFER_AMOUNT = 25;
const EXPECTED_COMMITMENT_COUNT = 2;

const sharedEnv = {
    ZKTLSN_SERVER_ADDR: SERVER_ADDR,
    ZKTLSN_SERVER_NAME: SERVER_NAME,
    ZKTLSN_SERVER_CERT_PATH: SERVER_CERT_PATH,
    ZKTLSN_SERVER_KEY_PATH: SERVER_KEY_PATH,
    ZKTLSN_SERVER_LISTEN_ADDR: SERVER_ADDR,
    ZKTLSN_VERIFIER_ADDR: VERIFIER_ADDR,
    ZKTLSN_VERIFIER_CERT_PATH: QUIC_CERT_PATH,
    ZKTLSN_QUIC_CERT_PATH: QUIC_CERT_PATH,
    ZKTLSN_QUIC_KEY_PATH: QUIC_KEY_PATH,
};

const cleanup = [];
const registerCleanup = (handle) => cleanup.push(handle);

async function runCleanup() {
    for (const handle of cleanup.reverse()) {
        try {
            handle.kill();
            await Promise.race([handle.result, sleep(2_000)]);
        } catch (error) {
            console.error(`cleanup error: ${error.message}`);
        }
    }
}

process.on('SIGINT', async () => {
    await runCleanup();
    process.exit(130);
});

try {
    console.log('[harness] starting demo server...');
    const server = spawnCargoBinary({
        bin: 'server',
        env: sharedEnv,
        label: 'server',
        color: '32',
    });
    registerCleanup(server);
    await waitForTcp('127.0.0.1', SERVER_PORT);
    console.log('[harness] demo server ready.');

    console.log('[harness] starting verifier service...');
    const verifier = spawnCargoBinary({
        bin: 'verifier',
        env: sharedEnv,
        label: 'verifier',
        color: '34',
    });
    registerCleanup(verifier);
    await waitForUdp('::1', VERIFIER_PORT);
    console.log('[harness] verifier ready.');

    console.log('[harness] running notarize client...');
    const notarize = await runCargoBinary({
        bin: 'notarize',
        env: {
            ...sharedEnv,
            ZKTLSN_FROM_USER: FROM_USER,
            ZKTLSN_TO_USER: TO_USER,
            ZKTLSN_TRANSFER_AMOUNT: String(TRANSFER_AMOUNT),
        },
        label: 'notarize',
        color: '36',
    });
    if (notarize.exitCode !== 0) {
        throw new Error(`notarize exited with code ${notarize.exitCode}`);
    }

    const result = parseResultLine(notarize.resultLine);
    assertEquals('flow', 'notarize', result.flow);
    assertEquals('server_name', SERVER_NAME, result.server_name);
    assertEquals('to_username', TO_USER, result.to_username);
    assertEquals('amount', TRANSFER_AMOUNT, result.amount);
    assertEquals('eligible_for_mint', true, result.eligible_for_mint);
    assertEquals('commitment_count', EXPECTED_COMMITMENT_COUNT, result.commitment_count);

    console.log('\ntlsn flow: PASS');
    console.log(JSON.stringify(result, null, 2));
    await runCleanup();
    process.exit(0);
} catch (error) {
    console.error(`\ntlsn flow: FAIL — ${error.message}`);
    await runCleanup();
    process.exit(1);
}
