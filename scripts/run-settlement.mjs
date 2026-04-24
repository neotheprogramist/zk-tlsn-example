#!/usr/bin/env node
// Flow 2: TLSN + ZK proof + recursive aggregation + on-chain settlement.
// Orchestrates anvil, runs the fixture deployment, starts the demo server
// and verifier service, then runs the settle binary for a 3-transfer batch.
// Asserts the on-chain mint matches the aggregated settlement state.

import {
    assertCargoExit,
    assertCargoResult,
    assertEquals,
    runCargoBinary,
    sleep,
    spawnCargoBinary,
    spawnProcess,
    waitForTcp,
    waitForUdp,
} from './lib/run-binary.mjs';

const ANVIL_HOST = '127.0.0.1';
const ANVIL_PORT = 8545;
const ANVIL_RPC_URL = `http://${ANVIL_HOST}:${ANVIL_PORT}`;
const ANVIL_PRIVATE_KEY =
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const MINT_RECIPIENT = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const MINT_RECIPIENT_NORMALIZED = MINT_RECIPIENT.toLowerCase();

const SERVER_ADDR = '127.0.0.1:8443';
const SERVER_PORT = 8443;
const SERVER_NAME = 'localhost';
const SERVER_CERT_PATH = '.data/tls/server-cert.pem';
const SERVER_KEY_PATH = '.data/tls/server-key.pem';

const VERIFIER_ADDR = '[::1]:5000';
const VERIFIER_PORT = 5000;
const QUIC_CERT_PATH = '.data/quic/verifier-cert.pem';
const QUIC_KEY_PATH = '.data/quic/verifier-key.pem';

const BATCH_FROM = 'alice,bob,alice';
const BATCH_TO = 'treasury,treasury,treasury';
const BATCH_AMOUNTS = '25,10,15';
const EXPECTED_NUM_ATTESTATIONS = 3;
const EXPECTED_TOTAL_AMOUNT = 50;
const EXPECTED_TO_USER_ID = 3;
const EXPECTED_BALANCE_BEFORE = '0';
const EXPECTED_BALANCE_DELTA = '50000000000000000000'; // 50 × 1e18
const EXPECTED_BALANCE_AFTER = EXPECTED_BALANCE_DELTA;

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
    ZKTLSN_ANVIL_RPC_URL: ANVIL_RPC_URL,
    ZKTLSN_ANVIL_PRIVATE_KEY: ANVIL_PRIVATE_KEY,
    ZKTLSN_MINT_RECIPIENT: MINT_RECIPIENT,
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

function assertHex(label, expectedLen, value) {
    if (typeof value !== 'string' || !value.startsWith('0x')) {
        throw new Error(`${label} must be 0x-prefixed hex, got ${JSON.stringify(value)}`);
    }
    const hex = value.slice(2);
    if (hex.length !== expectedLen || !/^[0-9a-fA-F]+$/.test(hex)) {
        throw new Error(`${label} must be ${expectedLen} hex chars, got ${hex.length}`);
    }
}

try {
    console.log('[harness] starting anvil...');
    const anvil = spawnProcess({
        command: 'anvil',
        args: ['--host', ANVIL_HOST, '--port', String(ANVIL_PORT)],
        label: 'anvil',
        color: '33',
    });
    registerCleanup(anvil);
    await waitForTcp(ANVIL_HOST, ANVIL_PORT);
    console.log('[harness] anvil ready.');

    console.log('[harness] running fixture (deploy contracts + write artifacts)...');
    const fixture = await runCargoBinary({
        bin: 'fixture',
        env: sharedEnv,
        label: 'fixture',
        color: '35',
    });
    assertCargoExit('fixture', fixture);

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

    console.log('[harness] running settle for 3-transfer batch...');
    const settle = await runCargoBinary({
        bin: 'settle',
        env: {
            ...sharedEnv,
            ZKTLSN_BATCH_FROM_USERS: BATCH_FROM,
            ZKTLSN_BATCH_TO_USERS: BATCH_TO,
            ZKTLSN_BATCH_AMOUNTS: BATCH_AMOUNTS,
        },
        label: 'settle',
        color: '36',
    });
    const result = assertCargoResult('settle', settle);
    assertEquals('flow', 'settle', result.flow);
    assertEquals('num_attestations', EXPECTED_NUM_ATTESTATIONS, result.num_attestations);
    assertEquals('total_amount', EXPECTED_TOTAL_AMOUNT, result.total_amount);
    assertEquals('to_user_id', EXPECTED_TO_USER_ID, result.to_user_id);
    assertEquals('claimed_root', true, result.claimed_root);
    assertEquals('balance_before', EXPECTED_BALANCE_BEFORE, result.balance_before);
    assertEquals('balance_after', EXPECTED_BALANCE_AFTER, result.balance_after);
    assertEquals('balance_delta', EXPECTED_BALANCE_DELTA, result.balance_delta);

    const resultRecipient = typeof result.recipient === 'string'
        ? result.recipient.toLowerCase()
        : result.recipient;
    assertEquals('recipient', MINT_RECIPIENT_NORMALIZED, resultRecipient);

    assertHex('transfers_root', 64, result.transfers_root);
    assertHex('null_vk_hash', 64, result.null_vk_hash);
    assertHex('recursive_vk_hash', 64, result.recursive_vk_hash);
    assertHex('inner_vk_hash', 64, result.inner_vk_hash);
    assertHex('tx_hash', 64, result.tx_hash);

    console.log('\nsettlement flow: PASS');
    console.log(JSON.stringify(result, null, 2));
    await runCleanup();
    process.exit(0);
} catch (error) {
    console.error(`\nsettlement flow: FAIL — ${error.message}`);
    await runCleanup();
    process.exit(1);
}
