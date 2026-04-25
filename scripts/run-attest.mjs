#!/usr/bin/env node
// Flow 1: browser WASM prover via Playwright (headed Chromium).
// Spawns the demo server and the `service` binary, then launches a real
// Chromium window through Playwright, navigates to the prover page, clicks
// "Start attestation", captures the ZKTLSN_RESULT line from the page console,
// and asserts on the revealed fields.
//
// Playwright is not vendored as a dependency. The script self-bootstraps by
// asking npx to install playwright into its cache on first run; subsequent
// runs resolve from that cache.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

import {
    assertEquals,
    sleep,
    spawnCargoBinary,
    waitForTcp,
} from './lib/run-binary.mjs';

async function loadPlaywright() {
    const mod = await (async () => {
        try {
            return await import('playwright');
        } catch {
            // Ask npx to install playwright into its cache, then resolve the
            // package through a require scoped to the cache's node_modules.
            const binPath = execFileSync(
                'npx',
                ['--yes', '--package=playwright', '--', 'which', 'playwright'],
                { encoding: 'utf8' },
            ).trim();
            const req = createRequire(binPath);
            return await import(req.resolve('playwright'));
        }
    })();
    return mod.chromium ?? mod.default?.chromium;
}

const chromium = await loadPlaywright();
if (!chromium) {
    throw new Error('failed to resolve playwright.chromium');
}

const SERVER_ADDR = '127.0.0.1:8443';
const SERVER_PORT = 8443;
const SERVER_NAME = 'localhost';
const SERVER_CERT_PATH = '.data/tls/server-cert.pem';
const SERVER_KEY_PATH = '.data/tls/server-key.pem';

const SERVICE_HOST = '127.0.0.1';
const SERVICE_PORT = 8444;
const SERVICE_ADDR = `${SERVICE_HOST}:${SERVICE_PORT}`;
const SERVICE_CERT_DIR = '.data/service';

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
    ZKTLSN_SERVICE_LISTEN_ADDR: SERVICE_ADDR,
    ZKTLSN_SERVICE_CERT_DIR: SERVICE_CERT_DIR,
    ZKTLSN_FROM_USER: FROM_USER,
    ZKTLSN_TO_USER: TO_USER,
    ZKTLSN_TRANSFER_AMOUNT: String(TRANSFER_AMOUNT),
};

const cleanup = [];
const registerCleanup = (handle) => cleanup.push(handle);

async function runCleanup() {
    for (const handle of cleanup.reverse()) {
        try {
            await handle.stop();
        } catch (error) {
            console.error(`cleanup error: ${error.message}`);
        }
    }
}

process.on('SIGINT', async () => {
    await runCleanup();
    process.exit(130);
});

async function waitForResult(page, timeoutMs = 120_000) {
    return new Promise((resolve, reject) => {
        let finished = false;
        const timer = setTimeout(async () => {
            if (finished) return;
            finished = true;
            const domLog = await page
                .evaluate(
                    () => document.querySelector('[data-role="log"]')?.textContent ?? '',
                )
                .catch(() => '');
            const tail = domLog.trim().split('\n').slice(-20).join('\n');
            reject(
                new Error(
                    `timed out waiting for ZKTLSN_RESULT after ${timeoutMs}ms\n` +
                        `page log tail:\n${tail}`,
                ),
            );
        }, timeoutMs);

        const finish = (result, err) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            if (err) reject(err);
            else resolve(result);
        };

        page.on('console', (msg) => {
            const text = msg.text();
            if (process.env.CHROME_CONSOLE) {
                process.stderr.write(`\x1b[35m[console]\x1b[0m ${text}\n`);
            }
            if (text.startsWith('ZKTLSN_RESULT ')) {
                finish(text.slice('ZKTLSN_RESULT '.length));
            }
            if (text.startsWith('ZKTLSN_ERROR ')) {
                finish(
                    null,
                    new Error(`page reported error: ${text.slice('ZKTLSN_ERROR '.length)}`),
                );
            }
        });
        page.on('pageerror', (err) => {
            const detail = err?.stack || err?.message || JSON.stringify(err) || String(err);
            finish(null, new Error(`page error: ${detail}`));
        });
    });
}

try {
    const wasmPath = path.join(
        process.cwd(),
        'demo/assets/wasm/core_bg.wasm',
    );
    if (!fs.existsSync(wasmPath)) {
        throw new Error(
            `missing ${wasmPath}. Build the wasm first:\n  node scripts/build-wasm.mjs`,
        );
    }

    console.log('[harness] starting demo server...');
    const server = spawnCargoBinary({
        bin: 'zktlsn',
        args: ['server'],
        env: sharedEnv,
        label: 'server',
        color: '32',
    });
    registerCleanup({
        stop: async () => {
            server.kill();
            await Promise.race([server.result, sleep(2_000)]);
        },
    });
    await waitForTcp('127.0.0.1', SERVER_PORT);
    console.log('[harness] demo server ready.');

    console.log('[harness] starting service...');
    const service = spawnCargoBinary({
        bin: 'zktlsn',
        args: ['service'],
        env: sharedEnv,
        label: 'service',
        color: '33',
    });
    registerCleanup({
        stop: async () => {
            service.kill();
            await Promise.race([service.result, sleep(2_000)]);
        },
    });
    await waitForTcp(SERVICE_HOST, SERVICE_PORT);
    console.log('[harness] service ready.');

    console.log('[harness] launching headed Chromium via Playwright...');
    const browser = await chromium.launch({
        headless: false,
        args: [
            '--ignore-certificate-errors',
            '--enable-features=WebTransport,SharedArrayBuffer',
        ],
    });
    registerCleanup({ stop: async () => browser.close() });

    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    // Forward uncaught errors to the console channel the harness reads.
    await page.addInitScript(() => {
        window.addEventListener('error', (e) =>
            console.error('ZKTLSN_ERROR ' + (e.error?.stack || e.message)),
        );
        window.addEventListener('unhandledrejection', (e) =>
            console.error('ZKTLSN_ERROR ' + (e.reason?.stack || e.reason)),
        );
    });

    const resultPromise = waitForResult(page);

    console.log('[harness] navigating to the service URL...');
    await page.goto(`https://${SERVICE_ADDR}/`, { waitUntil: 'load' });

    console.log('[harness] clicking "Start attestation"...');
    await page.locator('[data-role="start"]').click();

    console.log('[harness] prover running, awaiting ZKTLSN_RESULT (may take 20–60s)...');
    const resultJson = await resultPromise;
    const result = JSON.parse(resultJson);

    assertEquals('flow', 'notarize-wasm', result.flow);
    assertEquals('server_name', SERVER_NAME, result.server_name);
    assertEquals('to_username', TO_USER, result.to_username);
    assertEquals('amount', TRANSFER_AMOUNT, result.amount);
    assertEquals('eligible_for_mint', true, result.eligible_for_mint);
    assertEquals('commitment_count', EXPECTED_COMMITMENT_COUNT, result.commitment_count);

    console.log('\ntlsn wasm flow: PASS');
    console.log(JSON.stringify(result, null, 2));
    await runCleanup();
    process.exit(0);
} catch (error) {
    console.error(`\ntlsn wasm flow: FAIL — ${error.message}`);
    await runCleanup();
    process.exit(1);
}
