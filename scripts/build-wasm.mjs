#!/usr/bin/env node
// Builds the zktlsn_core wasm bundle for Flow 1 (browser) and writes the
// wasm-bindgen output into the service's asset directory.
//
// Post-step: wasm-bindgen emits web-spawn's snippet with `import('../../..')`,
// which Chrome can't resolve against a directory URL. Rewrite to an explicit
// `../../../core.js` so the dynamic import works in the browser.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const OUT_DIR = 'demo/assets/wasm';
const WASM_INPUT = 'target/wasm32-unknown-unknown/release/zktlsn_core.wasm';

function run(cmd, args) {
    return new Promise((resolve, reject) => {
        console.log(`$ ${cmd} ${args.join(' ')}`);
        const child = spawn(cmd, args, { stdio: 'inherit' });
        child.on('error', reject);
        child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`${cmd} exited with code ${code}`));
        });
    });
}

function patchSpawnJs() {
    const snippetsRoot = path.join(OUT_DIR, 'snippets');
    if (!fs.existsSync(snippetsRoot)) return;
    for (const dir of fs.readdirSync(snippetsRoot)) {
        const spawnJs = path.join(snippetsRoot, dir, 'js', 'spawn.js');
        if (!fs.existsSync(spawnJs)) continue;
        const before = fs.readFileSync(spawnJs, 'utf8');
        const after = before.replaceAll("'../../..'", "'../../../core.js'");
        if (after !== before) {
            fs.writeFileSync(spawnJs, after);
            console.log(`patched ${spawnJs}`);
        }
    }
}

try {
    await run('cargo', [
        '+nightly',
        'build',
        '-p',
        'zktlsn_core',
        '--lib',
        '--target',
        'wasm32-unknown-unknown',
        '--release',
    ]);
    await run('wasm-bindgen', [
        WASM_INPUT,
        '--out-dir',
        OUT_DIR,
        '--target',
        'web',
        '--out-name',
        'core',
    ]);
    patchSpawnJs();
    console.log(`\nbuilt ${path.join(OUT_DIR, 'core_bg.wasm')}`);
} catch (err) {
    console.error(`\nbuild-wasm: FAIL — ${err.message}`);
    process.exit(1);
}
