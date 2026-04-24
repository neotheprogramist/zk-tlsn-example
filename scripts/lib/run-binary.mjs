import { spawn } from 'node:child_process';
import dgram from 'node:dgram';
import net from 'node:net';

const RESULT_PREFIX = 'ZKTLSN_RESULT ';

export function formatLogLine(label, color, line) {
    return `[${color}m[${label}][0m ${line}`;
}

export function streamLines(stream, onLine) {
    let buf = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
        buf += chunk;
        let newlineIdx;
        while ((newlineIdx = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, newlineIdx);
            buf = buf.slice(newlineIdx + 1);
            onLine(line);
        }
    });
    stream.on('end', () => {
        if (buf.length > 0) onLine(buf);
    });
}

const STDERR_TAIL_LINES = 40;

function pushWithCap(buf, line, cap) {
    buf.push(line);
    if (buf.length > cap) buf.shift();
}

// Runs a cargo binary to completion. Returns { exitCode, resultLine, stderrTail } where
// resultLine is the first stdout line starting with "ZKTLSN_RESULT " (or null) and
// stderrTail is the most recent STDERR_TAIL_LINES lines. stdout/stderr are forwarded
// to the parent console with a [label] prefix.
export function runCargoBinary({ bin, args = [], env = {}, label = bin, color = '36' }) {
    const cargoArgs = ['run', '--release', '--quiet', '--bin', bin];
    if (args.length > 0) {
        cargoArgs.push('--', ...args);
    }

    const child = spawn('cargo', cargoArgs, {
        env: { ...process.env, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
    });

    let resultLine = null;
    const stderrTail = [];
    streamLines(child.stdout, (line) => {
        if (line.startsWith(RESULT_PREFIX) && resultLine === null) {
            resultLine = line;
        }
        process.stdout.write(formatLogLine(label, color, line) + '\n');
    });
    streamLines(child.stderr, (line) => {
        pushWithCap(stderrTail, line, STDERR_TAIL_LINES);
        process.stderr.write(formatLogLine(label, color, line) + '\n');
    });

    return new Promise((resolve, reject) => {
        child.on('error', reject);
        child.on('close', (exitCode) =>
            resolve({ exitCode, resultLine, stderrTail: stderrTail.join('\n') }),
        );
    });
}

// Asserts a cargo binary exited 0. Throws with binary name + exit code + stderr tail.
export function assertCargoExit(label, result) {
    if (result.exitCode !== 0) {
        throw new Error(
            `${label} exited with code ${result.exitCode}\nstderr tail:\n${result.stderrTail}`,
        );
    }
}

// Asserts a cargo binary exited 0 and emitted a parseable ZKTLSN_RESULT line.
// Throws with binary name + exit code + stderr tail on any failure mode.
export function assertCargoResult(label, result) {
    assertCargoExit(label, result);
    if (result.resultLine === null) {
        throw new Error(
            `${label} exited 0 but produced no "${RESULT_PREFIX}<json>" line\nstderr tail:\n${result.stderrTail}`,
        );
    }
    return parseResultLine(result.resultLine);
}

// Spawns a cargo binary and keeps it running. Returns a controller object
// with `kill()` and a `result` promise that resolves when the child exits.
export function spawnCargoBinary({ bin, args = [], env = {}, label = bin, color = '36' }) {
    const cargoArgs = ['run', '--release', '--quiet', '--bin', bin];
    if (args.length > 0) {
        cargoArgs.push('--', ...args);
    }

    const child = spawn('cargo', cargoArgs, {
        env: { ...process.env, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
    });

    streamLines(child.stdout, (line) => {
        process.stdout.write(formatLogLine(label, color, line) + '\n');
    });
    streamLines(child.stderr, (line) => {
        process.stderr.write(formatLogLine(label, color, line) + '\n');
    });

    const result = new Promise((resolve) => {
        child.on('close', (exitCode) => resolve(exitCode));
    });

    return {
        child,
        result,
        kill: () => {
            if (!child.killed) {
                child.kill('SIGTERM');
            }
        },
    };
}

// Spawns an external command (anvil, etc.) with the same logging conventions.
export function spawnProcess({ command, args = [], env = {}, label = command, color = '33' }) {
    const child = spawn(command, args, {
        env: { ...process.env, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    streamLines(child.stdout, (line) => {
        process.stdout.write(formatLogLine(label, color, line) + '\n');
    });
    streamLines(child.stderr, (line) => {
        process.stderr.write(formatLogLine(label, color, line) + '\n');
    });
    const result = new Promise((resolve) => {
        child.on('close', (exitCode) => resolve(exitCode));
    });
    return {
        child,
        result,
        kill: () => {
            if (!child.killed) child.kill('SIGTERM');
        },
    };
}

export function parseResultLine(resultLine) {
    if (!resultLine) {
        throw new Error(`no "${RESULT_PREFIX}<json>" line in binary stdout`);
    }
    return JSON.parse(resultLine.slice(RESULT_PREFIX.length));
}

export function assertEquals(label, expected, actual) {
    const expectedJson = JSON.stringify(expected);
    const actualJson = JSON.stringify(actual);
    if (expectedJson !== actualJson) {
        throw new Error(`${label}: expected ${expectedJson}, got ${actualJson}`);
    }
}

// Polls a TCP endpoint until it accepts a connection or timeoutMs elapses.
export async function waitForTcp(host, port, timeoutMs = 15_000, intervalMs = 200) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            await tryConnect(host, port);
            return;
        } catch {
            await sleep(intervalMs);
        }
    }
    throw new Error(`timed out waiting for ${host}:${port}`);
}

function tryConnect(host, port) {
    return new Promise((resolve, reject) => {
        const socket = net.connect({ host, port }, () => {
            socket.end();
            resolve();
        });
        socket.on('error', reject);
    });
}

export function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

// Polls a UDP endpoint by sending a probe datagram until the kernel stops
// returning ECONNREFUSED (i.e., something is bound). Quinn/QUIC servers don't
// respond to arbitrary datagrams, so we only look for "no ICMP unreachable".
export async function waitForUdp(host, port, timeoutMs = 15_000, intervalMs = 200) {
    const deadline = Date.now() + timeoutMs;
    const probe = Buffer.from([0]);
    while (Date.now() < deadline) {
        try {
            await sendOneDatagram(host, port, probe);
            return;
        } catch {
            await sleep(intervalMs);
        }
    }
    throw new Error(`timed out waiting for UDP ${host}:${port}`);
}

function sendOneDatagram(host, port, payload) {
    return new Promise((resolve, reject) => {
        const family = host.includes(':') ? 'udp6' : 'udp4';
        const socket = dgram.createSocket(family);
        let settled = false;
        const finish = (err) => {
            if (settled) return;
            settled = true;
            socket.close();
            if (err) reject(err);
            else resolve();
        };
        socket.on('error', finish);
        socket.send(payload, port, host, (err) => {
            if (err) return finish(err);
            // Wait briefly for an ECONNREFUSED from the kernel. If none arrives,
            // something is bound to the port and we consider it reachable.
            setTimeout(() => finish(), 100);
        });
    });
}
