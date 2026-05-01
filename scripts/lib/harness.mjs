// Shared E2E harness used by scripts/e2e-zktls.mjs and scripts/e2e-zkp.mjs.
// Owns: cargo binary spawning + log capture, Playwright bootstrap, headed
// Chromium launch, readiness probing, cleanup/SIGINT handling, console-line
// waiting, structured assertion helpers over backend tracing and browser
// CDP console output.

import { execFileSync, spawn } from "node:child_process";
import net from "node:net";
import { createRequire } from "node:module";

// ─── Pattern matching + structured log ─────────────────────────────────────

function lineMatches(text, pattern) {
  if (typeof pattern === "string") return text.includes(pattern);
  if (pattern instanceof RegExp) return pattern.test(text);
  throw new Error(`unsupported pattern type: ${typeof pattern}`);
}

function patternLabel(pattern) {
  return pattern instanceof RegExp ? pattern.source : pattern;
}

function tail(items, n, getText) {
  return items
    .slice(-n)
    .map((i) => getText(i))
    .join("\n");
}

// Returns a structured accessor over a captured line stream. `items` is a
// live array (mutated by the producer). `getText(item)` extracts the line
// payload used for matching.
export function makeLog(name, items, getText = (i) => i.text ?? i) {
  const fail = (msg) =>
    new Error(`${name} log: ${msg}\nlast 30 ${name} lines:\n${tail(items, 30, getText)}`);
  const norm = (p) => (Array.isArray(p) ? p : [p, patternLabel(p)]);

  return {
    items,
    name,

    expect(pattern, label) {
      const idx = items.findIndex((i) => lineMatches(getText(i), pattern));
      if (idx === -1) throw fail(`missing ${label ?? patternLabel(pattern)}`);
      return items[idx];
    },

    expectAll(patterns) {
      for (const p of patterns) {
        const [pat, lbl] = norm(p);
        this.expect(pat, lbl);
      }
    },

    expectInOrder(patterns) {
      let cursor = 0;
      for (const p of patterns) {
        const [pat, lbl] = norm(p);
        let found = -1;
        for (let i = cursor; i < items.length; i++) {
          if (lineMatches(getText(items[i]), pat)) {
            found = i;
            break;
          }
        }
        if (found === -1) {
          throw fail(`${lbl} not found in order (after position ${cursor})`);
        }
        cursor = found + 1;
      }
    },

    expectAbsent(pattern, label) {
      const idx = items.findIndex((i) => lineMatches(getText(i), pattern));
      if (idx !== -1) {
        throw fail(
          `unexpected ${label ?? patternLabel(pattern)} at position ${idx}: ${getText(items[idx])}`,
        );
      }
    },

    count(pattern) {
      return items.filter((i) => lineMatches(getText(i), pattern)).length;
    },

    expectCount(pattern, expected, label) {
      const got = this.count(pattern);
      if (got !== expected) {
        throw fail(
          `expected ${expected} occurrences of ${label ?? patternLabel(pattern)}, got ${got}`,
        );
      }
    },

    expectAtLeast(pattern, min, label) {
      const got = this.count(pattern);
      if (got < min) {
        throw fail(`expected ≥${min} occurrences of ${label ?? patternLabel(pattern)}, got ${got}`);
      }
    },

    // Returns the matched line text (whole captured payload), or throws.
    findText(pattern, label) {
      return getText(this.expect(pattern, label));
    },
  };
}

// ─── Logging (live forwarding) ─────────────────────────────────────────────

function streamLines(stream, onLine) {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      onLine(buf.slice(0, idx));
      buf = buf.slice(idx + 1);
    }
  });
  stream.on("end", () => {
    if (buf.length > 0) onLine(buf);
  });
}

function formatLogLine(label, color, line) {
  return `[${color}m[${label}][0m ${line}`;
}

// ANSI escape sequences in the binary's tracing output break substring/regex
// matching. Strip them for the captured buffer; the live forwarded line keeps
// them so the terminal stays coloured.
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[[0-9;]*m/g;
const stripAnsi = (s) => s.replace(ANSI_RE, "");

// ─── Cargo binary spawn ────────────────────────────────────────────────────

export function spawnCargoBinary({ bin, args = [], env = {}, label = bin, color = "36" }) {
  const cargoArgs = ["run", "--release", "--quiet", "--bin", bin];
  if (args.length > 0) cargoArgs.push("--", ...args);
  const child = spawn("cargo", cargoArgs, {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines = [];
  streamLines(child.stdout, (line) => {
    lines.push({ stream: "stdout", text: stripAnsi(line) });
    process.stdout.write(formatLogLine(label, color, line) + "\n");
  });
  streamLines(child.stderr, (line) => {
    lines.push({ stream: "stderr", text: stripAnsi(line) });
    process.stderr.write(formatLogLine(label, color, line) + "\n");
  });
  const result = new Promise((resolve) => child.on("close", resolve));
  return {
    child,
    result,
    lines,
    kill: () => {
      if (!child.killed) child.kill("SIGTERM");
    },
  };
}

// ─── Network readiness ─────────────────────────────────────────────────────

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForTcp(host, port, timeoutMs = 15_000, intervalMs = 200) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect({ host, port }, () => {
          socket.end();
          resolve();
        });
        socket.on("error", reject);
      });
      return;
    } catch {
      await sleep(intervalMs);
    }
  }
  throw new Error(`timed out waiting for ${host}:${port}`);
}

// ─── Assertions ────────────────────────────────────────────────────────────

export function assertEquals(label, expected, actual) {
  const a = JSON.stringify(expected);
  const b = JSON.stringify(actual);
  if (a !== b) throw new Error(`${label}: expected ${a}, got ${b}`);
}

export function assertInRange(label, value, min, max) {
  if (typeof value !== "number" || Number.isNaN(value) || value < min || value > max) {
    throw new Error(`${label}: ${value} not in [${min}, ${max}]`);
  }
}

// ─── Cleanup + SIGINT ──────────────────────────────────────────────────────

const cleanups = [];

export function registerCleanup(handle) {
  cleanups.push(handle);
}

export async function runCleanup() {
  for (const handle of cleanups.reverse()) {
    try {
      await handle.stop();
    } catch (error) {
      console.error(`cleanup error: ${error.message}`);
    }
  }
}

process.on("SIGINT", async () => {
  await runCleanup();
  process.exit(130);
});

// ─── Playwright ────────────────────────────────────────────────────────────

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    const binPath = execFileSync(
      "npx",
      ["--yes", "--package=playwright", "--", "which", "playwright"],
      { encoding: "utf8" },
    ).trim();
    const req = createRequire(binPath);
    return await import(req.resolve("playwright"));
  }
}

export async function launchHeadedChromium() {
  const mod = await loadPlaywright();
  const chromium = mod.chromium ?? mod.default?.chromium;
  if (!chromium) throw new Error("failed to resolve playwright.chromium");
  const browser = await chromium.launch({
    headless: false,
    args: ["--ignore-certificate-errors", "--enable-features=WebTransport,SharedArrayBuffer"],
  });
  registerCleanup({ stop: async () => browser.close() });
  return browser;
}

// ─── Demo binary lifecycle ─────────────────────────────────────────────────

export const SERVER_PORT = 8443;
export const SERVICE_HOST = "127.0.0.1";
export const SERVICE_PORT = 8444;
export const SERVER_NAME = "localhost";
export const FROM_USER = "alice";
export const TO_USER = "treasury";
export const TRANSFER_AMOUNT = 25;

export const SERVICE_ADDR = `${SERVICE_HOST}:${SERVICE_PORT}`;

export const sharedDemoEnv = {
  ZKTLSN_SERVER_ADDR: `127.0.0.1:${SERVER_PORT}`,
  ZKTLSN_SERVER_NAME: SERVER_NAME,
  ZKTLSN_SERVER_CERT_PATH: ".data/server/cert.pem",
  ZKTLSN_SERVER_KEY_PATH: ".data/server/key.pem",
  ZKTLSN_SERVER_LISTEN_ADDR: `127.0.0.1:${SERVER_PORT}`,
  ZKTLSN_SERVICE_LISTEN_ADDR: SERVICE_ADDR,
  ZKTLSN_SERVICE_CERT_DIR: ".data/service",
  ZKTLSN_FROM_USER: FROM_USER,
  ZKTLSN_TO_USER: TO_USER,
  ZKTLSN_TRANSFER_AMOUNT: String(TRANSFER_AMOUNT),
};

export async function startDemoBinary() {
  console.log("[harness] starting zktlsn (ledger + service)...");
  const proc = spawnCargoBinary({
    bin: "zktlsn",
    env: sharedDemoEnv,
    label: "zktlsn",
    color: "32",
  });
  registerCleanup({
    stop: async () => {
      proc.kill();
      await Promise.race([proc.result, sleep(2_000)]);
    },
  });
  await waitForTcp("127.0.0.1", SERVER_PORT);
  await waitForTcp(SERVICE_HOST, SERVICE_PORT);
  console.log("[harness] zktlsn ready.");
  return {
    proc,
    log: makeLog("backend", proc.lines, (l) => l.text),
  };
}

// ─── Browser CDP capture ───────────────────────────────────────────────────

// Captures every console.* message, every uncaught page error, and every
// failed network request from the page's DevTools-Protocol-backed event
// stream. Returns structured logs + helpers. Live-prints when CHROME_CONSOLE
// is set so failures are easier to debug.
export function setupBrowserCapture(page) {
  const consoleLines = [];
  const requestFailures = [];

  page.on("console", (msg) => {
    consoleLines.push({ type: msg.type(), text: msg.text() });
    if (process.env.CHROME_CONSOLE) {
      process.stderr.write(`\x1b[35m[console:${msg.type()}]\x1b[0m ${msg.text()}\n`);
    }
  });
  page.on("pageerror", (err) => {
    consoleLines.push({
      type: "pageerror",
      text: err?.stack || err?.message || String(err),
    });
  });
  page.on("requestfailed", (req) => {
    requestFailures.push({
      url: req.url(),
      method: req.method(),
      failure: req.failure()?.errorText ?? "unknown",
    });
  });

  return {
    console: makeLog("browser console", consoleLines, (l) => l.text),
    requestFailures,
    expectNoRequestFailures() {
      if (requestFailures.length === 0) return;
      const dump = requestFailures.map((f) => `${f.method} ${f.url}: ${f.failure}`).join("\n");
      throw new Error(`browser had ${requestFailures.length} failed network requests:\n${dump}`);
    },
  };
}

// ─── Console-line capture (synchronous predicate-based wait) ───────────────

// Listens to page console for a `<resultPrefix> <json>` line where the parsed
// JSON satisfies `predicate`. Rejects on `<errorPrefix> ...` or `pageerror`.
export function waitForConsoleResult({
  page,
  resultPrefix,
  errorPrefix,
  predicate = () => true,
  timeoutMs = 120_000,
  label = resultPrefix,
}) {
  return new Promise((resolve, reject) => {
    let finished = false;
    const finish = (value, err) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      page.off("console", onConsole);
      page.off("pageerror", onPageError);
      if (err) reject(err);
      else resolve(value);
    };
    const timer = setTimeout(async () => {
      const tail = await page
        .evaluate(() => document.querySelector('[data-role="log"]')?.textContent ?? "")
        .catch(() => "");
      finish(
        null,
        new Error(
          `timed out waiting for ${label} after ${timeoutMs}ms\npage log tail:\n` +
            tail.trim().split("\n").slice(-15).join("\n"),
        ),
      );
    }, timeoutMs);
    const onConsole = (msg) => {
      const text = msg.text();
      if (text.startsWith(resultPrefix + " ")) {
        try {
          const parsed = JSON.parse(text.slice(resultPrefix.length + 1));
          if (predicate(parsed)) finish(parsed);
        } catch {
          // Ignore malformed lines and keep listening.
        }
      } else if (text.startsWith(errorPrefix + " ")) {
        finish(null, new Error(text));
      }
    };
    const onPageError = (err) => {
      finish(null, new Error(`page error: ${err?.stack || err?.message || String(err)}`));
    };
    page.on("console", onConsole);
    page.on("pageerror", onPageError);
  });
}

export async function installPageErrorForwarder(page, errorPrefix) {
  await page.addInitScript((prefix) => {
    window.addEventListener("error", (e) =>
      console.error(`${prefix} ` + (e.error?.stack || e.message)),
    );
    window.addEventListener("unhandledrejection", (e) =>
      console.error(`${prefix} ` + (e.reason?.stack || e.reason)),
    );
  }, errorPrefix);
}
