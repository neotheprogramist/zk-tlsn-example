// Shared E2E harness used by scripts/e2e-zktls.mjs and scripts/e2e-zkp.mjs.
// Owns: cargo binary spawning + log capture, Playwright bootstrap, headed
// Chromium launch, readiness probing, cleanup/SIGINT handling, structured
// event-line parsing, and assertion helpers over backend tracing + browser
// CDP console output.

import { execFileSync, spawn } from "node:child_process";
import net from "node:net";
import { createRequire } from "node:module";

// ─── Event-line grammar ────────────────────────────────────────────────────
//
//   {rfc3339-ts}  {LEVEL} {event_name} key=value key=value ...
//
// Produced identically by Rust `tracing-subscriber` `compact()` (native +
// wasm) and the JS `event()` helper in `demo/assets/log.mjs`.

const EVENT_HEAD_RE =
  /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(INFO|WARN|ERROR|DEBUG|TRACE)\s+(\S+)(?:\s+(.+))?$/;

function parseFieldValue(raw) {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (raw === "null") return null;
  if (raw === "undefined") return undefined;
  if (raw.startsWith('"')) {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }
  if (/^-?\d+$/.test(raw)) return Number(raw);
  if (/^-?\d+\.\d+(?:[eE][-+]?\d+)?$/.test(raw)) return Number(raw);
  return raw;
}

function splitFieldChunks(rest) {
  const out = [];
  let i = 0;
  while (i < rest.length) {
    while (i < rest.length && rest[i] === " ") i++;
    if (i >= rest.length) break;
    const start = i;
    let inString = false;
    let escape = false;
    while (i < rest.length) {
      const c = rest[i];
      if (inString) {
        if (escape) escape = false;
        else if (c === "\\") escape = true;
        else if (c === '"') inString = false;
      } else if (c === '"') {
        inString = true;
      } else if (c === " ") {
        break;
      }
      i++;
    }
    out.push(rest.slice(start, i));
  }
  return out;
}

export function parseEventLine(text) {
  const m = EVENT_HEAD_RE.exec(text);
  if (!m) return null;
  const [, ts, level, event, rest] = m;
  const fields = {};
  if (rest) {
    for (const chunk of splitFieldChunks(rest)) {
      const eq = chunk.indexOf("=");
      if (eq <= 0) continue;
      fields[chunk.slice(0, eq)] = parseFieldValue(chunk.slice(eq + 1));
    }
  }
  return { ts, level, event, fields };
}

function fieldsMatch(actual, expected) {
  if (!expected) return true;
  for (const [k, v] of Object.entries(expected)) {
    if (typeof v === "function") {
      if (!v(actual[k])) return false;
    } else if (JSON.stringify(actual[k]) !== JSON.stringify(v)) {
      return false;
    }
  }
  return true;
}

// ─── Log accessor ──────────────────────────────────────────────────────────

function tail(items, n, getText) {
  return items
    .slice(-n)
    .map((i) => getText(i))
    .join("\n");
}

function describeEventQuery({ event, fields }) {
  if (!fields) return event;
  return `${event} ${Object.entries(fields)
    .map(([k, v]) => `${k}=${typeof v === "function" ? "<predicate>" : JSON.stringify(v)}`)
    .join(" ")}`;
}

// Returns a structured accessor over a captured line stream. `items` is a
// live array (mutated by the producer). `getText(item)` extracts the line
// payload used for matching. Items are augmented (lazily) with a parsed
// `event` shape `{ts, level, event, fields}` if `getText(item)` matches the
// event grammar; otherwise the parsed shape is `null`.
export function makeLog(name, items, getText = (i) => i.text ?? i) {
  const fail = (msg) =>
    new Error(`${name} log: ${msg}\nlast 30 ${name} lines:\n${tail(items, 30, getText)}`);

  const eventOf = (item) => {
    if (item._parsed === undefined) item._parsed = parseEventLine(getText(item));
    return item._parsed;
  };

  return {
    items,
    name,

    expectEvent(query, label) {
      const idx = items.findIndex((i) => {
        const e = eventOf(i);
        return e && e.event === query.event && fieldsMatch(e.fields, query.fields);
      });
      if (idx === -1) throw fail(`missing event ${label ?? describeEventQuery(query)}`);
      return eventOf(items[idx]);
    },

    expectEventInOrder(queries) {
      let cursor = 0;
      for (const q of queries) {
        let found = -1;
        for (let i = cursor; i < items.length; i++) {
          const e = eventOf(items[i]);
          if (e && e.event === q.event && fieldsMatch(e.fields, q.fields)) {
            found = i;
            break;
          }
        }
        if (found === -1) {
          throw fail(
            `event ${describeEventQuery(q)} not found in order (after position ${cursor})`,
          );
        }
        cursor = found + 1;
      }
    },

    expectEventAbsent(query, label) {
      const idx = items.findIndex((i) => {
        const e = eventOf(i);
        return e && e.event === query.event && fieldsMatch(e.fields, query.fields);
      });
      if (idx !== -1) {
        throw fail(`unexpected event ${label ?? describeEventQuery(query)} at position ${idx}`);
      }
    },

    countEvent(query) {
      return items.filter((i) => {
        const e = eventOf(i);
        return e && e.event === query.event && fieldsMatch(e.fields, query.fields);
      }).length;
    },

    expectEventCount(query, expected, label) {
      const got = this.countEvent(query);
      if (got !== expected) {
        throw fail(
          `expected ${expected} occurrences of ${label ?? describeEventQuery(query)}, got ${got}`,
        );
      }
    },

    findEvents(query) {
      return items
        .map((i) => eventOf(i))
        .filter((e) => e && e.event === query.event && fieldsMatch(e.fields, query.fields));
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

// ANSI escape sequences in the binary's tracing output break event-line
// parsing. The Rust subscriber is now configured `with_ansi(false)`, but keep
// this strip for safety in case anything downstream re-injects colour.
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

// ─── Event-line wait (synchronous predicate-based) ─────────────────────────

// Listens to the page console for an event line whose `event` matches and
// whose parsed fields satisfy `predicate`. Rejects on any matching error
// event or `pageerror`.
export function waitForEvent({
  page,
  event,
  predicate = () => true,
  errorEvents = [],
  timeoutMs = 120_000,
  label = event,
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
    const timer = setTimeout(() => {
      finish(null, new Error(`timed out waiting for event ${label} after ${timeoutMs}ms`));
    }, timeoutMs);
    const onConsole = (msg) => {
      const parsed = parseEventLine(msg.text());
      if (!parsed) return;
      if (parsed.event === event && predicate(parsed.fields)) {
        finish(parsed.fields);
      } else if (errorEvents.includes(parsed.event)) {
        finish(null, new Error(`${parsed.event}: ${JSON.stringify(parsed.fields)}`));
      }
    };
    const onPageError = (err) => {
      finish(null, new Error(`page error: ${err?.stack || err?.message || String(err)}`));
    };
    page.on("console", onConsole);
    page.on("pageerror", onPageError);
  });
}

export async function installPageErrorForwarder(page) {
  await page.addInitScript(() => {
    function emitErr(message) {
      console.error(
        `${new Date().toISOString()}  ERROR runtime.page.error message=${JSON.stringify(message)}`,
      );
    }
    window.addEventListener("error", (e) => emitErr(e.error?.stack || e.message));
    window.addEventListener("unhandledrejection", (e) =>
      emitErr(e.reason?.stack || String(e.reason)),
    );
  });
}
