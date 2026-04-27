const root = document.querySelector('[data-role="prove-root"]');
const logEl = document.querySelector('[data-role="log"]');
const btn = document.querySelector('[data-role="start"]');

function appendLog(line) {
  const ts = new Date().toISOString();
  logEl.textContent += `[${ts}] ${line}\n`;
  console.log(`[${ts}] ${line}`);
}

function readConfig() {
  const d = root.dataset;
  return {
    connectUrl: new URL("/connect", location.origin).toString(),
    certHashHex: d.certHash,
    serverHost: d.serverHost,
    serverPort: Number(d.serverPort),
    serverName: d.serverName,
    serverCertDerHex: d.serverCertDerHex,
    fromUser: d.fromUser,
    toUser: d.toUser,
    transferAmount: Number(d.transferAmount),
    txId: Number(d.txId),
  };
}

btn.addEventListener("click", () => {
  btn.disabled = true;
  appendLog("spawning prover worker");
  const worker = new Worker("/assets/prove.worker.js", { type: "module" });
  worker.addEventListener("message", (ev) => {
    const msg = ev.data;
    if (msg.kind === "log") {
      appendLog(msg.line);
    } else if (msg.kind === "result") {
      appendLog("ZKTLSN_RESULT " + JSON.stringify(msg.result));
      console.log("ZKTLSN_RESULT " + JSON.stringify(msg.result));
      worker.terminate();
      btn.disabled = false;
    } else if (msg.kind === "error") {
      appendLog("ZKTLSN_ERROR " + msg.message);
      console.error("ZKTLSN_ERROR " + msg.message);
      worker.terminate();
      btn.disabled = false;
    }
  });
  worker.addEventListener("error", (ev) => {
    ev.preventDefault?.();
    const detail = [
      ev.message || null,
      ev.filename ? `at ${ev.filename}:${ev.lineno}:${ev.colno}` : null,
      ev.error ? ev.error.stack || ev.error.message || String(ev.error) : null,
    ]
      .filter(Boolean)
      .join(" | ");
    const message = detail || "(no detail on worker ErrorEvent)";
    appendLog("ZKTLSN_ERROR worker error: " + message);
    console.error("ZKTLSN_ERROR worker error: " + message);
    btn.disabled = false;
  });
  worker.addEventListener("messageerror", (ev) => {
    appendLog(
      "ZKTLSN_ERROR worker messageerror: " + (ev.data ? JSON.stringify(ev.data) : "unknown"),
    );
    console.error("ZKTLSN_ERROR worker messageerror");
  });
  worker.postMessage({ kind: "start", config: readConfig() });
});

// Surface page-level uncaught errors to the harness's console-line watcher.
window.addEventListener("error", (e) => {
  console.error("ZKTLSN_ERROR " + (e.error?.stack || e.message));
});
window.addEventListener("unhandledrejection", (e) => {
  console.error("ZKTLSN_ERROR " + (e.reason?.stack || e.reason));
});
