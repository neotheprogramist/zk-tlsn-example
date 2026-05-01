// Shared worker scaffolding for the /zktls and /zkp flows.
// - startWorker / installPageErrorForwarders run on the main thread.
// - installWorkerErrorForwarder runs inside a worker.
// - appendLog / fmtMs / fmtKB are pure formatters.

export function appendLog(el, line) {
  const ts = new Date().toISOString().split("T")[1].replace("Z", "");
  el.textContent += `[${ts}] ${line}\n`;
  el.scrollTop = el.scrollHeight;
  console.log(`[${ts}] ${line}`);
}

export function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms.toFixed(0)} ms`;
}

export function fmtKB(bytes) {
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function detail(ev) {
  return [
    ev.message || null,
    ev.filename ? `at ${ev.filename}:${ev.lineno}:${ev.colno}` : null,
    ev.error ? ev.error.stack || ev.error.message || String(ev.error) : null,
  ]
    .filter(Boolean)
    .join(" | ");
}

export function startWorker(url, onMessage) {
  const worker = new Worker(url, { type: "module" });
  worker.addEventListener("message", (ev) => onMessage(ev.data));
  worker.addEventListener("error", (ev) => {
    ev.preventDefault?.();
    onMessage({ kind: "error", message: "worker error: " + (detail(ev) || "(no detail)") });
  });
  worker.addEventListener("messageerror", (ev) => {
    onMessage({
      kind: "error",
      message: "worker messageerror: " + (ev.data ? JSON.stringify(ev.data) : "unknown"),
    });
  });
  return worker;
}

export function installPageErrorForwarders(prefix) {
  window.addEventListener("error", (e) => {
    console.error(`${prefix} ` + (e.error?.stack || e.message));
  });
  window.addEventListener("unhandledrejection", (e) => {
    console.error(`${prefix} ` + (e.reason?.stack || e.reason));
  });
}

export function installWorkerErrorForwarder() {
  self.addEventListener("error", (ev) => {
    self.postMessage({
      kind: "error",
      message: "worker self error: " + (detail(ev) || "(no detail)"),
    });
  });
  self.addEventListener("unhandledrejection", (ev) => {
    const r = ev.reason;
    self.postMessage({
      kind: "error",
      message: "worker unhandledrejection: " + (r?.stack || r?.message || String(r)),
    });
  });
}
