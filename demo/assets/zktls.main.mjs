import { appendLog, installPageErrorForwarders, startWorker } from "./flow.mjs";

const root = document.querySelector('[data-role="prove-root"]');
const log = document.querySelector('[data-role="log"]');
const btn = document.querySelector('[data-role="start"]');

installPageErrorForwarders("ZKTLS_ERROR");

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
  appendLog(log, "spawning prover worker");
  const worker = startWorker("/assets/zktls.worker.mjs", (msg) => {
    if (msg.kind === "log") {
      appendLog(log, msg.line);
    } else if (msg.kind === "result") {
      appendLog(log, "ZKTLS_RESULT " + JSON.stringify(msg.result));
      console.log("ZKTLS_RESULT " + JSON.stringify(msg.result));
      worker.terminate();
      btn.disabled = false;
    } else if (msg.kind === "error") {
      appendLog(log, "ZKTLS_ERROR " + msg.message);
      console.error("ZKTLS_ERROR " + msg.message);
      worker.terminate();
      btn.disabled = false;
    }
  });
  worker.postMessage({ kind: "start", config: readConfig() });
});
