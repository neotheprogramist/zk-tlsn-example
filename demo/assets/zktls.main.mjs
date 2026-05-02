import { event, eventErr } from "./log.mjs";
import { installPageErrorForwarders, startWorker } from "./flow.mjs";

const root = document.querySelector('[data-role="prove-root"]');
const btn = document.querySelector('[data-role="start"]');

installPageErrorForwarders();

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
  event("zktls.action.start.click");
  const worker = startWorker("/assets/zktls.worker.mjs", (msg) => {
    if (msg.kind === "result") {
      event("zktls.notarize.done", msg.result);
      worker.terminate();
      btn.disabled = false;
    } else if (msg.kind === "error") {
      eventErr("zktls.notarize.failed", { message: msg.message });
      worker.terminate();
      btn.disabled = false;
    }
  });
  worker.postMessage({ kind: "start", config: readConfig() });
});
