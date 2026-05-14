// /vault entry point. Discovers DOM, creates the store + scheduler, builds
// the shared ctx, attaches handlers, wires the visualization + log, and
// boots the worker pool. All rendering logic lives in vault.render.mjs;
// all event handlers live in vault.handlers.mjs.

import { event, eventErr } from "./log.mjs";
import { installPageErrorForwarders } from "./flow.mjs";
import { createStore } from "./vault.state.mjs";
import { createScheduler } from "./vault.scheduler.mjs";
import { attachVisualization } from "./vault.viz.mjs";
import { createLog } from "./ui/ui.log.mjs";
import { discoverDom } from "./vault.dom.mjs";
import { refresh, updateIdentityDisplay } from "./vault.render.mjs";
import { attachHandlers } from "./vault.handlers.mjs";

function decidePoolSize() {
  const override = new URLSearchParams(window.location.search).get("pool");
  if (override !== null) {
    const n = Number.parseInt(override, 10);
    if (!Number.isInteger(n) || n < 1) {
      throw new Error(`?pool=${override} is not a positive integer`);
    }
    return n;
  }
  const detected = navigator.hardwareConcurrency;
  if (!Number.isInteger(detected) || detected < 1) {
    throw new Error("navigator.hardwareConcurrency unavailable; specify ?pool=N");
  }
  return detected;
}

const IDENTITIES = ["alice", "bob", "charlie"];

const els = discoverDom();
const store = createStore();
const poolSize = decidePoolSize();
const scheduler = createScheduler({
  workerScriptUrl: "/assets/vault.worker.mjs",
  poolSize,
});

const ctx = {
  els,
  store,
  scheduler,
  selected: new Set(),
  activeUsername: "alice",
  booted: false,
  poolSize,
  identities: IDENTITIES,
};

installPageErrorForwarders();
attachVisualization(els.viz, scheduler);
createLog(els.log);
attachHandlers(ctx);

async function setupIdentities() {
  els.identity.replaceChildren();
  els.mintOwner.replaceChildren();
  for (const u of IDENTITIES) {
    await store.addIdentity(u);
    for (const sel of [els.identity, els.mintOwner]) {
      const opt = document.createElement("option");
      opt.value = u;
      opt.textContent = u;
      sel.appendChild(opt);
    }
  }
  els.identity.value = ctx.activeUsername;
  els.mintOwner.value = ctx.activeUsername;
  updateIdentityDisplay(ctx);
}

store.subscribe(() => refresh(ctx));
scheduler.subscribe(() => {});

event("vault.page.loading", { pool_size: poolSize });
await setupIdentities();
refresh(ctx);
scheduler
  .init()
  .then(() => {
    ctx.booted = true;
    event("vault.scheduler.booted", { pool_size: poolSize });
    refresh(ctx);
  })
  .catch((err) => {
    eventErr("vault.scheduler.boot.failed", { message: err.message });
  });
