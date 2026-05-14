// Event handlers for the /vault page. All `addEventListener` wiring lives
// here. Each handler reads from / writes to the shared `ctx` object; pure
// DOM rendering is delegated to vault.render.mjs.

import { event, eventErr } from "./log.mjs";
import { setFieldError } from "./ui/ui.field-error.mjs";
import {
  buildTransfer,
  buildCreateOffer,
  buildSolveOffer,
  buildCancelOffer,
} from "./vault.actions.mjs";
import {
  refresh,
  renderOfferParams,
  renderSolveWitnessFields,
  addTransferRow,
  setActiveTabLabel,
  updateIdentityDisplay,
} from "./vault.render.mjs";

export function attachHandlers(ctx) {
  ctx.onResourceToggle = (uid, checked) => {
    if (checked) ctx.selected.add(uid);
    else ctx.selected.delete(uid);
    refresh(ctx);
  };

  ctx.els.actionTabs.addEventListener("click", (ev) => {
    const tab = ev.target?.dataset?.actionTab;
    if (!tab) return;
    for (const b of ctx.els.actionTabs.querySelectorAll("button")) {
      b.setAttribute("aria-selected", b.dataset.actionTab === tab ? "true" : "false");
    }
    for (const p of document.querySelectorAll("[data-action-panel]")) {
      p.hidden = p.dataset.actionPanel !== tab;
    }
    setActiveTabLabel(ctx, tab);
    refresh(ctx);
  });

  ctx.els.identity.addEventListener("change", () => {
    ctx.activeUsername = ctx.els.identity.value;
    updateIdentityDisplay(ctx);
    refresh(ctx);
  });

  ctx.els.mintKindRegister.addEventListener("click", () => {
    const label = ctx.els.mintKindNew.value.trim();
    if (!label) return;
    if (ctx.store.registerKind(label)) {
      event("vault.kind.registered", { label });
      ctx.els.mintKindNew.value = "";
      refresh(ctx);
      ctx.els.mintKind.value = label;
    }
  });

  ctx.els.mint.addEventListener("click", async () => {
    try {
      const kindLabel = ctx.els.mintKind.value;
      const amount = Number(ctx.els.mintAmount.value);
      const ownerUsername = ctx.els.mintOwner.value;
      const r = await ctx.store.mintErc20({ kindLabel, amount, ownerUsername });
      event("vault.resource.minted", {
        uid: r.uid,
        kind: r.kind,
        amount: r.amount,
        owner: r.ownerUsername,
      });
    } catch (err) {
      eventErr("vault.mint.failed", { message: err.message });
    }
  });

  ctx.els.reset.addEventListener("click", () => {
    ctx.store.reset();
    ctx.scheduler.clearAll();
    ctx.selected.clear();
    event("vault.reset", {});
  });

  ctx.els.offerChallenge.addEventListener("change", () => renderOfferParams(ctx));
  ctx.els.solveOfferSelect.addEventListener("change", () => renderSolveWitnessFields(ctx));

  ctx.els.transferAddOutput.addEventListener("click", () => addTransferRow(ctx));

  ctx.els.filterKind.addEventListener("change", () => refresh(ctx));
  ctx.els.filterMine.addEventListener("change", () => refresh(ctx));

  ctx.els.transferSubmit.addEventListener("click", () => onTransferSubmit(ctx));
  ctx.els.offerCreateSubmit.addEventListener("click", () => onCreateOfferSubmit(ctx));
  ctx.els.solveSubmit.addEventListener("click", () => onSolveSubmit(ctx));
  ctx.els.cancelSubmit.addEventListener("click", () => onCancelSubmit(ctx));
}

function selectedRecords(ctx) {
  const snap = ctx.store.snapshot();
  return snap.resources.filter((r) => ctx.selected.has(r.uid));
}

async function runAction(ctx, plan) {
  const knownStates = new WeakMap();
  ctx.store.setPendingDelta(1);
  // The scheduler invokes onUpdate synchronously inside submitAction (before
  // the outer `await` resolves), so the closure cannot read the destructured
  // `state` binding — it's still in TDZ. Use the actionState parameter that
  // the scheduler already passes in.
  const { ok, state } = await ctx.scheduler.submitAction(plan, {
    onUpdate: (actionState) => {
      for (const n of actionState.nodes) {
        if (knownStates.get(n) === n.state) continue;
        knownStates.set(n, n.state);
        event("vault.action.node", {
          action_id: actionState.actionId,
          flow: actionState.flow,
          air: n.air,
          node_id: n.id,
          state: n.state,
        });
      }
    },
  });
  ctx.store.setPendingDelta(-1);
  if (ok) {
    for (let i = 0; i < plan.consumedRecords.length; i++) {
      const r = plan.consumedRecords[i];
      ctx.store.consume(r.uid, plan.nullifiersHex[i]);
    }
    for (const r of plan.createdRecords) {
      ctx.store.create(r);
    }
    ctx.store.setCompleted(true);
    ctx.store.recordAction({
      actionId: plan.actionId,
      flow: plan.flow,
      success: true,
      durationMs: state.finishedAt - state.startedAt,
    });
    ctx.selected.clear();
  } else {
    ctx.store.setCompleted(false);
    ctx.store.recordAction({
      actionId: plan.actionId,
      flow: plan.flow,
      success: false,
      error: state.error,
      durationMs: state.finishedAt - state.startedAt,
    });
  }
  refresh(ctx);
}

async function onTransferSubmit(ctx) {
  ctx.els.transferError.textContent = "";
  setFieldError(ctx.els.transferFeeResource, null);
  try {
    const inputs = selectedRecords(ctx).filter((r) => r.kindFamily === "erc20");
    if (inputs.length === 0) {
      throw new Error("select at least one erc20 resource as input");
    }
    const outputs = Array.from(
      ctx.els.transferOutputs.querySelectorAll('[data-role="transfer-output-row"]'),
    ).map((row) => ({
      recipientUsername: row.querySelector('[data-role="transfer-output-recipient"]').value,
      amount: Number(row.querySelector('[data-role="transfer-output-amount"]').value),
    }));
    const feeUid = ctx.els.transferFeeResource.value;
    if (!feeUid) {
      setFieldError(ctx.els.transferFeeResource, "choose a USDC resource");
      throw new Error("choose a USDC resource for the fee");
    }
    const plan = await buildTransfer({
      store: ctx.store,
      activeUsername: ctx.activeUsername,
      inputs,
      outputs,
      feeRecord: ctx.store.getResource(feeUid),
    });
    event("vault.action.submit", { flow: "transfer", action_id: plan.actionId });
    await runAction(ctx, plan);
  } catch (err) {
    ctx.els.transferError.textContent = err.message;
    eventErr("vault.action.submit.failed", { flow: "transfer", message: err.message });
  }
}

async function onCreateOfferSubmit(ctx) {
  ctx.els.offerCreateError.textContent = "";
  setFieldError(ctx.els.offerFeeResource, null);
  try {
    const inputs = selectedRecords(ctx).filter((r) => r.kindFamily === "erc20");
    if (inputs.length === 0) {
      throw new Error("select at least one erc20 resource to lock");
    }
    const challengeParams = {};
    for (const inp of ctx.els.offerChallengeParams.querySelectorAll(
      '[data-role="offer-challenge-param"]',
    )) {
      challengeParams[inp.dataset.fieldName] = inp.value;
    }
    const feeUid = ctx.els.offerFeeResource.value;
    if (!feeUid) {
      setFieldError(ctx.els.offerFeeResource, "choose a USDC resource");
      throw new Error("choose a USDC resource for the fee");
    }
    const plan = await buildCreateOffer({
      store: ctx.store,
      activeUsername: ctx.activeUsername,
      inputs,
      lockedAmount: Number(ctx.els.offerLockedAmount.value),
      refundAmount: Number(ctx.els.offerRefundAmount.value),
      challengeId: ctx.els.offerChallenge.value,
      challengeParams,
      feeRecord: ctx.store.getResource(feeUid),
    });
    event("vault.action.submit", { flow: "create_offer", action_id: plan.actionId });
    await runAction(ctx, plan);
  } catch (err) {
    ctx.els.offerCreateError.textContent = err.message;
    eventErr("vault.action.submit.failed", { flow: "create_offer", message: err.message });
  }
}

async function onSolveSubmit(ctx) {
  ctx.els.solveError.textContent = "";
  setFieldError(ctx.els.solveOfferSelect, null);
  setFieldError(ctx.els.solveFeeResource, null);
  try {
    const uid = ctx.els.solveOfferSelect.value;
    if (!uid) {
      setFieldError(ctx.els.solveOfferSelect, "pick an offer");
      throw new Error("choose an offer");
    }
    const witness = {};
    for (const inp of ctx.els.solveWitnessFields.querySelectorAll(
      '[data-role="solve-witness-input"]',
    )) {
      witness[inp.dataset.fieldName] = inp.type === "number" ? Number(inp.value) : inp.value;
    }
    const feeUid = ctx.els.solveFeeResource.value;
    if (!feeUid) {
      setFieldError(ctx.els.solveFeeResource, "choose a USDC resource");
      throw new Error("choose a USDC resource for the fee");
    }
    const plan = await buildSolveOffer({
      store: ctx.store,
      activeUsername: ctx.activeUsername,
      offerRecord: ctx.store.getResource(uid),
      witness,
      feeRecord: ctx.store.getResource(feeUid),
    });
    event("vault.action.submit", { flow: "solve_offer", action_id: plan.actionId });
    await runAction(ctx, plan);
  } catch (err) {
    ctx.els.solveError.textContent = err.message;
    eventErr("vault.action.submit.failed", { flow: "solve_offer", message: err.message });
  }
}

async function onCancelSubmit(ctx) {
  ctx.els.cancelError.textContent = "";
  setFieldError(ctx.els.cancelOfferSelect, null);
  setFieldError(ctx.els.cancelFeeResource, null);
  try {
    const uid = ctx.els.cancelOfferSelect.value;
    if (!uid) {
      setFieldError(ctx.els.cancelOfferSelect, "pick an offer");
      throw new Error("choose an offer");
    }
    const feeUid = ctx.els.cancelFeeResource.value;
    if (!feeUid) {
      setFieldError(ctx.els.cancelFeeResource, "choose a USDC resource");
      throw new Error("choose a USDC resource for the fee");
    }
    const plan = await buildCancelOffer({
      store: ctx.store,
      activeUsername: ctx.activeUsername,
      offerRecord: ctx.store.getResource(uid),
      feeRecord: ctx.store.getResource(feeUid),
    });
    event("vault.action.submit", { flow: "cancel_offer", action_id: plan.actionId });
    await runAction(ctx, plan);
  } catch (err) {
    ctx.els.cancelError.textContent = err.message;
    eventErr("vault.action.submit.failed", { flow: "cancel_offer", message: err.message });
  }
}
