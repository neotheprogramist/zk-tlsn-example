// Pure render functions for the /vault page. Each takes the shared `ctx`
// object ({ els, store, selected, activeUsername, identities, ... }) and
// mutates the DOM under specific data-role anchors. No event handlers
// live here; see vault.handlers.mjs.

import { listChallenges, getChallenge } from "./vault.challenges.mjs";

export function refresh(ctx) {
  rebuildMintKindOptions(ctx);
  renderTransferOutputs(ctx);
  rebuildFeeDropdown(ctx, ctx.els.transferFeeResource);
  rebuildFeeDropdown(ctx, ctx.els.offerFeeResource);
  rebuildFeeDropdown(ctx, ctx.els.solveFeeResource);
  rebuildFeeDropdown(ctx, ctx.els.cancelFeeResource);
  rebuildOfferDropdowns(ctx);
  renderChallengeRegistry(ctx);
  renderResources(ctx);
  updateIdentityDisplay(ctx);
  updateSubmitButtons(ctx);
  ctx.els.pool.textContent = ctx.booted ? `${ctx.poolSize} workers ready` : "— (booting)";
}

export function updateIdentityDisplay(ctx) {
  const snap = ctx.store.snapshot();
  const id = snap.identities.find((i) => i.username === ctx.activeUsername);
  if (!id) return;
  ctx.els.identityNk.textContent = id.nkHex.slice(0, 12) + "…";
  ctx.els.identitySalt.textContent = id.userkeySaltHex.slice(0, 12) + "…";
}

export function rebuildMintKindOptions(ctx) {
  const snap = ctx.store.snapshot();
  const prevMint = ctx.els.mintKind.value;
  const prevFilter = ctx.els.filterKind.value;
  ctx.els.mintKind.replaceChildren();
  ctx.els.filterKind.replaceChildren();
  const allOpt = document.createElement("option");
  allOpt.value = "";
  allOpt.textContent = "all kinds";
  ctx.els.filterKind.appendChild(allOpt);
  for (const k of snap.registeredKinds) {
    for (const sel of [ctx.els.mintKind, ctx.els.filterKind]) {
      const opt = document.createElement("option");
      opt.value = k;
      opt.textContent = k;
      sel.appendChild(opt);
    }
  }
  if (Array.from(ctx.els.mintKind.options).some((o) => o.value === prevMint)) {
    ctx.els.mintKind.value = prevMint;
  }
  if (Array.from(ctx.els.filterKind.options).some((o) => o.value === prevFilter)) {
    ctx.els.filterKind.value = prevFilter;
  }
}

export function renderResources(ctx) {
  const snap = ctx.store.snapshot();
  const kindFilter = ctx.els.filterKind.value || null;
  const mineOnly = ctx.els.filterMine.checked;
  const visible = snap.resources.filter((r) => {
    if (kindFilter && r.kind !== kindFilter) return false;
    if (mineOnly && r.ownerUsername !== ctx.activeUsername) return false;
    return true;
  });

  ctx.els.resources.replaceChildren();
  for (const r of visible) {
    ctx.els.resources.appendChild(renderResourceRow(ctx, r));
  }
  ctx.els.resourcesSummary.textContent = `${visible.length} visible · ${snap.resources.length} total`;
  ctx.els.liveCount.textContent = String(snap.resources.length);
  ctx.els.actionsDone.textContent = String(snap.completedActions);
  ctx.els.actionsFailed.textContent = String(snap.failedActions);
  ctx.els.actionsPending.textContent = String(snap.pendingActions);
  if (ctx.els.nfCount) {
    ctx.els.nfCount.textContent = String(snap.nullifiers.length);
    ctx.els.nfCount.dataset.count = String(snap.nullifiers.length);
  }
}

function renderResourceRow(ctx, r) {
  const row = document.createElement("div");
  row.className = "vault-resource-row";
  row.dataset.role = "resource-row";
  row.dataset.uid = r.uid;
  row.dataset.kind = r.kind;
  row.dataset.kindFamily = r.kindFamily;
  if (r.ownerUsername) row.dataset.owner = r.ownerUsername;
  else row.dataset.ownerKindFamily = r.ownerKindFamily;
  if (r.amount != null) row.dataset.amount = String(r.amount);
  if (r.offerState) {
    row.dataset.offerInstance = r.offerState.instanceSaltHex;
    row.dataset.offerChallenge = r.offerState.challengeId;
    row.dataset.offerLockedAmount = String(r.offerState.lockedAmount);
    row.dataset.offerCreator = r.offerState.creatorUsername;
  }
  if (ctx.selected.has(r.uid)) row.classList.add("selected");

  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.dataset.role = "resource-select";
  cb.checked = ctx.selected.has(r.uid);
  cb.addEventListener("change", () => ctx.onResourceToggle(r.uid, cb.checked));

  const body = document.createElement("div");
  body.className = "vault-resource-row__body";

  const summary = document.createElement("div");
  summary.className = "vault-resource-row__summary";

  const meta = document.createElement("div");
  meta.className = "vault-resource-row__meta";

  if (r.kindFamily === "erc20") {
    summary.textContent = `${r.uid}  ${r.kind}  ${r.amount}`;
    meta.textContent = `owner=${r.ownerUsername ?? r.ownerKindFamily}  cm=${r.commitmentHex.slice(0, 10)}…`;
  } else {
    const ofs = r.offerState;
    summary.textContent = `${r.uid}  offer{${ofs.challengeId} · ${ofs.lockedAmount} ${ofs.lockedKindLabel}}`;
    meta.textContent = `creator=${ofs.creatorUsername}  instance=${ofs.instanceSaltHex.slice(0, 10)}…`;
  }
  body.append(summary, meta);

  const chip = document.createElement("div");
  chip.className = "vault-resource-row__chip";
  chip.textContent = r.kindFamily === "offer" ? "offer" : r.kind;

  row.append(cb, body, chip);
  return row;
}

export function rebuildFeeDropdown(ctx, sel) {
  const snap = ctx.store.snapshot();
  const prev = sel.value;
  sel.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "— choose USDC resource —";
  sel.appendChild(placeholder);
  const candidates = snap.resources.filter(
    (r) => r.kind === ctx.store.CANONICAL_USDC_LABEL && r.ownerUsername === ctx.activeUsername,
  );
  for (const r of candidates) {
    const opt = document.createElement("option");
    opt.value = r.uid;
    opt.textContent = `${r.uid}  ${r.amount} USDC`;
    sel.appendChild(opt);
  }
  if (Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
}

export function rebuildOfferDropdowns(ctx) {
  const snap = ctx.store.snapshot();
  const offers = snap.resources.filter((r) => r.kindFamily === "offer");
  for (const sel of [ctx.els.solveOfferSelect, ctx.els.cancelOfferSelect]) {
    const prev = sel.value;
    sel.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "— choose offer —";
    sel.appendChild(placeholder);
    for (const r of offers) {
      const opt = document.createElement("option");
      opt.value = r.uid;
      opt.textContent = `${r.uid} · ${r.offerState.challengeId} · ${r.offerState.lockedAmount} ${r.offerState.lockedKindLabel}`;
      sel.appendChild(opt);
    }
    if (Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
  }
  renderSolveWitnessFields(ctx);
}

export function renderSolveWitnessFields(ctx) {
  const uid = ctx.els.solveOfferSelect.value;
  ctx.els.solveWitnessFields.replaceChildren();
  if (!uid) return;
  const offer = ctx.store.getResource(uid);
  const c = getChallenge(offer.offerState.challengeId);
  if (c.witnessSchema.length === 0) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = `${c.title}: no witness fields — proof is supplied by the TLSN gate.`;
    ctx.els.solveWitnessFields.appendChild(note);
    return;
  }
  for (const f of c.witnessSchema) {
    ctx.els.solveWitnessFields.appendChild(buildDynamicField("witness", f, "solve-witness-input"));
  }
}

export function renderChallengeRegistry(ctx) {
  ctx.els.challengeList.replaceChildren();
  ctx.els.offerChallenge.replaceChildren();
  const snap = ctx.store.snapshot();
  const activeOffers = snap.resources.filter((r) => r.kindFamily === "offer");
  const challenges = listChallenges();
  for (const c of challenges) {
    const li = document.createElement("li");
    li.dataset.role = "challenge-item";
    li.dataset.challengeId = c.id;
    const head = document.createElement("div");
    head.className = "vault-challenges__id";
    head.textContent = `${c.title}  (${c.id})`;
    const desc = document.createElement("div");
    desc.className = "vault-challenges__desc";
    const live = activeOffers.filter((o) => o.offerState.challengeId === c.id).length;
    desc.textContent = `${c.description} · active offers: ${live}`;
    li.append(head, desc);
    ctx.els.challengeList.appendChild(li);

    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.title;
    ctx.els.offerChallenge.appendChild(opt);
  }
  if (ctx.els.challengesCount) {
    ctx.els.challengesCount.textContent = `${challenges.length} registered`;
  }
  renderOfferParams(ctx);
}

export function renderOfferParams(ctx) {
  const id = ctx.els.offerChallenge.value;
  ctx.els.offerChallengeParams.replaceChildren();
  if (!id) return;
  const c = getChallenge(id);
  for (const f of c.paramSchema) {
    ctx.els.offerChallengeParams.appendChild(
      buildDynamicField("params", f, "offer-challenge-param"),
    );
  }
}

function buildDynamicField(prefix, field, role) {
  const row = document.createElement("div");
  row.className = prefix === "params" ? "vault-param-row" : "vault-witness-row";
  const label = document.createElement("label");
  label.className = prefix === "params" ? "vault-param-row__label" : "vault-witness-row__label";
  label.textContent = `${prefix}.${field.name}`;
  const input = document.createElement("input");
  input.dataset.role = role;
  input.dataset.fieldName = field.name;
  input.type = field.kind === "number" ? "number" : "text";
  row.append(label, input);
  return row;
}

export function renderTransferOutputs(ctx) {
  if (ctx.els.transferOutputs.children.length === 0) {
    ctx.els.transferOutputs.appendChild(buildTransferRow(ctx));
  }
  for (const row of ctx.els.transferOutputs.querySelectorAll('[data-role="transfer-output-row"]')) {
    const recipient = row.querySelector('[data-role="transfer-output-recipient"]');
    const prev = recipient.value;
    recipient.replaceChildren();
    for (const u of ctx.identities) {
      const opt = document.createElement("option");
      opt.value = u;
      opt.textContent = u;
      recipient.appendChild(opt);
    }
    if (prev) recipient.value = prev;
    else recipient.value = ctx.identities.find((u) => u !== ctx.activeUsername);
  }
}

export function addTransferRow(ctx) {
  ctx.els.transferOutputs.appendChild(buildTransferRow(ctx));
  renderTransferOutputs(ctx);
}

function buildTransferRow() {
  const row = document.createElement("div");
  row.className = "vault-output-row";
  row.dataset.role = "transfer-output-row";

  const recipient = document.createElement("select");
  recipient.dataset.role = "transfer-output-recipient";

  const amount = document.createElement("input");
  amount.type = "number";
  amount.min = "1";
  amount.value = "10";
  amount.dataset.role = "transfer-output-amount";

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "btn btn--bare";
  rm.textContent = "×";
  rm.addEventListener("click", () => row.remove());

  row.append(recipient, amount, rm);
  return row;
}

export function updateSubmitButtons(ctx) {
  const ready = ctx.booted;
  // Disable action submits while an action is in flight to prevent the
  // re-entrancy footgun (user double-click rapidly submits twice).
  const busy = ctx.store.snapshot().pendingActions > 0;
  ctx.els.transferSubmit.disabled = !ready || busy;
  ctx.els.offerCreateSubmit.disabled = !ready || busy;
  ctx.els.solveSubmit.disabled = !ready || busy;
  ctx.els.cancelSubmit.disabled = !ready || busy;
  ctx.els.mint.disabled = !ready;
  ctx.els.reset.disabled = !ready;
}

export function setActiveTabLabel(ctx, tab) {
  if (!ctx.els.activeTabLabel) return;
  const label = tab.replace(/_/g, " ");
  ctx.els.activeTabLabel.textContent = label;
}
