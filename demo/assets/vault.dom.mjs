// DOM discovery for the /vault page. One responsibility: resolve every
// `data-role` element and validate at boot that nothing required is missing.
// All required selectors used by vault.handlers / vault.render / the e2e
// harness live here.

const ELS_BY_ROLE = {
  pool: "pool",
  liveCount: "live-count",
  actionsDone: "actions-done",
  actionsPending: "actions-pending",
  actionsFailed: "actions-failed",
  nfCount: "nf-count",
  identity: "identity",
  identityNk: "identity-nk",
  identitySalt: "identity-salt",
  mintKind: "mint-kind",
  mintKindNew: "mint-kind-new",
  mintKindRegister: "mint-kind-register",
  mintAmount: "mint-amount",
  mintOwner: "mint-owner",
  mint: "mint",
  reset: "reset",
  filterKind: "filter-kind",
  filterMine: "filter-mine",
  resources: "resources",
  resourcesSummary: "resources-summary",
  actionTabs: "action-tabs",
  activeTabLabel: "active-tab-label",
  transferOutputs: "transfer-outputs",
  transferAddOutput: "transfer-add-output",
  transferFeeResource: "transfer-fee-resource",
  transferSubmit: "transfer-submit",
  transferError: "transfer-error",
  offerLockedAmount: "offer-locked-amount",
  offerRefundAmount: "offer-refund-amount",
  offerChallenge: "offer-challenge",
  offerChallengeParams: "offer-challenge-params",
  offerFeeResource: "offer-fee-resource",
  offerCreateSubmit: "offer-create-submit",
  offerCreateError: "offer-create-error",
  solveOfferSelect: "solve-offer-select",
  solveWitnessFields: "solve-witness-fields",
  solveFeeResource: "solve-fee-resource",
  solveSubmit: "solve-submit",
  solveError: "solve-error",
  cancelOfferSelect: "cancel-offer-select",
  cancelFeeResource: "cancel-fee-resource",
  cancelSubmit: "cancel-submit",
  cancelError: "cancel-error",
  viz: "viz",
  log: "log",
  challengeList: "challenge-list",
  challengesCount: "challenges-count",
};

// Elements that may legitimately be absent (preserves the existing
// nf-count tolerance for environments where the readout is omitted).
const OPTIONAL = new Set(["nfCount"]);

export function discoverDom() {
  const els = {};
  for (const [name, role] of Object.entries(ELS_BY_ROLE)) {
    els[name] = document.querySelector(`[data-role="${role}"]`);
    if (!els[name] && !OPTIONAL.has(name)) {
      throw new Error(`vault page missing required element els.${name} ([data-role="${role}"])`);
    }
  }
  return els;
}
