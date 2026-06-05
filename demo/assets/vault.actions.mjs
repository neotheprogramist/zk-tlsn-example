// Action builders. Each builder takes the form-input + selected resources
// + active identity and produces an ActionPlan:
//
//   { actionId, flow, consumedRecords, createdPreimages, leafSpecs,
//     actionDigestHex }
//
// The scheduler turns the `leafSpecs` array into worker jobs (one
// prove_leaf per spec, then a binary fold via prove_merge).
//
// Layout: kinds_touched (∪ over consumed.owner_kind + (consumed∪created).logic)
// determines the leaf set. The order of leaves matters — the binary fold
// reuses zkp's merge AIR which enforces leaf-index contiguity, so we
// allocate leaf indices in a deterministic ascending order matching the
// vault::AirKind discriminant ordering.

import {
  deriveCommitment,
  deriveNullifier,
  deriveAuthTag,
  deriveActionDigest,
  freshRho,
  freshRseed,
  fromHex,
  toHex,
} from "./vault.auth.mjs";
import init, { poseidonHash } from "/assets/wasm/vault.js";
import {
  PREIMAGE_LIMB_COUNT,
  bytes16ToLimbs4,
  bytes32ToLimbs8,
  encodePreimageLimbs,
} from "./vault.preimage.mjs";
import { getChallenge, computeChallengePublicHash } from "./vault.challenges.mjs";

let _wasmReady = null;
async function ensureWasm() {
  if (!_wasmReady) _wasmReady = init();
  return _wasmReady;
}

const FEE_AMOUNT = 1;
const AGGREGATOR_OWNER_SALT_HEX = "ff".repeat(32);

const hexToLimbs8 = (hex) => bytes32ToLimbs8(fromHex(hex));

async function makeErc20Preimage({ kindLabel, amount, ownerKind, ownerSaltHex }) {
  const rho = freshRho();
  const rseed = freshRseed();
  const preimage = {
    logic: "erc20",
    label: kindLabel,
    valueRef: { amount },
    ownerKind: ownerKind,
    ownerSaltHex: ownerSaltHex,
    rhoHex: toHex(rho),
    rseedHex: toHex(rseed),
  };
  return { preimage, rho, rseed };
}

async function makeOfferPreimage({
  instanceSaltHex,
  lockedKindLabel,
  lockedAmount,
  challengeId,
  challengePublicHashHex,
  creatorUserkeySaltHex,
}) {
  const rho = freshRho();
  const rseed = freshRseed();
  const preimage = {
    logic: "offer",
    label: `offer:${instanceSaltHex}`,
    valueRef: {
      lockedKind: lockedKindLabel,
      lockedAmount: lockedAmount,
      challengeId: challengeId,
      challengePublicHashHex: challengePublicHashHex,
      creatorUserkeySaltHex: creatorUserkeySaltHex,
    },
    ownerKind: `offer:${instanceSaltHex}`,
    ownerSaltHex: instanceSaltHex,
    rhoHex: toHex(rho),
    rseedHex: toHex(rseed),
  };
  return { preimage, rho, rseed };
}

async function makeResource(
  store,
  { preimage, rho, rseed, kindFamily, amount, offerState, ownerKindFamily, ownerUsername },
) {
  const cm = await deriveCommitment(preimage);
  const cmHex = toHex(cm);
  return {
    uid: store.nextUid(),
    kind: preimage.label,
    kindFamily,
    amount,
    offerState,
    ownerKindFamily,
    ownerUsername,
    ownerSaltHex: preimage.ownerSaltHex,
    rhoHex: toHex(rho),
    rseedHex: toHex(rseed),
    commitmentHex: cmHex,
    preimage,
  };
}

/// Deterministic 32-byte witness for an offer-self-owned resource —
/// reproducible by the host so the prover constructs the same value,
/// unique per (owner_salt, path_bit) so solve (0) and cancel (1) yield
/// distinct nullifiers for the same offer.
async function offerNullifierWitnessBytes(record, pathBit) {
  await ensureWasm();
  const inputLimbs = [pathBit & 0xff, ...Array.from(fromHex(record.ownerSaltHex))];
  const outLimbs = JSON.parse(poseidonHash(JSON.stringify(inputLimbs)));
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = outLimbs[i] | 0;
    bytes[4 * i] = v & 0xff;
    bytes[4 * i + 1] = (v >> 8) & 0xff;
    bytes[4 * i + 2] = (v >> 16) & 0xff;
    bytes[4 * i + 3] = (v >> 24) & 0xff;
  }
  return bytes;
}

/// Per-consumed-resource nullifier + (for UserKey-owned) auth_tag derivation.
/// `witnessSpecs[i]` is `"userkey"` (witness = identity.nk) or
/// `{ pathBit: 0 | 1 }` (witness = offerNullifierWitnessBytes(record, pathBit)).
async function collectConsumedAuth({ consumed, witnessSpecs, identity, actionDigestHex }) {
  const nullifiersHex = [];
  const witnessBytes = [];
  const authTagsHex = [];
  const consumedSaltsHex = [];
  const perResource = [];
  for (let i = 0; i < consumed.length; i++) {
    const r = consumed[i];
    const spec = witnessSpecs[i];
    const wb = spec === "userkey" ? identity.nk : await offerNullifierWitnessBytes(r, spec.pathBit);
    const nfHex = toHex(await deriveNullifier(wb, fromHex(r.rhoHex), fromHex(r.commitmentHex)));
    witnessBytes.push(wb);
    nullifiersHex.push(nfHex);
    consumedSaltsHex.push(r.ownerSaltHex);
    if (spec === "userkey") {
      const tag = toHex(
        await deriveAuthTag(identity.nk, fromHex(actionDigestHex), fromHex(r.commitmentHex)),
      );
      authTagsHex.push(tag);
      perResource.push({ actionDigestHex, cmHex: r.commitmentHex, authTagHex: tag });
    }
  }
  return { nullifiersHex, witnessBytes, authTagsHex, consumedSaltsHex, perResource };
}

async function actionDigest({ consumedCmsHex, createdCmsHex, kindsTouched }) {
  return toHex(
    await deriveActionDigest({
      consumed: consumedCmsHex.slice().sort(),
      created: createdCmsHex.slice().sort(),
      kindsTouched: kindsTouched.slice().sort(),
    }),
  );
}

// Leaf-spec helpers return specs with `leafIndex: null`; the action
// builder calls `assignLeafIndices()` at the end to assign contiguous
// 0,1,2,… indices. (The zkp merge AIR enforces contiguity; the AIR-kind
// metadata stays separate in `air` and the carried `air_kind_tag`.)

const witnessDigestBound = () => ({ kind: "digestBound" });
const witnessConservation = (consumed, created, fee) => ({
  kind: "conservation",
  consumed,
  created,
  fee,
});
const witnessOfferSolveXPlus1 = (x) => ({ kind: "offerSolveXPlus1", x });
const witnessOfferSolveSumEqN = (x, y, n) => ({ kind: "offerSolveSumEqN", x, y, n });

async function complianceLeafSpec({
  actionDigestHex,
  consumedRecords,
  createdRecords,
  consumedNullifiersHex,
  consumedWitnessBytes,
}) {
  await ensureWasm();

  const consumed = [];
  for (let i = 0; i < consumedRecords.length; i++) {
    const r = consumedRecords[i];
    const preimageLimbs = await encodePreimageLimbs(r.preimage);
    const expectedCmLimbs = bytes32ToLimbs8(fromHex(r.commitmentHex));
    const witnessLimbs = bytes32ToLimbs8(consumedWitnessBytes[i]);
    const rhoLimbs = bytes16ToLimbs4(fromHex(r.rhoHex));
    const expectedNfLimbs = bytes32ToLimbs8(fromHex(consumedNullifiersHex[i]));
    consumed.push({
      preimageLimbs,
      expectedCmLimbs,
      witnessLimbs,
      rhoLimbs,
      expectedNfLimbs,
    });
  }

  const created = [];
  for (const r of createdRecords) {
    const preimageLimbs = await encodePreimageLimbs(r.preimage);
    const expectedCmLimbs = bytes32ToLimbs8(fromHex(r.commitmentHex));
    created.push({ preimageLimbs, expectedCmLimbs });
  }

  // Padding fillers — all zeros. Pre-compute the matching cm/nf so the
  // eq constraints trivially hold for unused slots.
  const zeroPreimageLimbs = Array.from({ length: PREIMAGE_LIMB_COUNT }, () => 0);
  const zeroCmLimbs = JSON.parse(poseidonHash(JSON.stringify(zeroPreimageLimbs)));
  const zeroWitnessLimbs = [0, 0, 0, 0, 0, 0, 0, 0];
  const zeroRhoLimbs = [0, 0, 0, 0];
  const zeroNfInput = [...zeroWitnessLimbs, ...zeroRhoLimbs, ...zeroCmLimbs];
  const zeroNfLimbs = JSON.parse(poseidonHash(JSON.stringify(zeroNfInput)));

  return {
    leafIndex: null,
    air: "compliance",
    publicInputs: {
      air: "compliance",
      actionDigestHex: actionDigestHex,
      consumedCommitmentsHex: consumedRecords.map((r) => r.commitmentHex),
      createdCommitmentsHex: createdRecords.map((r) => r.commitmentHex),
      nullifiersHex: consumedNullifiersHex,
    },
    privateWitness: {
      kind: "compliance",
      consumed,
      created,
      paddingConsumed: {
        preimageLimbs: zeroPreimageLimbs,
        expectedCmLimbs: zeroCmLimbs,
        witnessLimbs: zeroWitnessLimbs,
        rhoLimbs: zeroRhoLimbs,
        expectedNfLimbs: zeroNfLimbs,
      },
      paddingCreated: {
        preimageLimbs: zeroPreimageLimbs,
        expectedCmLimbs: zeroCmLimbs,
      },
    },
  };
}

function conservationLeafSpec({ kindLabel, consumedAmounts, createdAmounts, feeAmount }) {
  return {
    leafIndex: null,
    air: "conservationFungible",
    publicInputs: {
      air: "conservationFungible",
      kindLabel: kindLabel,
      consumedAmounts: consumedAmounts,
      createdAmounts: createdAmounts,
      feeAmount: feeAmount,
    },
    privateWitness: witnessConservation(consumedAmounts, createdAmounts, feeAmount),
  };
}

async function userkeyLeafSpec({
  actionDigestHex,
  consumedSalts,
  authTags,
  identity,
  perResource,
}) {
  // The UserKey AIR enforces:
  //   Poseidon(nk) == userkey_salt
  //   for each consumed userkey-owned resource:
  //     Poseidon(nk ‖ action_digest ‖ cm) == auth_tag
  //
  // Slots are zero-padded up to MAX_USERKEY_AUTH_PER_LEAF (= 4 in the
  // vault crate). The padding entry's auth_tag is host-computed as
  // Poseidon(nk ‖ 0…0 ‖ 0…0) so the constraint trivially holds.
  const nk = identity.nk;
  const userkeySalt = identity.userkeySalt;
  const zero32 = new Uint8Array(32);
  const paddingAuthTag = await deriveAuthTag(nk, zero32, zero32);
  return {
    leafIndex: null,
    air: "userKey",
    publicInputs: {
      air: "userKey",
      actionDigestHex: actionDigestHex,
      consumedResourcesUserkeySaltHex: consumedSalts,
      authTagsHex: authTags,
    },
    privateWitness: {
      kind: "userKeyAuth",
      nkLimbs: bytes32ToLimbs8(nk),
      expectedUserkeySaltLimbs: bytes32ToLimbs8(userkeySalt),
      consumedAuthTags: perResource.map((r) => ({
        actionDigestLimbs: hexToLimbs8(r.actionDigestHex),
        cmLimbs: hexToLimbs8(r.cmHex),
        authTagLimbs: hexToLimbs8(r.authTagHex),
      })),
      paddingFiller: {
        actionDigestLimbs: Array.from({ length: 8 }, () => 0),
        cmLimbs: Array.from({ length: 8 }, () => 0),
        authTagLimbs: bytes32ToLimbs8(paddingAuthTag),
      },
    },
  };
}

function offerCreateLeafSpec({
  instanceSaltHex,
  lockedKindLabel,
  lockedAmount,
  challengeId,
  challengePublicHashHex,
}) {
  return {
    leafIndex: null,
    air: "offerCreate",
    publicInputs: {
      air: "offerCreate",
      instanceSaltHex: instanceSaltHex,
      lockedKindLabel: lockedKindLabel,
      lockedAmount: lockedAmount,
      challengeId: challengeId,
      challengePublicHashHex: challengePublicHashHex,
    },
    privateWitness: witnessDigestBound(),
  };
}

function offerSolveLeafSpec({ instanceSaltHex, challengeId, declaration, witness }) {
  let privateWitness;
  if (challengeId === "x_plus_1_eq_2") {
    privateWitness = witnessOfferSolveXPlus1(Number(witness.x));
  } else if (challengeId === "sum_eq_n") {
    privateWitness = witnessOfferSolveSumEqN(
      Number(witness.x),
      Number(witness.y),
      Number(declaration.n),
    );
  } else {
    throw new Error(`offer-solve circuit not registered for challenge ${challengeId}`);
  }
  return {
    leafIndex: null,
    air: "offerSolve",
    publicInputs: {
      air: "offerSolve",
      instanceSaltHex: instanceSaltHex,
      challengeId: challengeId,
      challengeDeclaration: declaration,
    },
    privateWitness,
  };
}

// TlsnAttestation leaf: in-circuit opening of a TLSN Poseidon transcript
// commitment over the bank's 32-byte ASCII attestation. The circuit
// constraints (vault::leaf_circuits::build_tlsn_attestation):
//   1. Parse `tx_id` (10d) / `to_user_id` (10d) / `amount` (12d) from
//      the attestation bytes and bind each to its public counterpart.
//   2. Recompute `Poseidon2(attestation ‖ blinder)` and bind to
//      `commitment_limbs`.
// All five private witness fields (attestation, blinder, tx_id,
// to_user_id, amount) come from `vault.tlsn.worker.mjs`. The public
// inputs include the commitment limbs + parsed scalars so the verifier
// can recompute the public-input digest and bind the proof to a
// specific (tx_id, to_user_id, amount) tuple.
function tlsnAttestationLeafSpec({
  commitmentLimbs,
  txId,
  toUserId,
  amount,
  attestationBytes,
  blinderBytes,
}) {
  return {
    leafIndex: null,
    air: "tlsnAttestation",
    publicInputs: {
      air: "tlsnAttestation",
      commitmentLimbs,
      txId,
      toUserId,
      amount,
    },
    privateWitness: {
      kind: "tlsnAttestation",
      attestationBytes,
      blinderBytes,
      commitmentLimbs,
      txId,
      toUserId,
      amount,
    },
  };
}

function offerCancelLeafSpec({
  instanceSaltHex,
  creatorUserkeySaltHex,
  cancelAuthTagHex,
  actionDigestHex,
  cmOfferHex,
  nkCreator,
}) {
  // OfferCancel AIR enforces:
  //   Poseidon(nk_creator) == creator_userkey_salt
  //   Poseidon(nk_creator ‖ action_digest ‖ cm_offer) == cancel_auth_tag
  return {
    leafIndex: null,
    air: "offerCancel",
    publicInputs: {
      air: "offerCancel",
      instanceSaltHex: instanceSaltHex,
      creatorUserkeySaltHex: creatorUserkeySaltHex,
      cancelAuthTagHex: cancelAuthTagHex,
    },
    privateWitness: {
      kind: "offerCancelAuth",
      nkCreatorLimbs: bytes32ToLimbs8(nkCreator),
      creatorUserkeySaltLimbs: hexToLimbs8(creatorUserkeySaltHex),
      actionDigestLimbs: hexToLimbs8(actionDigestHex),
      cmOfferLimbs: hexToLimbs8(cmOfferHex),
      cancelAuthTagLimbs: hexToLimbs8(cancelAuthTagHex),
    },
  };
}

function assignLeafIndices(leafSpecs) {
  for (let i = 0; i < leafSpecs.length; i++) leafSpecs[i].leafIndex = i;
  return leafSpecs;
}

async function feeResourceWithChange({ store, feeRecord, ownerUsername, identity }) {
  if (feeRecord.kind !== store.CANONICAL_USDC_LABEL) {
    throw new Error(`fee must be paid in ${store.CANONICAL_USDC_LABEL} (got ${feeRecord.kind})`);
  }
  if (feeRecord.ownerUsername !== ownerUsername) {
    throw new Error("fee resource must belong to the active identity");
  }
  if (feeRecord.amount < FEE_AMOUNT) {
    throw new Error(
      `fee resource has only ${feeRecord.amount} ${feeRecord.kind} (need ${FEE_AMOUNT})`,
    );
  }
  const ownerSaltHex = toHex(identity.userkeySalt);
  const fee = await makeErc20Preimage({
    kindLabel: feeRecord.kind,
    amount: FEE_AMOUNT,
    ownerKind: "aggregator",
    ownerSaltHex: AGGREGATOR_OWNER_SALT_HEX,
  });
  const feeResource = await makeResource(store, {
    preimage: fee.preimage,
    rho: fee.rho,
    rseed: fee.rseed,
    kindFamily: "erc20",
    amount: FEE_AMOUNT,
    offerState: null,
    ownerKindFamily: "aggregator",
    ownerUsername: null,
  });
  let changeResource = null;
  const changeAmount = feeRecord.amount - FEE_AMOUNT;
  if (changeAmount > 0) {
    const change = await makeErc20Preimage({
      kindLabel: feeRecord.kind,
      amount: changeAmount,
      ownerKind: "userkey",
      ownerSaltHex,
    });
    changeResource = await makeResource(store, {
      preimage: change.preimage,
      rho: change.rho,
      rseed: change.rseed,
      kindFamily: "erc20",
      amount: changeAmount,
      offerState: null,
      ownerKindFamily: "userkey",
      ownerUsername,
    });
  }
  return { feeResource, changeResource };
}

export async function buildTransfer({ store, activeUsername, inputs, outputs, feeRecord }) {
  if (inputs.length === 0) throw new Error("transfer needs at least one input");
  if (inputs.some((r) => r.uid === feeRecord.uid)) {
    throw new Error("fee resource must be distinct from transfer inputs");
  }
  const kind = inputs[0].kind;
  for (const r of inputs) {
    if (r.kind !== kind) throw new Error("transfer inputs must share one kind");
    if (r.ownerUsername !== activeUsername) {
      throw new Error("transfer input must belong to active identity");
    }
    if (r.kindFamily !== "erc20") throw new Error("transfer is for erc20 only");
  }
  for (const o of outputs) {
    if (!Number.isInteger(o.amount) || o.amount <= 0) {
      throw new Error(`output amount must be positive integer (got ${o.amount})`);
    }
  }
  const totalIn = inputs.reduce((s, r) => s + r.amount, 0);
  const totalOut = outputs.reduce((s, o) => s + o.amount, 0);
  if (totalOut > totalIn) {
    throw new Error(`outputs ${totalOut} exceed inputs ${totalIn}`);
  }
  const changeAmount = totalIn - totalOut;
  const identity = store.getIdentity(activeUsername);
  const ownerSaltHex = toHex(identity.userkeySalt);

  const created = [];
  for (const o of outputs) {
    const recipient = store.getIdentity(o.recipientUsername);
    const p = await makeErc20Preimage({
      kindLabel: kind,
      amount: o.amount,
      ownerKind: "userkey",
      ownerSaltHex: toHex(recipient.userkeySalt),
    });
    const rec = await makeResource(store, {
      preimage: p.preimage,
      rho: p.rho,
      rseed: p.rseed,
      kindFamily: "erc20",
      amount: o.amount,
      offerState: null,
      ownerKindFamily: "userkey",
      ownerUsername: o.recipientUsername,
    });
    created.push(rec);
  }
  if (changeAmount > 0) {
    const c = await makeErc20Preimage({
      kindLabel: kind,
      amount: changeAmount,
      ownerKind: "userkey",
      ownerSaltHex,
    });
    const rec = await makeResource(store, {
      preimage: c.preimage,
      rho: c.rho,
      rseed: c.rseed,
      kindFamily: "erc20",
      amount: changeAmount,
      offerState: null,
      ownerKindFamily: "userkey",
      ownerUsername: activeUsername,
    });
    created.push(rec);
  }
  const { feeResource, changeResource: feeChange } = await feeResourceWithChange({
    store,
    feeRecord,
    ownerUsername: activeUsername,
    identity,
  });
  if (feeChange) created.push(feeChange);

  // Include the consumed fee resource as a transfer-input.
  const allConsumed = [...inputs, feeRecord];

  const consumedCmsHex = allConsumed.map((r) => r.commitmentHex);
  const createdCmsHex = [...created.map((r) => r.commitmentHex), feeResource.commitmentHex];
  const kindsTouched = ["userKey", kind, store.CANONICAL_USDC_LABEL].filter(
    (v, i, arr) => arr.indexOf(v) === i,
  );

  // Compute action digest.
  const actionDigestHex = await actionDigest({ consumedCmsHex, createdCmsHex, kindsTouched });

  const {
    nullifiersHex,
    witnessBytes: consumedWitnessBytes,
    authTagsHex,
    consumedSaltsHex,
    perResource,
  } = await collectConsumedAuth({
    consumed: allConsumed,
    witnessSpecs: allConsumed.map(() => "userkey"),
    identity,
    actionDigestHex,
  });

  const leafSpecs = [];
  leafSpecs.push(
    await complianceLeafSpec({
      actionDigestHex,
      consumedRecords: allConsumed,
      createdRecords: [...created, feeResource],
      consumedNullifiersHex: nullifiersHex,
      consumedWitnessBytes,
    }),
  );
  // Conservation: one per fungible kind. Transfer's kind may equal USDC,
  // in which case the two collapse into one. The circuit AIR enforces
  // Σ consumed == Σ created + fee, so the fee resource going to the
  // aggregator is NOT in `created_amounts` — it's the explicit `fee_amount`.
  const fungibleKinds = new Set([kind, store.CANONICAL_USDC_LABEL]);
  for (const k of fungibleKinds) {
    const consumedAmounts = allConsumed.filter((r) => r.kind === k).map((r) => r.amount);
    const createdForKind = created.filter((r) => r.kind === k);
    const createdAmounts = createdForKind.map((r) => r.amount);
    const feeForKind = k === store.CANONICAL_USDC_LABEL ? FEE_AMOUNT : 0;
    const sumIn = consumedAmounts.reduce((s, n) => s + n, 0);
    const sumOut = createdAmounts.reduce((s, n) => s + n, 0);
    if (sumIn !== sumOut + feeForKind) {
      throw new Error(
        `conservation violated for ${k}: consumed=${sumIn} created=${sumOut} fee=${feeForKind}`,
      );
    }
    leafSpecs.push(
      conservationLeafSpec({
        kindLabel: k,
        consumedAmounts,
        createdAmounts,
        feeAmount: feeForKind,
      }),
    );
  }
  leafSpecs.push(
    await userkeyLeafSpec({
      actionDigestHex,
      consumedSalts: consumedSaltsHex,
      authTags: authTagsHex,
      identity,
      perResource,
    }),
  );

  return {
    actionId: store.nextActionIdAndAllocate(),
    flow: "transfer",
    consumedRecords: allConsumed,
    createdRecords: [...created, feeResource],
    nullifiersHex,
    leafSpecs: assignLeafIndices(leafSpecs),
    actionDigestHex,
    kindsTouched,
  };
}

export async function buildCreateOffer({
  store,
  activeUsername,
  inputs,
  lockedAmount,
  refundAmount,
  challengeId,
  challengeParams,
  feeRecord,
}) {
  if (inputs.length === 0) throw new Error("create-offer needs at least one input");
  if (inputs.some((r) => r.uid === feeRecord.uid)) {
    throw new Error("fee resource must be distinct from create-offer inputs");
  }
  const kind = inputs[0].kind;
  for (const r of inputs) {
    if (r.kind !== kind) throw new Error("create-offer inputs must share one kind");
    if (r.ownerUsername !== activeUsername) {
      throw new Error("create-offer input must belong to active identity");
    }
    if (r.kindFamily !== "erc20") throw new Error("create-offer locks an erc20");
  }
  const totalIn = inputs.reduce((s, r) => s + r.amount, 0);
  if (lockedAmount + refundAmount !== totalIn) {
    throw new Error(`locked+refund=${lockedAmount + refundAmount} must equal input sum ${totalIn}`);
  }
  const challenge = getChallenge(challengeId);
  const declaration = challenge.declaration(challengeParams ?? {});
  const challengePublicHashHex = await computeChallengePublicHash(challengeId, declaration);

  const identity = store.getIdentity(activeUsername);
  const creatorUserkeySaltHex = toHex(identity.userkeySalt);

  // instance_salt: 32 random bytes.
  const instanceSalt = new Uint8Array(32);
  crypto.getRandomValues(instanceSalt);
  const instanceSaltHex = toHex(instanceSalt);

  // Co-create the locked resource (owner = offer-self).
  const lockedP = await makeErc20Preimage({
    kindLabel: kind,
    amount: lockedAmount,
    ownerKind: `offer:${instanceSaltHex}`,
    ownerSaltHex: instanceSaltHex,
  });
  const lockedResource = await makeResource(store, {
    preimage: lockedP.preimage,
    rho: lockedP.rho,
    rseed: lockedP.rseed,
    kindFamily: "erc20",
    amount: lockedAmount,
    offerState: null,
    ownerKindFamily: "offer-self",
    ownerUsername: null,
  });

  // Create the Offer resource itself (self-owned).
  const offerP = await makeOfferPreimage({
    instanceSaltHex,
    lockedKindLabel: kind,
    lockedAmount,
    challengeId,
    challengePublicHashHex,
    creatorUserkeySaltHex,
  });
  const offerResource = await makeResource(store, {
    preimage: offerP.preimage,
    rho: offerP.rho,
    rseed: offerP.rseed,
    kindFamily: "offer",
    amount: null,
    offerState: {
      instanceSaltHex,
      lockedKindLabel: kind,
      lockedAmount,
      lockedResourceUid: lockedResource.uid,
      challengeId,
      challengeDeclaration: declaration,
      challengePublicHashHex,
      creatorUsername: activeUsername,
      creatorUserkeySaltHex,
    },
    ownerKindFamily: "offer-self",
    ownerUsername: null,
  });

  // Refund (to active identity) if any.
  const created = [lockedResource, offerResource];
  if (refundAmount > 0) {
    const refundP = await makeErc20Preimage({
      kindLabel: kind,
      amount: refundAmount,
      ownerKind: "userkey",
      ownerSaltHex: creatorUserkeySaltHex,
    });
    const refundResource = await makeResource(store, {
      preimage: refundP.preimage,
      rho: refundP.rho,
      rseed: refundP.rseed,
      kindFamily: "erc20",
      amount: refundAmount,
      offerState: null,
      ownerKindFamily: "userkey",
      ownerUsername: activeUsername,
    });
    created.push(refundResource);
  }

  const { feeResource, changeResource } = await feeResourceWithChange({
    store,
    feeRecord,
    ownerUsername: activeUsername,
    identity,
  });
  if (changeResource) created.push(changeResource);
  const createdAll = [...created, feeResource];

  const allConsumed = [...inputs, feeRecord];

  const consumedCmsHex = allConsumed.map((r) => r.commitmentHex);
  const createdCmsHex = createdAll.map((r) => r.commitmentHex);
  const kindsTouched = [
    "userkey",
    kind,
    store.CANONICAL_USDC_LABEL,
    `offer:${instanceSaltHex}`,
  ].filter((v, i, arr) => arr.indexOf(v) === i);

  const actionDigestHex = await actionDigest({ consumedCmsHex, createdCmsHex, kindsTouched });

  const {
    nullifiersHex,
    witnessBytes: consumedWitnessBytes,
    authTagsHex,
    consumedSaltsHex,
    perResource,
  } = await collectConsumedAuth({
    consumed: allConsumed,
    witnessSpecs: allConsumed.map(() => "userkey"),
    identity,
    actionDigestHex,
  });
  const leafSpecs = [];
  leafSpecs.push(
    await complianceLeafSpec({
      actionDigestHex,
      consumedRecords: allConsumed,
      createdRecords: createdAll,
      consumedNullifiersHex: nullifiersHex,
      consumedWitnessBytes,
    }),
  );
  const fungibleKinds = new Set([kind, store.CANONICAL_USDC_LABEL]);
  for (const k of fungibleKinds) {
    const consumedAmounts = allConsumed.filter((r) => r.kind === k).map((r) => r.amount);
    // Exclude feeResource from created_amounts — it's represented by `fee_amount`.
    const createdForKind = created.filter((r) => r.kind === k);
    const createdAmounts = createdForKind.map((r) => r.amount);
    const feeForKind = k === store.CANONICAL_USDC_LABEL ? FEE_AMOUNT : 0;
    const sumIn = consumedAmounts.reduce((s, n) => s + n, 0);
    const sumOut = createdAmounts.reduce((s, n) => s + n, 0);
    if (sumIn !== sumOut + feeForKind) {
      throw new Error(
        `conservation violated for ${k}: in=${sumIn} out=${sumOut} fee=${feeForKind}`,
      );
    }
    leafSpecs.push(
      conservationLeafSpec({
        kindLabel: k,
        consumedAmounts,
        createdAmounts,
        feeAmount: feeForKind,
      }),
    );
  }
  leafSpecs.push(
    offerCreateLeafSpec({
      instanceSaltHex,
      lockedKindLabel: kind,
      lockedAmount,
      challengeId,
      challengePublicHashHex,
    }),
  );
  leafSpecs.push(
    await userkeyLeafSpec({
      actionDigestHex,
      consumedSalts: consumedSaltsHex,
      authTags: authTagsHex,
      identity,
      perResource,
    }),
  );

  return {
    actionId: store.nextActionIdAndAllocate(),
    flow: "create_offer",
    consumedRecords: allConsumed,
    createdRecords: createdAll,
    nullifiersHex,
    leafSpecs: assignLeafIndices(leafSpecs),
    actionDigestHex,
    kindsTouched,
    offerInstanceSaltHex: instanceSaltHex,
  };
}

export async function buildSolveOffer({ store, activeUsername, offerRecord, witness, feeRecord }) {
  if (offerRecord.kindFamily !== "offer") throw new Error("not an offer resource");
  const ofs = offerRecord.offerState;
  const challenge = getChallenge(ofs.challengeId);
  if (!challenge.verify(ofs.challengeDeclaration, witness)) {
    throw new Error(`challenge ${ofs.challengeId} witness does not satisfy declaration`);
  }
  const lockedResource = store.getResource(ofs.lockedResourceUid);
  const identity = store.getIdentity(activeUsername);
  const solverSaltHex = toHex(identity.userkeySalt);

  // Created: locked tokens released to solver.
  const releasedP = await makeErc20Preimage({
    kindLabel: ofs.lockedKindLabel,
    amount: ofs.lockedAmount,
    ownerKind: "userkey",
    ownerSaltHex: solverSaltHex,
  });
  const releasedResource = await makeResource(store, {
    preimage: releasedP.preimage,
    rho: releasedP.rho,
    rseed: releasedP.rseed,
    kindFamily: "erc20",
    amount: ofs.lockedAmount,
    offerState: null,
    ownerKindFamily: "userkey",
    ownerUsername: activeUsername,
  });
  const { feeResource, changeResource } = await feeResourceWithChange({
    store,
    feeRecord,
    ownerUsername: activeUsername,
    identity,
  });

  const consumed = [offerRecord, lockedResource, feeRecord];
  const created = [releasedResource, feeResource];
  if (changeResource) created.push(changeResource);

  const consumedCmsHex = consumed.map((r) => r.commitmentHex);
  const createdCmsHex = created.map((r) => r.commitmentHex);
  const kindsTouched = [
    "userkey",
    `offer:${ofs.instanceSaltHex}`,
    ofs.lockedKindLabel,
    store.CANONICAL_USDC_LABEL,
  ].filter((v, i, arr) => arr.indexOf(v) === i);

  const actionDigestHex = await actionDigest({ consumedCmsHex, createdCmsHex, kindsTouched });

  const {
    nullifiersHex,
    witnessBytes: consumedWitnessBytes,
    authTagsHex,
    perResource,
  } = await collectConsumedAuth({
    consumed,
    witnessSpecs: [{ pathBit: 0 }, { pathBit: 0 }, "userkey"],
    identity,
    actionDigestHex,
  });

  const leafSpecs = [];
  leafSpecs.push(
    await complianceLeafSpec({
      actionDigestHex,
      consumedRecords: consumed,
      createdRecords: created,
      consumedNullifiersHex: nullifiersHex,
      consumedWitnessBytes,
    }),
  );
  // Conservation per fungible kind. fee_amount is a separate term in the
  // circuit's Σ consumed == Σ created + fee constraint, so the fee resource
  // going to the aggregator must be excluded from created_amounts here.
  const fungibleKinds = new Set([ofs.lockedKindLabel, store.CANONICAL_USDC_LABEL]);
  for (const k of fungibleKinds) {
    const consumedAmounts = consumed
      .filter((r) => r.kind === k && r.kindFamily === "erc20")
      .map((r) => r.amount);
    const createdForKind = created.filter((r) => r.kind === k && r.uid !== feeResource.uid);
    const createdAmounts = createdForKind.map((r) => r.amount);
    const feeForKind = k === store.CANONICAL_USDC_LABEL ? FEE_AMOUNT : 0;
    const sumIn = consumedAmounts.reduce((s, n) => s + n, 0);
    const sumOut = createdAmounts.reduce((s, n) => s + n, 0);
    if (sumIn !== sumOut + feeForKind) {
      throw new Error(
        `conservation violated for ${k}: in=${sumIn} out=${sumOut} fee=${feeForKind}`,
      );
    }
    leafSpecs.push(
      conservationLeafSpec({
        kindLabel: k,
        consumedAmounts,
        createdAmounts,
        feeAmount: feeForKind,
      }),
    );
  }
  // Per-challenge leaf: algebraic challenges (x+1=2, sum_eq_n, …) emit an
  // offerSolve leaf binding the witness in-circuit. The `tlsn_transfer`
  // challenge emits a tlsnAttestation leaf instead — the witness here
  // carries the TLSN-extracted attestation + blinder + commitment limbs
  // from `vault.tlsn.worker.mjs`, and the in-circuit proof opens the
  // Poseidon commitment and parses the (tx_id, to_user_id, amount)
  // segments out of the attestation bytes.
  if (ofs.challengeId === "tlsn_transfer") {
    leafSpecs.push(
      tlsnAttestationLeafSpec({
        commitmentLimbs: witness.commitmentLimbs,
        txId: witness.txId,
        toUserId: witness.toUserId,
        amount: witness.amount,
        attestationBytes: witness.attestationBytes,
        blinderBytes: witness.blinderBytes,
      }),
    );
  } else {
    leafSpecs.push(
      offerSolveLeafSpec({
        instanceSaltHex: ofs.instanceSaltHex,
        challengeId: ofs.challengeId,
        declaration: ofs.challengeDeclaration,
        witness,
      }),
    );
  }
  leafSpecs.push(
    await userkeyLeafSpec({
      actionDigestHex,
      consumedSalts: [feeRecord.ownerSaltHex],
      authTags: authTagsHex,
      identity,
      perResource,
    }),
  );

  return {
    actionId: store.nextActionIdAndAllocate(),
    flow: "solve_offer",
    consumedRecords: consumed,
    createdRecords: created,
    nullifiersHex,
    leafSpecs: assignLeafIndices(leafSpecs),
    actionDigestHex,
    kindsTouched,
  };
}

export async function buildCancelOffer({ store, activeUsername, offerRecord, feeRecord }) {
  if (offerRecord.kindFamily !== "offer") throw new Error("not an offer resource");
  const ofs = offerRecord.offerState;
  if (ofs.creatorUsername !== activeUsername) {
    throw new Error(`only the creator (${ofs.creatorUsername}) may cancel this offer`);
  }
  const lockedResource = store.getResource(ofs.lockedResourceUid);
  const identity = store.getIdentity(activeUsername);
  const creatorSaltHex = toHex(identity.userkeySalt);

  const returnedP = await makeErc20Preimage({
    kindLabel: ofs.lockedKindLabel,
    amount: ofs.lockedAmount,
    ownerKind: "userkey",
    ownerSaltHex: creatorSaltHex,
  });
  const returnedResource = await makeResource(store, {
    preimage: returnedP.preimage,
    rho: returnedP.rho,
    rseed: returnedP.rseed,
    kindFamily: "erc20",
    amount: ofs.lockedAmount,
    offerState: null,
    ownerKindFamily: "userkey",
    ownerUsername: activeUsername,
  });
  const { feeResource, changeResource } = await feeResourceWithChange({
    store,
    feeRecord,
    ownerUsername: activeUsername,
    identity,
  });

  const consumed = [offerRecord, lockedResource, feeRecord];
  const created = [returnedResource, feeResource];
  if (changeResource) created.push(changeResource);

  const consumedCmsHex = consumed.map((r) => r.commitmentHex);
  const createdCmsHex = created.map((r) => r.commitmentHex);
  const kindsTouched = [
    "userkey",
    `offer:${ofs.instanceSaltHex}`,
    ofs.lockedKindLabel,
    store.CANONICAL_USDC_LABEL,
  ].filter((v, i, arr) => arr.indexOf(v) === i);

  const actionDigestHex = await actionDigest({ consumedCmsHex, createdCmsHex, kindsTouched });

  const {
    nullifiersHex,
    witnessBytes: consumedWitnessBytes,
    authTagsHex,
    perResource,
  } = await collectConsumedAuth({
    consumed,
    witnessSpecs: [{ pathBit: 1 }, { pathBit: 1 }, "userkey"],
    identity,
    actionDigestHex,
  });
  const cancelAuthTag = await deriveAuthTag(
    identity.nk,
    fromHex(actionDigestHex),
    fromHex(offerRecord.commitmentHex),
  );

  const leafSpecs = [];
  leafSpecs.push(
    await complianceLeafSpec({
      actionDigestHex,
      consumedRecords: consumed,
      createdRecords: created,
      consumedNullifiersHex: nullifiersHex,
      consumedWitnessBytes,
    }),
  );
  const fungibleKinds = new Set([ofs.lockedKindLabel, store.CANONICAL_USDC_LABEL]);
  for (const k of fungibleKinds) {
    const consumedAmounts = consumed
      .filter((r) => r.kind === k && r.kindFamily === "erc20")
      .map((r) => r.amount);
    // fee_amount is a separate circuit term — exclude the fee resource.
    const createdForKind = created.filter((r) => r.kind === k && r.uid !== feeResource.uid);
    const createdAmounts = createdForKind.map((r) => r.amount);
    const feeForKind = k === store.CANONICAL_USDC_LABEL ? FEE_AMOUNT : 0;
    const sumIn = consumedAmounts.reduce((s, n) => s + n, 0);
    const sumOut = createdAmounts.reduce((s, n) => s + n, 0);
    if (sumIn !== sumOut + feeForKind) {
      throw new Error(
        `conservation violated for ${k}: in=${sumIn} out=${sumOut} fee=${feeForKind}`,
      );
    }
    leafSpecs.push(
      conservationLeafSpec({
        kindLabel: k,
        consumedAmounts,
        createdAmounts,
        feeAmount: feeForKind,
      }),
    );
  }
  leafSpecs.push(
    offerCancelLeafSpec({
      instanceSaltHex: ofs.instanceSaltHex,
      creatorUserkeySaltHex: ofs.creatorUserkeySaltHex,
      cancelAuthTagHex: toHex(cancelAuthTag),
      actionDigestHex,
      cmOfferHex: offerRecord.commitmentHex,
      nkCreator: identity.nk,
    }),
  );
  leafSpecs.push(
    await userkeyLeafSpec({
      actionDigestHex,
      consumedSalts: [feeRecord.ownerSaltHex],
      authTags: authTagsHex,
      identity,
      perResource,
    }),
  );

  return {
    actionId: store.nextActionIdAndAllocate(),
    flow: "cancel_offer",
    consumedRecords: consumed,
    createdRecords: created,
    nullifiersHex,
    leafSpecs: assignLeafIndices(leafSpecs),
    actionDigestHex,
    kindsTouched,
  };
}
