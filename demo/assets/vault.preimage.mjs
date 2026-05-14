// Canonical 38-limb preimage encoding — the wire-format contract
// between the JS host and the in-circuit Compliance AIR's
// `cm = Poseidon(preimage_limbs)` constraint. The schema MUST match
// `vault/src/preimage.rs` exactly: same slot offsets, same
// discriminant values, same packing rules.

import init, { poseidonHash } from "/assets/wasm/vault.js";

let wasmReady = null;
async function ensureWasm() {
  if (!wasmReady) wasmReady = init();
  return wasmReady;
}

// Slot layout — must match vault/src/preimage.rs.
export const PREIMAGE_LIMB_COUNT = 38;
export const SLOT_LOGIC_KIND = 0;
export const SLOT_LABEL_ID_START = 1;
export const SLOT_VALUE_REF_START = 9;
export const SLOT_OWNER_KIND = 17;
export const SLOT_OWNER_SALT_START = 18;
export const SLOT_RHO_START = 26;
export const SLOT_RSEED_START = 30;

export const LOGIC_KIND = Object.freeze({ erc20: 1, offer: 2 });
export const OWNER_KIND = Object.freeze({ userkey: 1, offer_self: 2, aggregator: 3 });

const enc = new TextEncoder();

// Pack 32 bytes → 8 M31-safe u32 limbs (lower 31 bits used; high bit
// always 0 after mask). Inverse of `limbsToBytes` in vault.auth.mjs.
export function bytes32ToLimbs8(bytes32) {
  if (bytes32.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes32.length}`);
  }
  const out = Array.from({ length: 8 });
  for (let i = 0; i < 8; i++) {
    out[i] =
      ((bytes32[4 * i] |
        (bytes32[4 * i + 1] << 8) |
        (bytes32[4 * i + 2] << 16) |
        (bytes32[4 * i + 3] << 24)) >>>
        0) &
      0x7fffffff;
  }
  return out;
}

// Pack 16 bytes → 4 M31-safe u32 limbs.
export function bytes16ToLimbs4(bytes16) {
  if (bytes16.length !== 16) {
    throw new Error(`expected 16 bytes, got ${bytes16.length}`);
  }
  const out = Array.from({ length: 4 });
  for (let i = 0; i < 4; i++) {
    out[i] =
      ((bytes16[4 * i] |
        (bytes16[4 * i + 1] << 8) |
        (bytes16[4 * i + 2] << 16) |
        (bytes16[4 * i + 3] << 24)) >>>
        0) &
      0x7fffffff;
  }
  return out;
}

// Hash arbitrary bytes via Poseidon (each byte → one M31 limb).
async function poseidonOfBytes(bytes) {
  await ensureWasm();
  const limbs = Array.from(bytes);
  const out = JSON.parse(poseidonHash(JSON.stringify(limbs)));
  return out; // [u32; 8]
}

// Resource kind labels are arbitrary strings (e.g. "vault.usdc",
// "offer:<instance_salt_hex>"). Host pre-hashes to 8 M31 limbs so the
// circuit's preimage schema is fixed-size.
async function labelToLimbs(label) {
  return await poseidonOfBytes(enc.encode(label));
}

// Determinism: sort keys before JSON-stringifying so the hash is stable.
// The result is fed through Poseidon to produce 8 limbs.
async function valueRefToLimbs(valueRef) {
  const canonical = JSON.stringify(valueRef, Object.keys(valueRef).sort());
  return await poseidonOfBytes(enc.encode(canonical));
}

function logicKindDiscriminant(logic) {
  if (logic === "erc20") return LOGIC_KIND.erc20;
  if (logic === "offer") return LOGIC_KIND.offer;
  throw new Error(`unknown logic kind: ${logic}`);
}

function ownerKindDiscriminantFromString(ownerKindStr) {
  if (ownerKindStr === "userkey") return OWNER_KIND.userkey;
  if (ownerKindStr === "aggregator") return OWNER_KIND.aggregator;
  if (ownerKindStr.startsWith("offer:")) return OWNER_KIND.offer_self;
  throw new Error(`unknown owner kind: ${ownerKindStr}`);
}

/// Convert a preimage object (camelCase fields) to its canonical
/// 38-limb encoding. Returns a flat u32 array of length 38.
///
/// `preimage` shape (matches what JS state/actions construct):
///   {
///     logic: "erc20" | "offer",
///     label: string,
///     valueRef: object,
///     ownerKind: "userkey" | "aggregator" | "offer:<instanceSaltHex>",
///     ownerSaltHex: 64-char hex,
///     rhoHex: 32-char hex,
///     rseedHex: 64-char hex,
///   }
export async function encodePreimageLimbs(preimage) {
  await ensureWasm();
  const labelLimbs = await labelToLimbs(preimage.label);
  const valueRefLimbs = await valueRefToLimbs(preimage.valueRef);

  const ownerSaltBytes = hexToBytes(preimage.ownerSaltHex, 32);
  const rhoBytes = hexToBytes(preimage.rhoHex, 16);
  const rseedBytes = hexToBytes(preimage.rseedHex, 32);

  const out = Array.from({ length: PREIMAGE_LIMB_COUNT }, () => 0);
  out[SLOT_LOGIC_KIND] = logicKindDiscriminant(preimage.logic);
  for (let i = 0; i < 8; i++) out[SLOT_LABEL_ID_START + i] = labelLimbs[i];
  for (let i = 0; i < 8; i++) out[SLOT_VALUE_REF_START + i] = valueRefLimbs[i];
  out[SLOT_OWNER_KIND] = ownerKindDiscriminantFromString(preimage.ownerKind);
  const saltLimbs = bytes32ToLimbs8(ownerSaltBytes);
  for (let i = 0; i < 8; i++) out[SLOT_OWNER_SALT_START + i] = saltLimbs[i];
  const rhoLimbs = bytes16ToLimbs4(rhoBytes);
  for (let i = 0; i < 4; i++) out[SLOT_RHO_START + i] = rhoLimbs[i];
  const rseedLimbs = bytes32ToLimbs8(rseedBytes);
  for (let i = 0; i < 8; i++) out[SLOT_RSEED_START + i] = rseedLimbs[i];
  return out;
}

/// Extract the rho_limbs (4 u32) from a 38-limb preimage.
export function rhoLimbsFromPreimage(preimageLimbs) {
  return preimageLimbs.slice(SLOT_RHO_START, SLOT_RHO_START + 4);
}

/// Hash a 38-limb preimage via Poseidon → 8-limb cm.
export async function commitmentFromLimbs(preimageLimbs) {
  if (preimageLimbs.length !== PREIMAGE_LIMB_COUNT) {
    throw new Error(
      `preimageLimbs length ${preimageLimbs.length} (expected ${PREIMAGE_LIMB_COUNT})`,
    );
  }
  await ensureWasm();
  return JSON.parse(poseidonHash(JSON.stringify(preimageLimbs)));
}

/// Hash a 20-limb nullifier input (witness ‖ rho ‖ cm) → 8-limb nf.
export async function nullifierFromLimbs(witnessLimbs8, rhoLimbs4, cmLimbs8) {
  if (witnessLimbs8.length !== 8 || rhoLimbs4.length !== 4 || cmLimbs8.length !== 8) {
    throw new Error("invalid limb counts for nullifier input");
  }
  await ensureWasm();
  const input = [...witnessLimbs8, ...rhoLimbs4, ...cmLimbs8];
  return JSON.parse(poseidonHash(JSON.stringify(input)));
}

function hexToBytes(hex, expectedLen) {
  if (hex.length !== expectedLen * 2) {
    throw new Error(`expected ${expectedLen * 2}-char hex, got ${hex.length}`);
  }
  const out = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
