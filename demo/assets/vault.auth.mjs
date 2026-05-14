// UserKey-flavoured identity + auth_tag for the vault toy.
//
// After audit-2, the entire codebase hashes with one primitive: the
// vault crate's Poseidon2-M31, exposed to JS as `poseidonHash` via
// `/assets/wasm/vault.js`. There is no SHA-256, no Blake2s, no other
// hash function in this module — everything routes through one bridge.
//
// Convention: each byte of the input becomes one M31 limb (lower 8 bits
// used; M31-safe). The hash output is an 8-limb (u32) array; for
// transport / storage we re-pack as 32 bytes little-endian (lower 31
// bits of each limb → 4 bytes; the high bit is always 0 by construction).

import init, { poseidonHash } from "/assets/wasm/vault.js";
import {
  bytes16ToLimbs4,
  bytes32ToLimbs8,
  commitmentFromLimbs,
  encodePreimageLimbs,
  nullifierFromLimbs,
} from "./vault.preimage.mjs";

let wasmReady = null;
async function ensureWasm() {
  if (!wasmReady) wasmReady = init();
  return wasmReady;
}

const enc = new TextEncoder();

export function toHex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// One byte per M31 limb (lower 8 bits used). Lossless and M31-safe.
function bytesToLimbs(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const limbs = Array.from({ length: total });
  let off = 0;
  for (const p of parts) {
    for (let i = 0; i < p.byteLength; i++) {
      limbs[off + i] = p[i];
    }
    off += p.byteLength;
  }
  return limbs;
}

// 8 u32 (M31-safe) → 32 bytes little-endian (lower 31 bits of each u32
// occupy bytes [4*i .. 4*i+3]; bit 31 is always 0 by construction).
function limbsToBytes(limbsU32) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = limbsU32[i] | 0;
    out[4 * i] = v & 0xff;
    out[4 * i + 1] = (v >> 8) & 0xff;
    out[4 * i + 2] = (v >> 16) & 0xff;
    out[4 * i + 3] = (v >> 24) & 0xff;
  }
  return out;
}

/// Hash a sequence of byte sequences via Poseidon2-M31, treating bytes as
/// one M31 limb per byte. Used only for host-only operations (nk derivation
/// from variable-length username bytes, action_digest from JSON payload).
async function poseidonBytes(...parts) {
  await ensureWasm();
  const limbs = bytesToLimbs(...parts);
  const outJson = poseidonHash(JSON.stringify(limbs));
  const outLimbs = JSON.parse(outJson);
  return limbsToBytes(outLimbs);
}

/// Hash a sequence of 32-byte parts via Poseidon2-M31, packing each part
/// as 8 M31-safe limbs (4 bytes per limb, little-endian, top bit masked).
/// Used for the in-circuit-bound hashes (salt = Poseidon(nk),
/// auth_tag = Poseidon(nk ‖ action_digest ‖ cm), cancel auth_tag) so the
/// host-side digest matches what `hash_in_circuit` recomputes from
/// `[u32; 8]` witness limbs.
async function poseidonOf32ByteParts(...parts) {
  await ensureWasm();
  const limbs = [];
  for (const p of parts) {
    if (p.length !== 32) {
      throw new Error(`poseidonOf32ByteParts: every part must be 32 bytes (got ${p.length})`);
    }
    limbs.push(...bytes32ToLimbs8(p));
  }
  const outJson = poseidonHash(JSON.stringify(limbs));
  const outLimbs = JSON.parse(outJson);
  return limbsToBytes(outLimbs);
}

// ─── Derivation helpers ───────────────────────────────────────────────────
//
// Length-distinguished inputs give domain separation without prefix
// tags (matching the in-circuit constraint shape — see
// `vault/src/leaf_circuits.rs::build_userkey_auth`):
//
//   nk         = Poseidon(username_bytes)           // arbitrary length input
//   salt       = Poseidon(nk)                       // 32-byte input
//   auth_tag   = Poseidon(nk ‖ action_digest ‖ cm)  // 96-byte input
//   cm         = Poseidon(serialised_preimage)      // variable-length JSON
//   nf         = Poseidon(witness ‖ rho ‖ cm)       // 80-byte input
//   action_d.  = Poseidon(serialised_action_payload)// variable-length JSON

export async function deriveNk(username) {
  return poseidonBytes(enc.encode(username));
}

export async function deriveUserkeySalt(nk) {
  return poseidonOf32ByteParts(nk);
}

export async function deriveAuthTag(nk, actionDigest, cm) {
  return poseidonOf32ByteParts(nk, actionDigest, cm);
}

export async function deriveActionDigest(payload) {
  return poseidonBytes(enc.encode(JSON.stringify(payload)));
}

/// `cm = Poseidon(canonical_preimage_limbs)` — the same function the
/// Compliance AIR recomputes in-circuit. `resource` carries the host
/// shape with `logic`, `label`, `value_ref`, `ownerKindFamily`,
/// `ownerSaltHex`, `rhoHex`, `rseedHex`. Returns 32 bytes (8 limbs
/// little-endian).
export async function deriveCommitment(resource) {
  const limbs = await encodePreimageLimbs(resource);
  const cmLimbs = await commitmentFromLimbs(limbs);
  return limbsArrayToBytes(cmLimbs);
}

/// `nf = Poseidon(witness ‖ rho ‖ cm)` over the canonical 20-limb
/// nullifier input. `witnessBytes` is 32 bytes (an 8-limb hash like nk
/// or an offer pseudo-witness). Returns 32 bytes.
export async function deriveNullifier(witnessBytes, rhoBytes, cmBytes) {
  const witnessLimbs = bytes32ToLimbs8(witnessBytes);
  const rhoLimbs = bytes16ToLimbs4(rhoBytes);
  const cmLimbs = bytes32ToLimbs8(cmBytes);
  const nfLimbs = await nullifierFromLimbs(witnessLimbs, rhoLimbs, cmLimbs);
  return limbsArrayToBytes(nfLimbs);
}

function limbsArrayToBytes(limbsU32) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const v = limbsU32[i] | 0;
    out[4 * i] = v & 0xff;
    out[4 * i + 1] = (v >> 8) & 0xff;
    out[4 * i + 2] = (v >> 16) & 0xff;
    out[4 * i + 3] = (v >> 24) & 0xff;
  }
  return out;
}

export function freshRho() {
  const out = new Uint8Array(16);
  crypto.getRandomValues(out);
  return out;
}

export function freshRseed() {
  const out = new Uint8Array(32);
  crypto.getRandomValues(out);
  return out;
}
