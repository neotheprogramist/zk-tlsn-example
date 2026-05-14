# zk-tlsn-example

Three browser-WASM ZK demos sharing one local server:

- **`zktls`** (`/zktls`) — a WASM prover runs MPC-TLS against a small fiat-transfer ledger and produces a selectively disclosed attestation that a Rust verifier validates.
- **`zkp`** (`/zkp`) — binary streaming PCD over Stwo: leaves fold into a binary tree of merge proofs whose AIR re-verifies both children in-circuit; the root is host-verified. Runs on a pool of N equivalent worker threads with on-demand cross-worker proof transfer, so independent merges run in parallel.
- **`vault`** (`/vault`) — toy of the unified-ownership Ethereum vault. Resources are owned by a logic (UserKey for users, Offer for self-owned escrows). USDC is the canonical fee kind; other ERC20 kinds register by name. Each Action (transfer / create-offer / solve-offer / cancel-offer) emits one Compliance leaf, one Logic-AIR leaf per touched kind, and a binary fold producing one Action-AIR root — all real Stwo proofs over the same envelope as `zkp`. Offers carry a pluggable challenge family (start with `x + 1 = 2`).

Both crates expose the same shape: a zero-sized `Prover` and `Verifier`, a single closed `Error` enum, and matching `#[wasm_bindgen]` `Prover` / `Verifier` classes for the browser. `zkp` is sync (pure CPU); `zktls` is async (TLS). Transfer-attestation specifics (HTTP request shape, reveal config, schema assertions) live in the `demo` crate, not in `zktls`.

Proof of concept, not production code. Engineering standards live in `GUIDELINES.md`.

## Layout

```
zktls/      Rust crate — TLS notarization library + browser bindings
zkp/        Rust crate — STWO leaf + binary-PCD merge prover
vault/      Rust crate — per-kind Logic-AIR facade over zkp's envelope (toy)
demo/       HTTP/3 service, ledger, landing page
scripts/    Playwright E2E harness + per-flow drivers
```

## Prerequisites

- Stable toolchain pinned in `rust-toolchain.toml` (1.95.0).
- `nightly-2025-07-14` for `zkp`, `vault`, and all three wasm builds:

  ```bash
  rustup toolchain install nightly-2025-07-14 --target wasm32-unknown-unknown
  ```

- `wasm-bindgen-cli` 0.2.118 on `PATH`.
- Node 20+ (Playwright is `npx`-installed on first e2e run).

## Build

`demo/assets/wasm/` is gitignored; `zktls_bg.wasm`, `zkp_bg.wasm`, **and** `vault_bg.wasm` must all exist before the binary will start.

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build -p zktls --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/zktls.wasm \
  --out-dir demo/assets/wasm --target web --out-name zktls
sed -i '' "s|'\.\./\.\./\.\.'|'\.\./\.\./\.\./zktls\.js'|g" \
  demo/assets/wasm/snippets/*/js/spawn.js

RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build -p zkp --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/zkp.wasm \
  --out-dir demo/assets/wasm --target web --out-name zkp

RUSTUP_TOOLCHAIN=nightly-2025-07-14 \
  cargo build -p vault --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/vault.wasm \
  --out-dir demo/assets/wasm --target web --out-name vault
```

The `sed` patches `web-spawn`'s broken dynamic-import path; only `zktls` needs it. On GNU sed drop the `''` after `-i`. Always `--release` — debug builds make MPC-TLS take ~30 s instead of ~3 s.

## Run

```bash
cargo run --release --bin zktlsn
```

Binds on `[::]:8443` (ledger) and `[::]:8444` (HTTP/3 service) by default. All env knobs in `demo/src/main.rs`; defaults work for both walkthroughs and the e2e scripts.

## Manual walkthrough — zktls

1. Build wasm; start the binary; wait for the two `listening` log lines on `:8444`.
2. Open Chrome at `https://localhost:8444/zktls`. Accept the self-signed cert (Advanced → Proceed).
3. Open DevTools → Console.
4. Click **Start attestation**. After ≈3–5 s the console emits `… INFO zktls.notarize.done flow=notarize-wasm to_username=treasury amount=25 eligible_for_mint=true commitment_count=2`. The binary terminal shows the matching `zktls.verifier.outcome.sent success=true`.
5. **Failure mode:** `… ERROR zktls.notarize.failed message="…"` carries the cause.

## Manual walkthrough — zkp

1. Build wasm; start the binary; wait for the two `listening` log lines on `:8444`.
2. Open Chrome at `https://localhost:8444/zkp`. Accept the cert. Open DevTools → Console.
   - Default pool size is `navigator.hardwareConcurrency`. Override with `?pool=N` (e.g. `/zkp?pool=4`).
3. Wait for `zkp.scheduler.booted` in the console.
4. Click **Next** several times (rapidly — clicks are non-blocking). Each click schedules a leaf on the next idle worker; with N workers, up to N leaves prove in parallel (~6 s each). As leaves settle, the MMR streaming rule folds equal-count peaks into merge jobs (~9 s each); independent merges run on different workers in parallel via on-demand cross-worker proof transfer.
5. Click **Verify**. The scheduler cascades any remaining peaks left-to-right into a single root, host-verifies it on the worker that owns the root, and shows `VERIFIED ✓ [0..N-1] count=N` next to the buttons. Console emits `… INFO zkp.scheduler.verified verified=true lo=0 hi=N-1 count=N`.
6. Click **Reset** to clear all state. The worker pool stays alive.
7. **Failure mode:** `… ERROR zkp.scheduler.job.failed message="…"` (or `zkp.verify.failed`) carries the cause.

### Wire format

Every JS↔Rust JSON object uses **camelCase** keys and tags (`#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]` on the boundary types). Rust struct fields stay snake_case in code; only the JSON wire form is camelCase. This applies to vault's `PublicInputs` / `LeafWitness` and zktls's `JsProverInputs` / `JsVerifierInputs`. The viz's `data-air` attributes (e.g., `userKey`, `conservationFungible`, `actionRoot`) mirror the AIR wire-form so CSS selectors stay aligned with the JSON.

## Manual walkthrough — vault

The `/vault` page is a **workbench** layout: inputs on the left, live output on the right. All progress and errors surface **in-page** (event log + inline `.field-error` next to bad inputs) — DevTools is no longer required.

1. Build wasm for all three crates (`zktls`, `zkp`, `vault`); start the binary; wait for the `listening` log lines on `:8444`.
2. Open Chrome at `https://localhost:8444/vault`. Accept the cert.
3. Wait for `pool: N workers ready` in the header (or `vault.scheduler.booted` in the log panel on the right).
4. **Identity** — header dropdown selects the active user (alice / bob / charlie). Each identity's `nk` and `userkey_salt` are deterministic from their username; switching identity changes which resources you can spend.
5. **Inputs column (left):**
   - **mint** — kind / amount / owner / `▸ mint`. Resources appear instantly in the resources section with no proof; minting is the only mock in the toy. **Every Action below burns exactly 1 USDC as fee**, so most flows want a dedicated USDC resource for the fee separate from the input being spent.
   - **resources** — checkbox-select inputs for the next Action. Filter by kind or "mine only". Each row shows uid · kind · amount · owner; hover reveals the commitment hash.
   - **action** — tabbed builder:
     - _Transfer_: consumes the resources checked above (one fungible kind), distributes amounts to recipient rows, pays 1 USDC fee from a separate fee resource.
     - _Create Offer_: locks selected fungible inputs, optional refund-to-self, pick a challenge family (`x + 1 = 2`), pays 1 USDC fee.
     - _Solve Offer_: pick an offer, supply the challenge witness (e.g. `x=1`), pays 1 USDC fee — locked tokens release to the active identity.
     - _Cancel Offer_: only the creator can cancel; locked tokens return to creator, 1 USDC fee.
6. **Output column (right, sticky on wide screens):**
   - **proving** — one sub-tree per pending or recent Action, newest first. Each viz-node shows AIR kind + prove time + proof size; hover for the public-input dump. The Action-AIR root appears once all leaves fold pairwise.
   - **log** — live mirror of the structured `vault.*` event stream (the same one DevTools sees). No need to open DevTools to follow what the page is doing.
   - **challenges** — collapsed by default; expand to see the registered challenge families and how many offers currently use each.
7. **Inline validation:** Any user-facing rejection — _"choose a USDC resource for the fee"_, _"select at least one erc20 resource"_, _"witness does not satisfy declaration"_, _"only the creator may cancel"_, _"fee resource must be distinct from inputs"_ — appears as a red `.field-error` next to the offending input AND in the log. The submit button is disabled while a proof is in flight, so a double-click cannot re-enter the same Action.

**Failure modes** to exercise from the UI:

- Solve with wrong `x` → inline error _"witness does not satisfy declaration"_ on the solve form; offer stays live. The native `cargo test -p vault --release` separately proves the in-circuit constraint also rejects (see `tests/smoke.rs::offer_solve_x_plus_1_eq_2_fails_for_x_eq_2`).
- Cancel by non-creator → inline error _"only the creator …"_ on the cancel form.
- Submit a Transfer with the same resource selected as both an input and the fee → inline error _"fee resource must be distinct from transfer inputs"_; nothing is consumed.
- Conservation-violating transfer (would only happen if the JS bypass were removed) → `cargo test` proves the conservation circuit rejects unbalanced sums (`tests/smoke.rs::conservation_unbalanced_fails`).

### AIR catalog (what each leaf attests in-circuit)

The entire vault toy uses **one hash primitive — Poseidon2-M31** (see `vault/src/poseidon.rs`), used identically by the host (Rust + JS via `vault::wasm::poseidonHash`) and the in-circuit constraints. There is no SHA-256, no Blake2s, no other hash function anywhere in the codebase.

| AIR                    | In-circuit constraint                                                                                                                       | Public outputs (slots 0..3)   | Notes                                                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `compliance`           | **for each consumed/created resource:** `cm == Poseidon(preimage_limbs)`; **for each consumed:** `nf == Poseidon(witness ‖ rho ‖ cm)`       | `(leaf_index, leaf_index, 1)` | up to 4 consumed + 6 created per leaf; preimage is the canonical 38-limb encoding shared with JS (`vault/src/preimage.rs` ↔ `demo/assets/vault.preimage.mjs`) |
| `conservationFungible` | `Σ consumed == Σ created + fee` over private M31 amount witnesses, zero-padded to MAX=8+8                                                   | `(leaf_index, leaf_index, 1)` | one leaf per touched fungible kind                                                                                                                            |
| `offerCreate`          | digest-bound                                                                                                                                | `(leaf_index, leaf_index, 1)` | locked co-creation is host-side                                                                                                                               |
| `offerSolve`           | per registered challenge family: `x_plus_1_eq_2` (constrains `x + 1 == 2`) and `sum_eq_n` (constrains `x + y == n` for a host-declared `n`) | `(leaf_index, leaf_index, 1)` | new challenges plug in by adding one circuit-builder + one JS witness builder                                                                                 |
| `offerCancel`          | **`Poseidon(nk_creator) == creator_userkey_salt` ∧ `Poseidon(nk_creator ‖ action_digest ‖ cm_offer) == cancel_auth_tag`**                   | `(leaf_index, leaf_index, 1)` | only the original creator can produce a valid proof                                                                                                           |
| `userKey`              | **`Poseidon(nk) == userkey_salt` ∧ per consumed: `Poseidon(nk ‖ action_digest ‖ cm) == auth_tag`**                                          | `(leaf_index, leaf_index, 1)` | up to MAX=4 consumed user-key-owned resources per leaf (covers the H6 scenario's 3 ETH inputs + 1 USDC fee)                                                   |
| `actionRoot`           | zkp merge AIR (in-circuit child verification, leaf-index contiguity, count summation)                                                       | `(lo, hi, count)`             | reused verbatim from `zkp/src/recursion.rs::prove_merge`                                                                                                      |

### What's still simulated (toy-only)

The toy enforces every cryptographic invariant inside the circuit using one hash primitive — Poseidon2-M31. Exactly **one** simulation remains:

- **Resource minting** — no proof of any kind. Clicking "mint" creates a resource in the UI as a state mutation; this is the explicit toy substitute for the L1 deposit-indexer that would normally produce a deposit proof.

Caveat: **Poseidon2-M31 round constants** are placeholder values (a deterministic toy formula, not the cryptographic constants the upstream Poseidon2 paper specifies). The constraint set and field arithmetic ARE real Poseidon2; only the constants need replacement with proper Poseidon2-M31 constants for production cryptographic strength.

In-circuit constraints the proof **does** enforce:

- **Compliance**: for every consumed/created resource in an Action, `cm == Poseidon(preimage_limbs)` using the canonical 38-limb encoding shared with JS; for every consumed resource, `nf == Poseidon(witness ‖ rho ‖ cm)` over the canonical 20-limb input.
- **OfferSolve**: the private witness `x` satisfies the registered challenge inside a STARK circuit (`x + 1 == 2` for `x_plus_1_eq_2`).
- **Conservation**: `Σ consumed == Σ created + fee` for every touched fungible kind.
- **UserKey**: `Poseidon(nk) == userkey_salt` and per-consumed-resource `Poseidon(nk ‖ action_digest ‖ cm) == auth_tag`.
- **OfferCancel**: `Poseidon(nk_creator) == creator_userkey_salt` and `Poseidon(nk_creator ‖ action_digest ‖ cm_offer) == cancel_auth_tag`.

The framework refuses to produce a proof for any witness that violates these constraints; the boundary surfaces the rejection as `Error::CircuitValidationFailed`. A malicious host cannot substitute a fabricated `cm` for a real resource or a fabricated `nf` for a fabricated witness — the circuit catches both.

## Automated tests

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo test -p zkp --release   # native unit/integration tests
RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo test -p vault --release # native smoke + hash unit tests
node scripts/e2e-zktls.mjs                                        # ~6 s
node scripts/e2e-zkp.mjs                                          # ~30 s, default ZKP_E2E_LEAVES=4 ZKP_E2E_POOL=4
ZKP_E2E_LEAVES=8 node scripts/e2e-zkp.mjs                         # longer run, more merges
node scripts/e2e-vault.mjs                                        # ~10-12 min, 12 vault scenarios (7 happy + 5 negative)
```

`cargo test -p vault` runs `tests/smoke.rs` and the in-crate `poseidon` + `hash` unit tests:

- `offer_solve_x_plus_1_eq_2_succeeds_for_x_eq_1` — real Stwo proof for `x = 1`.
- `offer_solve_x_plus_1_eq_2_fails_for_x_eq_2` — circuit rejects `x = 2` (no valid proof can be produced).
- `conservation_balanced_succeeds` — `100 = 99 + 1`.
- `conservation_unbalanced_fails` — `100 ≠ 50 + 0` is rejected by the circuit.
- `conservation_multi_in_multi_out_succeeds` — `50 + 70 == 100 + 20` (matches scenario 3 in e2e).
- `digest_bound_compliance_leaf_round_trips` — Compliance leaf prove+verify.
- `fold_two_contiguous_leaves` — Compliance + Conservation fold into one Action-AIR root, verified.
- `userkey_auth_succeeds_for_correct_nk` — Poseidon(nk) == userkey_salt + per-resource auth_tag binding succeeds in-circuit.
- `userkey_auth_fails_for_wrong_nk` — circuit rejects a witness where `Poseidon(nk_wrong) ≠ userkey_salt`.
- `offer_cancel_auth_succeeds_for_creator` — original creator's nk produces a valid cancel proof.
- `offer_cancel_auth_fails_for_non_creator` — attacker's nk produces no valid proof; circuit rejects.
- `compliance_succeeds_for_correct_cm_nf` — `cm = Poseidon(preimage_limbs)` + `nf = Poseidon(witness ‖ rho ‖ cm)` both verified in-circuit; prove + verify round-trip succeeds.
- `compliance_fails_for_wrong_cm` — tampering one limb of the claimed cm makes the circuit refuse.
- `compliance_fails_for_wrong_nf` — tampering one limb of the claimed nf makes the circuit refuse.
- `compliance_fails_for_wrong_preimage` — supplying a different preimage while claiming an honest cm makes the circuit refuse (Poseidon over the tampered preimage diverges from the claimed cm).

`node scripts/e2e-vault.mjs` runs **11 scenarios** end-to-end — every user-facing happy path plus the high-value error paths. Each scenario starts from a clean vault by clicking the in-page **reset vault** button (so a failure mid-suite does not corrupt later scenarios), then drives the demo exclusively through real button clicks via Playwright.

Per-scenario assertions are strict — no soft checks. Each happy path verifies (a) exact per-owner per-kind balances after the action, (b) nullifier-set growth matches consumed-resource count, (c) the balance-conservation invariant (`Σ live amounts == Σ minted` this scenario), (d) the proving tree has the exact expected AIR leaves (and `action_root` merge nodes) for the flow, (e) the action card reaches `data-state="done"`, and (f) the submit button is disabled while a proof is in flight. Each error-path verifies (a) no `vault.action.submit` was emitted, (b) the offending input shows a `.field-error` whose text contains the expected substring, (c) vault state is unchanged.

**Happy paths:**

1. **H1 · mint + transfer (single-kind)** — alice mints 100 + 5 USDC; transfers 60 USDC → bob with the 5-USDC resource as the fee. Same-kind transfer (USDC for both transferred amount and fee) collapses to one Conservation leaf.
2. **H2 · mint + transfer (multi-kind)** — alice mints 100 USDC + 50 ETH; transfers 25 ETH → bob, fee paid in USDC. Two Conservation leaves (ETH + USDC).
3. **H3 · create + solve (trivial challenge)** — alice locks 100 ETH with challenge `x + 1 = 2`; bob solves with `x = 1` and receives the 100 ETH.
4. **H4 · create + solve (with refund)** — alice mints 80 ETH, locks 60, refunds 20 to herself; bob solves and receives 60 ETH. Exercises the `refund_amount > 0` code path.
5. **H5 · create + cancel** — alice locks 30 ETH then cancels her own offer; the 30 ETH returns to alice.
6. **H6 · multi-input transfer** — alice mints three ETH resources (10 + 15 + 25), transfers 18 → bob + 20 → charlie + 12 change to herself. Exercises multi-input consumption + multi-output creation + change.
7. **H7 · create + solve (parametrized sum_eq_n)** — alice locks 50 ETH with challenge `sum_eq_n` and `n: 10`; bob solves with `x = 3, y = 7`. Exercises the parametrized challenge family end-to-end (Rust `OfferSolveSumEqN` dispatch + JS witness builder).

**Error paths:**

7. **E1 · transfer with no fee selected** — inline error on the fee dropdown mentions USDC; no state mutation.
8. **E2 · transfer with no inputs selected** — form-level error mentions "erc20 resource"; no state mutation.
9. **E3 · solve with wrong witness** — bob attempts `x = 2`; JS rejects pre-submission with "witness does not satisfy declaration"; offer stays live.
10. **E4 · cancel by non-creator** — bob attempts to cancel alice's offer; JS rejects with "only the creator"; offer stays live.
11. **E5 · solve with no offer selected** — inline error on the offer dropdown mentions "offer"; no state mutation.

`cargo test -p zkp` runs `tests/recursion.rs` (`tree_of_four_leaves`: 4 leaves → 2 height-1 merges → 1 root) and `tests/mutations.rs` (12 soundness tripwires, including pcs_config-downgrade rejection, non-canonical M31 rejection, and serialization-roundtrip / corrupted-bytes tests for cross-worker proof transfer).

The zkp e2e harness pins `?pool=4` so its parallelism assertions are independent of the host's `navigator.hardwareConcurrency`. It asserts that distinct worker slots prove leaves AND merges (verifying the parallel-merge architecture); override the pool with `ZKP_E2E_POOL=N`.

For a deeper architecture / soundness writeup, see the comments at the top of `demo/assets/zkp.scheduler.mjs` (peak-folding scheduler, cross-worker proof envelope) and the doc comments in `zkp/src/recursion.rs` (merge AIR's host-side and in-circuit checks: contiguity, count summation, range identity, pcs_config canonicality).

Both `e2e-*.mjs` scripts spawn the `zktlsn` binary, launch headed Chromium via Playwright, drive the demo through real button clicks, and assert against the structured event stream from the browser console + the binary's tracing output. PASS prints a JSON summary; FAIL exits non-zero with the failing assertion.

## Lint and format

```bash
cargo clippy -p demo -p zktls --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp -p vault --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp -p zktls -p vault --target wasm32-unknown-unknown -- -D warnings && \
  cargo +nightly-2025-07-14 fmt --all -- --check && \
  npx --yes oxlint && npx --yes oxfmt --check
```

Auto-fix:

```bash
cargo +nightly-2025-07-14 fmt --all && npx --yes oxfmt
```

`zkp` and `vault` need nightly because they pull `stwo`. `demo` and `zktls` build on stable. `fmt` runs under nightly because `.rustfmt.toml` enables unstable options that stable rustfmt silently ignores.
