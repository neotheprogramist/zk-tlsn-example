# zk-tlsn-example

Two browser-WASM ZK demos sharing one local server:

- **`zktls`** (`/zktls`) — a WASM prover runs MPC-TLS against a small fiat-transfer ledger and produces a selectively disclosed attestation that a native Rust verifier validates.
- **`zkp`** (`/zkp`) — binary streaming PCD over Stwo: leaves fold into a binary tree of merge proofs whose AIR re-verifies both children in-circuit; the root is host-verified. Runs on a pool of N equivalent worker threads with on-demand cross-worker proof transfer, so independent merges run in parallel.

Proof of concept, not production code. Engineering standards live in `GUIDELINES.md`.

## Layout

```
zktls/      Rust crate — TLS notarization library + browser bindings
zkp/        Rust crate — STWO leaf + binary-PCD merge prover
demo/       HTTP/3 service, ledger, landing page
scripts/    Playwright E2E harness + per-flow drivers
```

## Prerequisites

- Stable toolchain pinned in `rust-toolchain.toml` (1.95.0).
- `nightly-2025-07-14` for `zkp` and both wasm builds:

  ```bash
  rustup toolchain install nightly-2025-07-14 --target wasm32-unknown-unknown
  ```

- `wasm-bindgen-cli` 0.2.118 on `PATH`.
- Node 20+ (Playwright is `npx`-installed on first e2e run).

## Build

`demo/assets/wasm/` is gitignored; both `zktls_bg.wasm` and `zkp_bg.wasm` must exist before the binary will start.

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

## Automated tests

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo test -p zkp --release   # native unit/integration tests
node scripts/e2e-zktls.mjs                                        # ~6 s
node scripts/e2e-zkp.mjs                                          # ~30 s, default ZKP_E2E_LEAVES=4 ZKP_E2E_POOL=4
ZKP_E2E_LEAVES=8 node scripts/e2e-zkp.mjs                         # longer run, more merges
```

`cargo test -p zkp` runs `tests/recursion.rs` (`tree_of_four_leaves`: 4 leaves → 2 height-1 merges → 1 root) and `tests/mutations.rs` (9 soundness tripwires, including pcs_config-downgrade rejection and serialization-roundtrip / corrupted-bytes tests for cross-worker proof transfer).

The zkp e2e harness pins `?pool=4` so its parallelism assertions are independent of the host's `navigator.hardwareConcurrency`. It asserts that distinct worker slots prove leaves AND merges (verifying the parallel-merge architecture); override the pool with `ZKP_E2E_POOL=N`.

For a deeper architecture / soundness writeup including the cross-worker proof envelope and the MMR / PCD invariants the scheduler preserves, see [STWO_SOLIDITY_SERIALIZATION.md](STWO_SOLIDITY_SERIALIZATION.md) (proof wire-format reference) and the comments at the top of `demo/assets/zkp.scheduler.mjs`.

Both `e2e-*.mjs` scripts spawn the `zktlsn` binary, launch headed Chromium via Playwright, drive the demo through real button clicks, and assert against the structured event stream from the browser console + the binary's tracing output. PASS prints a JSON summary; FAIL exits non-zero with the failing assertion.

## Lint and format

```bash
cargo clippy --workspace --exclude zkp --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp --target wasm32-unknown-unknown --all-targets -- -D warnings && \
  cargo +nightly-2025-07-14 fmt --all -- --check && \
  npx --yes oxlint && npx --yes oxfmt --check
```

Auto-fix:

```bash
cargo +nightly-2025-07-14 fmt --all && npx --yes oxfmt
```

`zkp` is split off because its host build pulls `stwo` (nightly required). `fmt` runs under nightly because `.rustfmt.toml` enables unstable options that stable rustfmt silently ignores.
