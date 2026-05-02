# zk-tlsn-example

Two browser-WASM ZK demos sharing one local server:

- **`zktls`** (`/zktls`) — a WASM prover runs MPC-TLS against a small fiat-transfer ledger and produces a selectively disclosed attestation that a native Rust verifier validates.
- **`zkp`** (`/zkp`) — a recursive STWO counter. Click _Generate base proof_, then alternate _Increment_ and _Prove_; each step's proof verifies the previous proof in-circuit (`circuits-stark-verifier`) and binds the new counter via the constraint `n_new = prev_n + 1`. After every prove the Worker also runs a host-side STARK verifier (`zkp::verify::verify_record`) that calls `stwo::core::verifier::verify` against the freshly produced proof and binds `claim.output_values[0]` to the prover-tracked counter. Both proving and verification happen entirely in the browser.

`/` is a landing page with links to each demo. Proof of concept, not production code. Engineering standards live in `GUIDELINES.md`.

## Layout

```
zktls/      Rust crate — TLS notarization library + browser bindings (cdylib + rlib)
zkp/        Rust crate — STWO recursive prover (cdylib + rlib)
demo/       HTTP/3 service, ledger, landing — depends on zktls (native side)
scripts/    E2E harness + per-flow drivers
```

Both wasm crates produce `<crate>_bg.wasm` consumed by `demo/assets/wasm/`. The audit boundary covers `zktls::verifier` (native, gated `cfg(not(target_arch = "wasm32"))`) and the `zkp` recursion glue (`zkp::recursion`, `zkp::verify`); see the [Audit scope](#audit-scope) table below.

## Prerequisites

- Native toolchain pinned in `rust-toolchain.toml` (stable 1.95.0).
- Nightly `nightly-2025-07-14` for both wasm builds (matches stwo's pin):

  ```bash
  rustup toolchain install nightly-2025-07-14 --target wasm32-unknown-unknown
  ```

- `wasm-bindgen-cli` 0.2.118 on `PATH`.
- Node 20+ for the Playwright E2E harnesses.

`.cargo/config.toml` already supplies the wasm32 RUSTFLAGS (`+atomics,+bulk-memory,+mutable-globals,+simd128`); the build commands below don't need to set them.

## Build

`demo/assets/wasm/` is gitignored. Both `zktls_bg.wasm` and `zkp_bg.wasm` must exist before the binary will start.

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

The `sed` line patches `web-spawn 0.2.1`'s generated `snippets/web-spawn-*/js/spawn.js`, which calls `import('../../..')` — that resolves to the wasm-bindgen output directory (a directory, not a file) and the dynamic import 404s. The patch retargets it at the actual `zktls.js` glue. macOS BSD sed; on GNU sed drop the `''` after `-i`. Only `zktls` needs this — `zkp` doesn't pull in `web-spawn`.

`Cargo.lock` pins `ruint = 1.17.2` (newer 1.18.0 needs nightly features the 2025-07-14 toolchain doesn't expose). If a fresh `cargo update` bumps it, run `cargo update -p ruint --precise 1.17.2`.

## Run

```bash
cargo run --release --bin zktlsn
```

Every env var has a sensible default:

| Var                          | Default                 | Role                                              |
| ---------------------------- | ----------------------- | ------------------------------------------------- |
| `ZKTLSN_SERVER_LISTEN_ADDR`  | `[::]:8443`             | ledger socket bind (dual-stack)                   |
| `ZKTLSN_SERVICE_LISTEN_ADDR` | `[::]:8444`             | service socket bind (dual-stack)                  |
| `ZKTLSN_SERVER_ADDR`         | `localhost:8443`        | proxy dial target the service uses for the ledger |
| `ZKTLSN_SERVER_CERT_PATH`    | `.data/server/cert.pem` | ledger TLS cert (auto-created on first run)       |
| `ZKTLSN_SERVER_KEY_PATH`     | `.data/server/key.pem`  | ledger TLS key (auto-created on first run)        |

Override via a `.env` file at the repo root (`mise.toml` declares `_.file = ".env"`).

Both `*_LISTEN_ADDR`s use `[::]` (dual-stack) because Chrome's WebTransport (HTTP/3 over QUIC) prefers IPv6 when resolving `localhost`; a v4-only socket would refuse the QUIC handshake. macOS gives `IPV6_V6ONLY=0` by default, so one `[::]` socket serves both stacks.

Always `--release`. MPC-TLS is heavily optimisation-sensitive; debug builds make a single attestation take ~30 s instead of ~3 s.

## Manual walkthrough — zktls (notarized HTTP attestation)

1. **Build both wasm bundles** (once, or after any `zktls/` / `zkp/` change) — see [Build](#build) above.
2. **Start the binary** (`cargo run --release --bin zktlsn`). Wait for the two `listening` log lines (HTTP/3.0 and HTTP/1.1 on `:8444`).
3. **Open Chrome** at `https://localhost:8444/`. Accept the self-signed cert (Advanced → Proceed). Click **Open zktls demo →** (or navigate directly to `https://localhost:8444/zktls`). The cert SAN covers `localhost`, `127.0.0.1`, and `::1` — any works.
4. **Open DevTools → Console** before clicking.
5. **Click Start attestation.** Chrome spawns a Worker, loads the wasm prover, opens two WebTransport bidi streams, and runs MPC-TLS against the ledger over the second stream while the verifier watches the first.
6. **Watch the console.** Logs use the shared `{ts} LEVEL event_name k=v` grammar (see [Logging](#logging)). After MPC-TLS finishes (≈3–5 s) you'll see, in order:
   - `… INFO zktls.prover.view direction=request bytes=87 body="GET /api/attestations/1 HTTP/1.1\n…"`
   - `… INFO zktls.prover.view direction=response bytes=312 body="HTTP/1.1 200 OK\n…"`
   - `… INFO zktls.notarize.done flow=notarize-wasm server_name=localhost to_username=treasury amount=25 eligible_for_mint=true commitment_count=2`
7. **Cross-check the binary log.** The terminal shows the same grammar:
   - `… INFO zktls.verifier.view direction=request bytes=87 body="…"`
   - `… INFO zktls.verifier.view direction=response bytes=312 body="…"`
   - `… INFO zktls.verifier.outcome.sent success=true`

   The `body` field is a JSON-quoted multi-line string with three byte states:
   - **visible char** — revealed: the verifier sees the actual byte.
   - **`#`** — committed but not revealed: pinned by a hash commitment, value hidden. After `"attestation":` you should see exactly **32 `#`**, matching `zktls::FiatTransferAttestation` (`ATTESTATION_LEN` = 10 + 10 + 12).
   - **`·`** — neither revealed nor committed.

   Distinction comes from `output.transcript.sent_authed()` / `received_authed()` (revealed ranges) and the `Hash` commitments in `output.transcript_commitments`.

8. **Failure mode:** `… ERROR zktls.notarize.failed message="…"` — the prover or verifier rejected; the field carries the cause. Binary stderr shows the matching server-side error.

## Manual walkthrough — zkp (recursive STWO counter)

1. **Build both wasm bundles** — see [Build](#build).
2. **Start the binary** (`cargo run --release --bin zktlsn`). Wait for the two `listening` log lines on `:8444`.
3. **Open Chrome** at `https://localhost:8444/`, accept the cert, click **Open zkp demo →** (or navigate to `https://localhost:8444/zkp`). The page shows a key/value grid (state, steps proven, last prove time, last proof size, status), four buttons, and a scrolling log.
4. **Open DevTools → Console** before clicking.
5. **Click Generate base proof.** After the prove + verify cycle the state shows `0 ✓ verified` and the console emits `… INFO zkp.proof.done kind=base counter=0 prove_ms=NNNN proof_size_bytes=NNNN verified=true verify_ms=NNNN steps_proven=1`. The Worker calls `Prover::verify_current()` immediately after `prove_base()`, so the `verified` field is a real host-side STARK check (`zkp::verify::verify_record`), not a label.
6. **Click Increment.** State shows `1 (pending — click Prove)`.
7. **Click Prove.** The worker builds the inductive circuit: `circuits-stark-verifier::verify(...)` re-checks the prev proof, then `n_new = prev_n + 1` is enforced via `eq(context, n_new_var, add(context, prev_n_var, one))`. The Worker again runs `verify_current()` and emits `… INFO zkp.proof.done kind=step counter=1 prev_counter=0 verified=true …`.
8. **Repeat Increment + Prove** as desired. From step 2 onward prove times stabilise — the constant-size-recursion punchline.
9. **Click Reset** to drop in-memory state. State doesn't persist across reloads.
10. **Failure mode:** `… ERROR zkp.proof.failed message="…"` — the worker rejected the prove or the host verifier rejected the proof; the field carries the exception.

The chain is fully deterministic — same trivial base proof every time, same step-shape proofs from step 1 onward. Proof size is set by the explicit `PcsConfig` in `zkp::recursion::tuned_pcs_config` (`pow_bits = 20`, `log_blowup = 1`, `n_queries = 19` ≈ 39-bit FRI soundness); switching back to `PcsConfig::default()` would shrink proofs but drop soundness to ~13 bits. 39 bits is the WASM ceiling — a higher `n_queries` trips an upstream `unreachable` panic inside the in-circuit step verifier in the browser; the host `cargo test` accepts any setting. See the doc comment on `tuned_pcs_config` for the trade-off.

## Logging

One event grammar across the whole stack:

```
{rfc3339-ts}  {LEVEL} {event_name} key=value key=value ...
```

- `event_name` is dot-namespaced (e.g. `demo.transfer.seeded`, `zktls.notarize.done`, `zkp.prove.step.done`, `runtime.page.error`).
- Field values are bare for `[A-Za-z0-9_.-]+`; anything else is JSON-stringified (`body="multi\nline"`).
- Multi-line bodies (the rendered `verifier-view`/`prover-view` transcripts) live inside one quoted field; assertions key off `bytes=` / `direction=` and parse the body back via `JSON.parse`.

Three producers, one grammar:

- **Rust native** — `tracing-subscriber::fmt().compact().with_timer(UtcTime::rfc_3339()).with_ansi(false)`. Initialised once in `demo/src/lib.rs`. Override the filter with `RUST_LOG=…`.
- **Rust wasm** (`zkp/src/lib.rs`) — `event_info(name, &[(key, &display)])` builds the same line and ships it through `web_sys::console::log_1`.
- **JS** (`demo/assets/log.mjs`) — `event(name, fields)` / `eventWarn` / `eventErr` build the same line and call `console.log` / `console.error`.

The Playwright harness (`scripts/lib/harness.mjs`) parses lines via `parseEventLine`, then `expectEvent`, `expectEventInOrder`, and `expectEventCount` match structurally on `event` + `fields`. Both browser (CDP-backed `page.on("console")`) and backend (`spawnCargoBinary` stdout/stderr) feed the same parser. There is no in-page log widget — DevTools console is the source of truth.

## Tests

The repo's correctness signal is the two E2E scripts plus the `zkp` host integration tests. Run all three before merging:

```bash
RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo test -p zkp --release
node scripts/e2e-zktls.mjs    # drives /zktls
node scripts/e2e-zkp.mjs      # drives /zkp
```

`cargo test -p zkp` runs `tests/recursion.rs` (3-step happy-path: base → step → step + host verifier on each) and `tests/mutations.rs` (4 transcript-mutation tripwires that assert the prover or verifier rejects when any one of `claim.output_values[0]`, `params.n_blake_gates`, `params.output_addresses[0]`, or `stark_proof.commitments[0]` is corrupted). It needs the same nightly toolchain the wasm build uses because `stwo` requires nightly features.

Both `e2e-*.mjs` scripts spawn the `zktlsn` binary, launch headed Chromium (Playwright is `npx`-installed on first run), drive the demo through real button clicks, and assert against three observation surfaces. All assertions go through the structured event grammar (see [Logging](#logging)) — `expectEvent`, `expectEventInOrder`, `expectEventCount` over a parsed `{ts, level, event, fields}` record:

1. **Browser DevTools Protocol stream.** Every `console.*` call lands in the harness as a candidate event; the parser keys off `event=` to skip Playwright noise.
2. **Backend tracing output.** The `zktlsn` binary's stdout/stderr, parsed with the same grammar.
3. **Page errors / failed requests.** `pageerror` and `requestfailed` events from Playwright's CDP handlers — neither must occur.

### `e2e-zktls.mjs` — zktls flow

Result-event assertions (one `zktls.notarize.done`):

- `flow=notarize-wasm`, `server_name=localhost`, `to_username=treasury`, `amount=25`, `eligible_for_mint=true`, `commitment_count=2`.

Backend events (in order):

- `demo.transfer.seeded tx_id=1 from=alice to=treasury amount=25`,
- `demo.service.listening`, `demo.ledger.listening listen_addr=127.0.0.1:8443`,
- ≥1 `demo.ledger.connection.accepted`, exactly one `demo.ledger.attestations.lookup tx_id=1`,
- one `zktls.notarize.transcript.received` with `server_name=localhost`, `commitment_count=2`, `sent_len=87`, `received_len=312`,
- one `zktls.verifier.view direction=request bytes=87` and one `direction=response bytes=312`,
- the response-direction `body=` field (a JSON-quoted multi-line string) contains exactly 32 `#` after `"attestation":` (= `ATTESTATION_LEN`), plus revealed `"toUsername":"treasury"` and `"eligibleForMint":true`,
- one `zktls.verifier.outcome.sent success=true`,
- no `ERROR` lines beyond Chrome's harmless `demo.ledger.connection.error error=tls handshake eof` TCP probe.

Browser console events (in order):

- `zktls.action.start.click`, `zktls.worker.wasm.init.start` → `done`, `zktls.worker.pool.start` → `ready`, `zktls.transport.session.opening` → `ready`, `zktls.transport.streams.creating` → `preambles_written`, `zktls.prover.constructing` → `prove_streams.start` → `prove_streams.done`,
- `zktls.prover.view direction=request bytes=87` and `direction=response bytes=312` — the response-direction `body` contains `HTTP/1.1 200 OK`, `"toUsername":"treasury"`, and `"amount":25`,
- `zktls.transport.session.closed`, then exactly one `zktls.notarize.done`,
- zero `zktls.notarize.failed`, zero `runtime.page.error`, zero `pageerror`, zero `requestfailed`.

### `e2e-zkp.mjs` — zkp flow

Default `N=3` inductive steps; override with `ZKP_E2E_STEPS`. Result-event assertions (one base + N steps of `zkp.proof.done`):

- counter chain advances by exactly `+1` per Increment/Prove pair, ending at `N`,
- every `proof_size_bytes ∈ [5_000, 1_000_000]`, every `prove_ms ∈ [0, 600_000]`, every `verify_ms ∈ [0, 600_000]`,
- every `verified=true` (pinned in addition to `expectEventCount({event:"zkp.proof.failed"}, 0)`, so a silent boolean flip can't slip past),
- prove times for steps 2+ stay within ±50 % of their mean (uniform-recursion sanity check),
- the page-displayed state grid agrees with the final counter.

Backend events (zkp runs entirely in the browser, so backend just serves files):

- `demo.service.listening` is present,
- no `zktls.notarize.transcript.received` (must not appear),
- no `ERROR` lines beyond the allowed Chrome TCP probe.

Browser console events (in order):

- page boot: `zkp.page.loading`, `zkp.worker.ready`, `zkp.action.prove_base.click`, `zkp.prove.base.start` → `zkp.prove.base.done` → `zkp.verify.done` → `zkp.proof.done kind=base`,
- per step `i` in 1..N: `zkp.action.increment.click pending=i`, `zkp.action.prove_step.click prev_counter=i-1 counter=i`, `zkp.prove.step.start prev_counter=i-1`, `zkp.prove.step.done prev_counter=i-1 counter=i`, `zkp.verify.done`, `zkp.proof.done kind=step counter=i`,
- exactly 1 `zkp.proof.done kind=base` + exactly N `zkp.proof.done kind=step`, zero `zkp.proof.failed`, zero `runtime.page.error`, zero `pageerror`, zero `requestfailed`.

After the loop, the harness prints a JSON summary `{ flow, final_counter, base_prove_ms, base_verify_ms, base_size_bytes, step_count, step_prove_ms[], step_verify_ms[], step_size_bytes[] }` for the human reader and exits 0.

## Audit scope

| Component                        | Trust property enforced                                                                                                                                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `zktls::verifier`                | Validates the MPC-TLS session, enforces transcript commitment policy, validates disclosed transfer fields.                                                                                                                                 |
| `zktls::flow`                    | Canonical request, reveal config, and TLS config for the fixed transfer-attestation flow.                                                                                                                                                  |
| `zktls::FiatTransferAttestation` | 32-character zero-padded decimal attestation encoding shared by ledger and verifier.                                                                                                                                                       |
| `zkp::recursion`                 | Base AIR fixes `n=0`; step AIR verifies the prev proof in-circuit and constrains `n_new = prev_n + 1`; rejects the one M31 boundary that wraps; PcsConfig pinned to ~39-bit FRI soundness (the WASM ceiling — see `tuned_pcs_config` doc). |
| `zkp::verify`                    | Host-side STARK verifier that re-runs `stwo::core::verifier::verify` against the produced `CircuitProof` and binds `claim.output_values[0]` to `record.counter`.                                                                           |

Out of scope: `zktls::prover`, `zktls::parser`, `zktls::wasm`, `demo/*`, `scripts/*.mjs`, Playwright. Those exercise the flows; they are not the trust boundary.

`zkp/*` ships its own host-side STARK verifier (`zkp::verify::verify_record`, exposed to JS as `Prover::verify_current`) and is exercised by `zkp/tests/recursion.rs` (3-step happy-path) and `zkp/tests/mutations.rs` (4 transcript-mutation tripwires). The crate uses an explicit `PcsConfig` (`pow_bits = 20`, `log_blowup = 1`, `n_queries = 19` ≈ 39-bit FRI soundness) — well below an audit-grade 96 bits, but the highest setting the in-circuit step verifier tolerates inside browser WASM today (higher hits an upstream `unreachable` panic; see the doc comment on `tuned_pcs_config` and upstream [stwo#1311 — "Uncaught panics on invalid FRI inputs"](https://github.com/starkware-libs/stwo/issues/1311)). The audit-grade soundness gap is also tracked upstream as [stwo#1399 — "Necessity to write a comment in PcsConfig::default to indicate that it is insecure"](https://github.com/starkware-libs/stwo/issues/1399), which calls out that `PcsConfig::default()` should be renamed `default_insecure`. Cryptographic soundness still bottoms out on the upstream `stwo` + `stwo-circuits` primitives; the recursion glue, the prover-claim/host-verifier binding, and the counter-overflow guard are local concerns and reviewable here.

## Lint and format

```bash
cargo clippy --workspace --exclude zkp --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp --all-targets -- -D warnings && \
  RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo clippy -p zkp --target wasm32-unknown-unknown --all-targets -- -D warnings && \
  cargo +nightly-2025-07-14 fmt --all -- --check && \
  npx --yes oxlint && npx --yes oxfmt --check
```

`zkp` is split off because its host build now pulls `stwo` (for the host verifier `zkp::verify::verify_record`), and `stwo` needs the same nightly toolchain the wasm build uses. Everything else stays on stable, where `salvo` requires `1.92`+.

Auto-fix formatting in place:

```bash
cargo +nightly-2025-07-14 fmt --all && npx --yes oxfmt
```

`fmt` runs under nightly because `.rustfmt.toml` enables `imports_granularity`, `group_imports`, `format_code_in_doc_comments`, and `condense_wildcard_suffixes` — all unstable options that stable rustfmt silently ignores.
