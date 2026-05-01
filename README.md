# zk-tlsn-example

Two browser-WASM ZK demos sharing one local server:

- **`zktls`** (`/zktls`) — a WASM prover runs MPC-TLS against a small fiat-transfer ledger and produces a selectively disclosed attestation that a native Rust verifier validates.
- **`zkp`** (`/zkp`) — a recursive STWO counter. Click _Generate base proof_, then alternate _Increment_ and _Prove_; each step's proof verifies the previous proof in-circuit (`circuits-stark-verifier`) and binds the new counter via the constraint `n_new = prev_n + 1`. Both proving and verification happen entirely in the browser via stwo + stwo-circuits.

`/` is a landing page with links to each demo. Proof of concept, not production code. Engineering standards live in `GUIDELINES.md`.

## Layout

```
zktls/      Rust crate — TLS notarization library + browser bindings (cdylib + rlib)
zkp/        Rust crate — STWO recursive prover (cdylib + rlib)
demo/       HTTP/3 service, ledger, landing — depends on zktls (native side)
scripts/    E2E harness + per-flow drivers
```

Both wasm crates produce `<crate>_bg.wasm` consumed by `demo/assets/wasm/`. The audit boundary is `zktls::verifier` (native, gated `cfg(not(target_arch = "wasm32"))`).

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
6. **Watch the console.** After MPC-TLS finishes (≈3–5 s) you'll see, in order:
   - `prover-view REQUEST (NN bytes, full): GET /api/attestations/1 …`
   - `prover-view RESPONSE (NN bytes, full): HTTP/1.1 200 OK …`
   - `ZKTLS_RESULT {"flow":"notarize-wasm","server_name":"localhost","to_username":"treasury","amount":25,"eligible_for_mint":true,"commitment_count":2}`
7. **Cross-check the binary log.** The terminal shows:
   - `verifier-view REQUEST (NN bytes; revealed = visible char, # = committed-not-revealed, · = redacted): …`
   - `verifier-view RESPONSE (…): …`
   - `Sending verification outcome success=true`

   Three byte states in `verifier-view`:
   - **visible char** — revealed: the verifier sees the actual byte.
   - **`#`** — committed but not revealed: pinned by a hash commitment, value hidden. After `"attestation":` you should see exactly **32 `#`**, matching `zktls::FiatTransferAttestation` (`ATTESTATION_LEN` = 10 + 10 + 12).
   - **`·`** — neither revealed nor committed.

   Distinction comes from `output.transcript.sent_authed()` / `received_authed()` (revealed ranges) and the `Hash` commitments in `output.transcript_commitments`.

8. **Failure mode:** `ZKTLS_ERROR …` instead of `ZKTLS_RESULT …` — the prover or verifier rejected; the message contains the cause. Binary stderr shows the matching server-side error.

## Manual walkthrough — zkp (recursive STWO counter)

1. **Build both wasm bundles** — see [Build](#build).
2. **Start the binary** (`cargo run --release --bin zktlsn`). Wait for the two `listening` log lines on `:8444`.
3. **Open Chrome** at `https://localhost:8444/`, accept the cert, click **Open zkp demo →** (or navigate to `https://localhost:8444/zkp`). The page shows a key/value grid (state, steps proven, last prove time, last proof size, status), four buttons, and a scrolling log.
4. **Open DevTools → Console** before clicking.
5. **Click Generate base proof.** After ≈6–8 s the state shows `0 ✓ verified` and the console emits `ZKP_RESULT {"kind":"base","counter":0,"prove_ms":NNNN,"proof_size_bytes":~51000,"steps_proven":1}`.
6. **Click Increment.** State shows `1 (pending — click Prove)`.
7. **Click Prove.** Status flips to `proving 0→1…`. The worker builds the inductive circuit: `circuits-stark-verifier::verify(...)` re-checks the prev proof, then `n_new = prev_n + 1` is enforced via `eq(context, n_new_var, add(context, prev_n_var, one))`. After ≈7–8 s `ZKP_RESULT {"kind":"step","counter":1,…}` lands.
8. **Repeat Increment + Prove** as desired. From step 2 onward prove times stabilise — the constant-size-recursion punchline.
9. **Click Reset** to drop in-memory state. State doesn't persist across reloads.
10. **Failure mode:** `ZKP_ERROR …` (status badge red) — the worker rejected the prove; the line carries the exception.

The chain is fully deterministic — same trivial base proof every time, same step-shape proofs from step 1 onward, same `~48–51 KB` band.

## Tests

The repo's correctness signal is the two E2E scripts. There are no `cargo test` unit tests — they would only re-cover what the E2E flow already exercises end-to-end, and the audit narrative is "click a button, watch the trust boundary do its thing." Run both before merging:

```bash
node scripts/e2e-zktls.mjs    # drives /zktls
node scripts/e2e-zkp.mjs      # drives /zkp
```

Both spawn the `zktlsn` binary, launch headed Chromium (Playwright is `npx`-installed on first run), drive the demo through real button clicks, and assert against three observation surfaces:

1. **JSON results.** The structured `ZKTLS_RESULT` / `ZKP_RESULT` lines on the page console.
2. **Backend tracing output.** The `zktlsn` binary's stdout/stderr, captured line-by-line.
3. **Browser DevTools Protocol stream.** Every `console.*` call, every `pageerror`, every `requestfailed` event from Playwright's CDP-backed event handlers.

### `e2e-zktls.mjs` — zktls flow

Result-JSON assertions (one `ZKTLS_RESULT`):

- `flow=notarize-wasm`, `server_name=localhost`, `to_username=treasury`, `amount=25`, `eligible_for_mint=true`, `commitment_count=2`.

Backend tracing (in order):

- ledger seed line (`tx_id=1 from=alice to=treasury amount=25`),
- `service: listening on https://...`, `listening [HTTP/3.0]`, `listening [HTTP/1.1]`,
- ≥1 `Accepted connection`, exactly one `starting MPC-TLS` → `finished MPC-TLS`,
- exactly one `GET /api/attestations tx_id=1` (ledger hit),
- one `Received notarization transcript` with `server_name=localhost`, `commitment_count=2`, `sent_len=87`, `received_len=312`,
- one `verifier-view REQUEST (87 bytes;` and one `verifier-view RESPONSE (312 bytes;`,
- response-body line shows **exactly 32 `#`** after `"attestation":` (= `ATTESTATION_LEN`), plus revealed `"toUsername":"treasury"` and `"eligibleForMint":true`,
- one `Sending verification outcome success=true`,
- no `ERROR` lines beyond Chrome's harmless `tls handshake eof` TCP probe.

Browser CDP console (in order):

- worker boot sequence: `spawning prover worker`, `initialising WASM`, `starting web-spawn worker pool`, `opening WebTransport session`, `WebTransport session ready`, `creating verifier + proxy bidi streams`, `role preambles written`, `constructing Prover`, `running prover.prove_streams`,
- `prover-view REQUEST (87 bytes, full):` and `prover-view RESPONSE (312 bytes, full):` — the latter contains `HTTP/1.1 200 OK`, `"toUsername":"treasury"`, and `"amount":25`,
- `WebTransport session closed`, then exactly one `ZKTLS_RESULT`,
- zero `ZKTLS_ERROR`, zero `pageerror`, zero `requestfailed`, zero unexpected `console.error`.

### `e2e-zkp.mjs` — zkp flow

Default `N=3` inductive steps; override with `ZKP_E2E_STEPS`. Result-JSON assertions (one base + N steps):

- counter chain advances by exactly `+1` per Increment/Prove pair, ending at `N`,
- every `proof_size_bytes ∈ [5_000, 500_000]`, every `prove_ms ∈ [0, 600_000]`,
- prove times for steps 2+ stay within ±50 % of their mean (uniform-recursion sanity check),
- the page-displayed state grid agrees with the console-emitted final counter.

Backend tracing (zkp runs entirely in the browser, so backend just serves files):

- `service: listening on...`, `listening [HTTP/3.0]`, `listening [HTTP/1.1]`,
- `starting MPC-TLS` and `Received notarization transcript` must **not** appear,
- no `ERROR` lines beyond the allowed Chrome TCP probe.

Browser CDP console:

- page boot: `loading wasm…`, `worker ready (wasm init …)`, `→ prove_base`, `zkp: prove_base start` / `done ms=N size=N`, `ZKP_RESULT {"kind":"base"}`,
- per step `i` in 1..N: `+ increment (pending i)`, `→ prove_step (i-1)→i`, `zkp: prove_step from n=(i-1) start`, `zkp: prove_step n=(i-1)->i done ms=N size=N`, `step (i-1)→i (verifies step-shape): prove ... size ... B`, `ZKP_RESULT {"kind":"step","counter":i,…}`,
- exactly 1 `ZKP_RESULT base` + exactly N `ZKP_RESULT step`, zero `ZKP_ERROR`, zero `pageerror`, zero `requestfailed`.

After the loop, emits one `ZKP_E2E_RESULT { flow, final_counter, base_prove_ms, base_size_bytes, step_count, step_prove_ms[], step_size_bytes[] }` summary line and exits 0.

## Audit scope

| Component                        | Trust property enforced                                                                                    |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `zktls::verifier`                | Validates the MPC-TLS session, enforces transcript commitment policy, validates disclosed transfer fields. |
| `zktls::flow`                    | Canonical request, reveal config, and TLS config for the fixed transfer-attestation flow.                  |
| `zktls::FiatTransferAttestation` | 32-character zero-padded decimal attestation encoding shared by ledger and verifier.                       |

Out of scope: `zktls::prover`, `zktls::parser`, `zktls::wasm`, `demo/*`, `zkp/*`, `scripts/*.mjs`, Playwright. Those exercise the flows; they are not the trust boundary. The `zkp` demo's trust properties are the upstream `stwo` + `stwo-circuits` libraries', not this repo's.

## Lint and format

```bash
cargo clippy --workspace --all-targets -- -D warnings && \
  cargo +nightly-2025-07-14 fmt --all -- --check && \
  npx --yes oxlint && npx --yes oxfmt --check
```

Auto-fix formatting in place:

```bash
cargo +nightly-2025-07-14 fmt --all && npx --yes oxfmt
```

`fmt` runs under nightly because `.rustfmt.toml` enables `imports_granularity`, `group_imports`, `format_code_in_doc_comments`, and `condense_wildcard_suffixes` — all unstable options that stable rustfmt silently ignores.
