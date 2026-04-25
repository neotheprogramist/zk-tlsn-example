# zk-tlsn-example

Stablecoin-settlement demo on TLSNotary + Noir + Barretenberg: three fiat transfers are attested via MPC-TLS, folded into one recursive Honk proof, and settled on-chain for a single mint.

## Prerequisites

- Rust toolchain pinned in `rust-toolchain.toml`.
- [`mise`](https://mise.jdx.dev/) (`mise install` once) — pins Foundry and injects `.env`.
- Node **20+** (stdlib only; no `npm install`).
- Noir / Barretenberg CLIs on `PATH`, ABI-compatible pair:
  - `nargo 1.0.0-beta.20`
  - `bb 5.0.0-nightly.20260324`

  A mismatched pair fails inside the recursive circuit with `Assertion failed: size() == max_size_impl`. Pin with `noirup` / `bbup`.

## Repo layout

| Crate   | Role                                                                                                                                                                                       |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `core/` | Audit-scope library (`zktlsn_core`): `Prover` (native + wasm), `Verifier` (native), HTTP parsers, `FiatTransferAttestation`, per-transfer Noir proof, recursive fold, nargo/bb shell-outs. |
| `demo/` | Native-only integration layer: demo HTTPS ledger, QUIC verifier service, browser WebTransport host, settlement orchestrator, fixture generator, single `zktlsn` binary.                    |

Dependency direction: `demo → core`. `core` builds for both `wasm32-unknown-unknown` (`Prover` only — `verifier` and `zk` are `cfg(not(target_arch = "wasm32"))` because `tlsn::Verifier` and `nargo`/`bb` shell-outs cannot run in a browser) and native. `demo` is native-only. Noir circuits live in `circuits/{attestation,null,recursive}/`; Solidity contracts in `evm/src/`.

```
demo/src/
  main.rs            # single binary, 5 subcommands
  lib.rs             # CLI arg groups + logging
  tls.rs             # cert + QUIC fixtures
  transport.rs       # MPC-TLS prover + verifier transport (QUIC + WebTransport)
  ledger/            # demo HTTPS ledger (out-of-audit)
  browser/           # Flow 1: WebTransport host + WASM page
  settlement/        # Flow 2: on-chain settlement + fixture
```

## Generated assets

`demo/assets/wasm/` is **gitignored**: it holds the wasm-bindgen output
(`core.js`, `core_bg.wasm`, `core.d.ts`, `snippets/`) consumed by Flow 1's
browser page. Generate it with:

```bash
node scripts/build-wasm.mjs
```

That script runs `cargo +nightly build -p zktlsn_core --lib --target
wasm32-unknown-unknown --release`, then `wasm-bindgen` with `--out-dir
demo/assets/wasm --out-name core`, then patches the `web-spawn` snippet's
`import('../../..')` to `import('../../../core.js')` so Chrome can resolve it.
Run it once before `zktlsn service` (Flow 1) or `node scripts/run-attest.mjs`;
re-run whenever `core/src/prover.rs` or `core/Cargo.toml`'s wasm deps change.
The full prerequisite list (nightly Rust, `wasm-bindgen-cli` 0.2.118, a wasm-
capable clang) lives under [Flow 1 — Browser WASM attestation](#flow-1--browser-wasm-attestation).

## Binary

| Subcommand        | Role                                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `zktlsn server`   | Demo HTTPS ledger (salvo). Long-running. Shared by both flows.                                                                   |
| `zktlsn service`  | Browser WebTransport + WASM host. Long-running. Used by Flow 1.                                                                  |
| `zktlsn verifier` | QUIC verifier service — runs the TLSN verifier side of MPC-TLS and returns an attest-only outcome. Long-running. Used by Flow 2. |
| `zktlsn settle`   | Run the 3-transfer batch, aggregate proofs, submit on-chain. One-shot.                                                           |
| `zktlsn fixture`  | Generate deterministic settlement artifacts and deploy settlement contracts. One-shot.                                           |

## Examples vs. e2e tests

_Examples_ are the `zktlsn` subcommands above — run them by hand and read the `ZKTLSN_RESULT` JSON line on stdout. _E2E tests_ are Node harness scripts in `scripts/` that spawn the same subcommands and assert on that same JSON line. Identical flow, identical asserts; only the orchestrator differs. There is no Rust test suite and no mocks — the ledger, verifier, prover, anvil node, and both `nargo` / `bb` invocations are all real.

## Audit scope

The security-relevant surface is one Rust crate + one contract:

| Component                        | Trust property enforced                                                                                                           |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `core::verifier`                 | Only the verifier side: validates the MPC-TLS session, enforces transcript commitment policy, signs the attestation.              |
| `core::zk::{prove, recursive}`   | Generates the per-transfer Honk proof + recursive fold; the aggregate's 7 public inputs are the only thing the contract consumes. |
| `evm/src/SettlementMintGate.sol` | Verifies the aggregated Honk proof, matches three VK hashes, marks `transfers_root` claimed (replay protection), mints tokens.    |
| `core::FiatTransferAttestation`  | Canonical 16-byte attestation encoding shared by the server, the Noir circuit, and the contract.                                  |

Demo scaffolding (out of audit scope): `core::prover` (untrusted client code, runs in browser/native), `demo::ledger`, `demo::browser`, `demo::transport` (prover side only), `demo::settlement`, `zktlsn fixture`, `scripts/*.mjs`, Playwright, anvil. These exist to exercise the flows end-to-end; they are not intended to be production code.

The prover side runs untrusted client code; its correctness matters for liveness and privacy, not for settlement integrity. The settlement guarantee rests entirely on the four rows above.

## Cleanup

Between runs you usually don't need to reset anything; stale state only matters when you change circuits or contracts.

| Directory        | Contents                                                              | Reset command  |
| ---------------- | --------------------------------------------------------------------- | -------------- |
| `.data/`         | Certs, circuit cache, fixture proof bytes, on-chain deployment state. | `rm -rf .data` |
| `target/`        | Rust build output and compiled Noir `.json` artifacts.                | `cargo clean`  |
| `out/`, `cache/` | Foundry build + fixture caches.                                       | `forge clean`  |

Full reset:

```bash
rm -rf .data target out cache
```

## Flow 1 — Browser WASM attestation

The TLSN attestation flow as a web page. The prover is `core::prover::Prover::prove`, compiled to `wasm32-unknown-unknown` and driven from Chrome. The browser opens a **single** WebTransport session to the `zktlsn service` process's `/connect` endpoint and multiplexes both channels over two bidi streams: each stream begins with a role preamble — `VERIFY\n` for the attestation-verifier protocol, `CONNECT <host>:<port>\n` for the raw TCP tunnel to the demo ledger. The service reads the first line on each stream and dispatches to either the TLSN verifier pipeline or the allow-listed TCP forwarder.

The prover runs **inside a dedicated Web Worker**, not on the page's main thread. Every `JsValue` handle it owns — the WebTransport session, both bidi streams, both `WebTransportIo`s, the `Prover` — is constructed and polled on that Worker, which makes `WebTransportIo`'s `unsafe impl Send` sound and keeps MPC-TLS's `parking_lot::Mutex` + `Atomics.wait` on a legal thread. `SharedArrayBuffer` and `crossOriginIsolated` are available because the service serves `Cross-Origin-Embedder-Policy: require-corp` + `Cross-Origin-Resource-Policy: same-origin` on every asset response, including the worker script. tlsn's internal MPC parallelism dispatches onto a `web-spawn` worker pool that `core::prover::initialize()` starts up front, before the `Prover` is constructed.

**Asserted** (from `scripts/run-attest.mjs`): `flow == "notarize-wasm"`, `server_name == "localhost"`, `to_username == "treasury"`, `amount == 25`, `eligible_for_mint == true`, `commitment_count == 2`.

### Prerequisites (in addition to the common ones)

- Node **22+**.
- `npx` on `PATH` — the harness fetches Playwright at runtime; no `package.json` is vendored.
- Rust **nightly** with the `wasm32-unknown-unknown` target and `rust-src`: `rustup toolchain install nightly && rustup component add rust-src --toolchain nightly && rustup target add wasm32-unknown-unknown --toolchain nightly`.
- `wasm-bindgen-cli` matching the workspace's `wasm-bindgen` version (0.2.118): `cargo install wasm-bindgen-cli --version 0.2.118`.
- A clang that can target `wasm32-unknown-unknown` (needed to build `ring`'s C sources). Tested with MacPorts LLVM-22 at `/opt/local/libexec/llvm-22/bin/{clang,llvm-ar}`; configure a different path in `.cargo/config.toml` if yours lives elsewhere.

Playwright downloads its own bundled Chromium the first time it runs (`~/Library/Caches/ms-playwright/` on macOS, `~/.cache/ms-playwright/` on Linux). If it hasn't been run before on this machine, pre-fetch with `npx --yes --package=playwright -- playwright install chromium`.

### Build the browser prover

Plain `cargo build` followed by `wasm-bindgen`, no `wasm-pack`:

```bash
cargo +nightly build -p zktlsn_core --lib --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/zktlsn_core.wasm \
  --out-dir demo/assets/wasm \
  --target web \
  --out-name core
```

The output lands in `demo/assets/wasm/` as `core.js`, `core_bg.wasm`, and `core.d.ts`. The `zktlsn service` subcommand refuses to start if the `.wasm` is missing.

`node scripts/build-wasm.mjs` runs both steps above and applies one necessary patch to the `web-spawn` snippet that wasm-bindgen emits: `import('../../..')` → `import('../../../core.js')`. Chrome can't resolve the former against a directory URL. `tlsn[web]` pulls `web-spawn` in transitively for its MPC worker pool, so the snippet is always emitted and always needs the patch.

### E2E test

```bash
# Harness spawns server + service, launches a real (headed) Chromium window
# via Playwright, navigates to the prover page, clicks "Start attestation",
# and asserts on the ZKTLSN_RESULT console line. The script self-bootstraps
# Playwright via `npx` on first run.
node scripts/run-attest.mjs
```

The Chromium window is visible on purpose. The test closes it automatically on PASS.

### Example (manual)

```dotenv
ZKTLSN_SERVER_ADDR=127.0.0.1:8443
ZKTLSN_SERVER_LISTEN_ADDR=127.0.0.1:8443
ZKTLSN_SERVER_NAME=localhost
ZKTLSN_SERVER_CERT_PATH=.data/tls/server-cert.pem
ZKTLSN_SERVER_KEY_PATH=.data/tls/server-key.pem
ZKTLSN_SERVICE_LISTEN_ADDR=127.0.0.1:8444
ZKTLSN_SERVICE_CERT_DIR=.data/service
ZKTLSN_FROM_USER=alice
ZKTLSN_TO_USER=treasury
ZKTLSN_TRANSFER_AMOUNT=25
```

Then, in three shells (each `cd`'d into the repo root):

```bash
# 1. demo ledger (shell 1, long-running)
cargo run --release --bin zktlsn -- server

# 2. service (shell 2, long-running) — hosts page + WebTransport proxy + browser-facing TLSN verifier.
cargo run --release --bin zktlsn -- service

# 3. open https://127.0.0.1:8444/ in Chrome, click "Start attestation".
#    The page reads cert-hash + connect-url + server details from data-* attributes,
#    spawns a dedicated Worker (/assets/prove.worker.js), opens ONE WebTransport
#    session to /connect with serverCertificateHashes pinning, creates two bidi
#    streams (VERIFY + CONNECT host:port), runs Prover.prove() inside the Worker,
#    and prints ZKTLSN_RESULT {…} in both the on-page log and the browser console.
```

The `zktlsn service` subcommand creates the demo transfer (`POST /api/transfers`) at startup before serving — so by the time you open the page, the tx_id the prover will attest over is already embedded in the HTML as a `data-tx-id` attribute.

## Flow 2 — TLSN + recursive ZK proof + on-chain settlement

Three fiat transfers (`alice → treasury 25`, `bob → treasury 10`, `alice → treasury 15`) each produce a TLSN attestation, each proved against the Noir `attestation` circuit. A `null` circuit produces the initial `(total=0, root=0)` state. Three `recursive` circuit steps then fold the three attestation proofs into one aggregated Honk proof whose 7 public inputs carry `(reserved=0, total_amount, transfers_root, to_user_id, null_vk_hash, recursive_vk_hash, inner_vk_hash)`. The final proof is submitted to `SettlementMintGate.settle`, which verifies the Honk proof, matches all three VK hashes, marks the `transfers_root` as claimed (replay protection), and mints `total_amount × 10¹⁸` stable-token units to the recipient.

**Asserted** (from `scripts/run-settle.mjs`): `num_attestations == 3`, `total_amount == 50`, `to_user_id == 3` (treasury), `claimed_root == true`, `balance_before == "0"`, `balance_delta == "50000000000000000000"`, plus 64-hex `transfers_root`, `null_vk_hash`, `recursive_vk_hash`, `inner_vk_hash`, and `tx_hash`.

### E2E test

```bash
# Harness spawns anvil + `zktlsn fixture` + server + verifier + `zktlsn settle` in sequence
# and asserts on the aggregated mint.
node scripts/run-settle.mjs
```

### Example (manual)

Each shell runs one long-lived process; one extra shell runs the batch driver. Every binary reads its config from environment variables, and `mise.toml` auto-loads them from `.env` when you enter the project directory — so you set them once and forget.

**One-time setup.** Install `mise` (see [Prerequisites](#prerequisites)), then from the repo root:

```bash
mise trust       # authorise mise.toml + .env for this project
mise install     # pin Foundry (and anything else mise.toml declares)
```

Create `.env` in the repo root with the values below. These match `scripts/run-settle.mjs`, which is the source of truth.

```dotenv
ZKTLSN_ANVIL_RPC_URL=http://127.0.0.1:8545
ZKTLSN_ANVIL_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ZKTLSN_MINT_RECIPIENT=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
ZKTLSN_SERVER_ADDR=127.0.0.1:8443
ZKTLSN_SERVER_LISTEN_ADDR=127.0.0.1:8443
ZKTLSN_SERVER_NAME=localhost
ZKTLSN_SERVER_CERT_PATH=.data/tls/server-cert.pem
ZKTLSN_SERVER_KEY_PATH=.data/tls/server-key.pem
ZKTLSN_VERIFIER_ADDR=[::1]:5000
ZKTLSN_VERIFIER_CERT_PATH=.data/quic/verifier-cert.pem
ZKTLSN_QUIC_CERT_PATH=.data/quic/verifier-cert.pem
ZKTLSN_QUIC_KEY_PATH=.data/quic/verifier-key.pem

ZKTLSN_BATCH_FROM_USERS=alice,bob,alice
ZKTLSN_BATCH_TO_USERS=treasury,treasury,treasury
ZKTLSN_BATCH_AMOUNTS=25,10,15
```

Then, in four shells (each `cd`'d into the repo root so mise injects `.env`):

```bash
# 1. anvil (shell 1)
anvil --host 127.0.0.1 --port 8545

# 2. deploy contracts + generate fixture artifacts (shell 2, one-shot)
cargo run --release --bin zktlsn -- fixture

# 3. demo ledger (shell 3, long-running)
cargo run --release --bin zktlsn -- server

# 4. verifier service (shell 4, long-running)
cargo run --release --bin zktlsn -- verifier

# 5. run the 3-transfer settlement batch (shell 2 again)
cargo run --release --bin zktlsn -- settle
```

Step 5 emits the same `ZKTLSN_RESULT` JSON line the e2e test asserts on — identical flow, identical output.

## Forge tests

```bash
forge test -vvv
```

The Solidity gate + replay + VK-hash + tamper asserts in `evm/test/` consume fixture artifacts under `.data/evm/testdata/` produced by `cargo run --bin zktlsn -- fixture` (step 2 of Flow 2). Run that fixture step at least once before `forge test`.
