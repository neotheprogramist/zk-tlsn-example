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

| Crate        | Role                                                                                                                              |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `tlsnotary/` | TLSN attestation core: MPC-TLS prover + verifier + validator + HTTP transcript parser + `Runtime`. No ZK, no on-chain.            |
| `zktlsn/`    | Wrapper on `tlsnotary`: per-attestation ZK proof (`prove_attestation`) + recursive fold (`aggregate_attestations`) via Noir/`bb`. |
| `shared/`    | `FiatTransferAttestation` encoder/parser — the only type shared by server and zktlsn.                                             |
| `e2e/`       | Demo HTTPS ledger, QUIC verifier service, TLS/cert helpers, on-chain submission, and the six runnable binaries.                   |

Dependency direction: `tlsnotary → zktlsn → e2e`. Noir circuits live in `circuits/{attestation,null,recursive}/`; Solidity contracts in `evm/src/`.

## Binaries

| Binary     | Role                                                                                                                                          |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `server`   | Demo HTTPS ledger (salvo). Long-running. Shared by both flows.                                                                                |
| `verifier` | QUIC verifier service — runs the TLSN verifier side of MPC-TLS and returns an attest-only outcome. Long-running. Shared by both flows.        |
| `notarize` | **tlsnotary-only** client: creates a transfer, runs a TLSN session via `verifier`, prints the revealed transcript. No ZK.                     |
| `prove`    | **zktlsn wrapper**: same TLSN attestation as `notarize`, then generates a per-transfer ZK proof via `zktlsn::prove_attestation`.              |
| `fixture`  | Compiles circuits, generates the settlement fixture, deploys contracts to anvil.                                                              |
| `settle`   | **wraps `prove` 3×**: collects 3 TLSN+ZK attestations, folds them via `zktlsn::aggregate_attestations`, submits the aggregate proof on-chain. |

## Examples vs. e2e tests

_Examples_ are the cargo binaries above — run them by hand and read the `ZKTLSN_RESULT` JSON line on stdout. _E2E tests_ are Node harness scripts in `scripts/` that spawn the same binaries and assert on that same JSON line. Identical flow, identical asserts; only the orchestrator differs. There is no Rust test suite and no mocks — the server, verifier, prover, anvil node, and both `nargo` / `bb` invocations are all real.

Both flows share the same `server` and `verifier` processes. The `verifier` service is purely a TLSN attestation service — it never sees a ZK proof. ZK proof generation is a **client-side** step done by `prove` (and by `settle`, which wraps it) using the `zktlsn` library. The on-chain `SettlementMintGate` contract is the real ZK verifier.

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

## Flow 1 — TLSN attestation only

The `notarize` client `POST /transfer`s a 25-unit `alice → treasury` transfer through the demo ledger, opens a TLSN session via the QUIC `verifier` service, and reads back an attest-only outcome. The client then parses the notarised HTTP response body client-side and asserts the revealed fields. No ZK proof is generated.

**Asserted** (from `scripts/run-tlsn.mjs`): `server_name == "localhost"`, `to_username == "treasury"`, `amount == 25`, `eligible_for_mint == true`, `commitment_count == 2`.

### E2E test

```bash
# Harness spawns server + verifier + notarize, asserts ZKTLSN_RESULT.
node scripts/run-tlsn.mjs
```

### Example (manual)

One-time setup (`mise trust` + `mise install`) and `.env` creation are shared with Flow 2 — see the Flow 2 manual block below. Flow 1 uses the same `server` + `verifier` binaries and the same `.env`; it only needs `ZKTLSN_FROM_USER` / `ZKTLSN_TO_USER` / `ZKTLSN_TRANSFER_AMOUNT` in addition.

Then, in three shells (each `cd`'d into the repo root):

```bash
# 1. demo ledger (shell 1, long-running)
cargo run --release --bin server

# 2. verifier service (shell 2, long-running)
cargo run --release --bin verifier

# 3. notarize client (shell 3, one-shot)
cargo run --release --bin notarize
```

The `notarize` binary emits the same `ZKTLSN_RESULT` JSON line the e2e test asserts on. Its call chain uses only `tlsnotary` primitives — zktlsn is not on this path.

## Flow 2 — TLSN + recursive ZK proof + on-chain settlement

Three fiat transfers (`alice → treasury 25`, `bob → treasury 10`, `alice → treasury 15`) each produce a TLSN attestation, each proved against the Noir `attestation` circuit. A `null` circuit produces the initial `(total=0, root=0)` state. Three `recursive` circuit steps then fold the three attestation proofs into one aggregated Honk proof whose 7 public inputs carry `(reserved=0, total_amount, transfers_root, to_user_id, null_vk_hash, recursive_vk_hash, inner_vk_hash)`. The final proof is submitted to `SettlementMintGate.settle`, which verifies the Honk proof, matches all three VK hashes, marks the `transfers_root` as claimed (replay protection), and mints `total_amount × 10¹⁸` stable-token units to the recipient.

**Asserted** (from `scripts/run-settlement.mjs`): `num_attestations == 3`, `total_amount == 50`, `to_user_id == 3` (treasury), `claimed_root == true`, `balance_before == "0"`, `balance_delta == "50000000000000000000"`, plus 64-hex `transfers_root`, `null_vk_hash`, `recursive_vk_hash`, `inner_vk_hash`, and `tx_hash`.

### E2E test

```bash
# Harness spawns anvil + fixture + server + verifier + settle in sequence
# and asserts on the aggregated mint.
node scripts/run-settlement.mjs
```

### Example (manual)

Each shell runs one long-lived process; one extra shell runs the batch driver. Every binary reads its config from environment variables, and `mise.toml` auto-loads them from `.env` when you enter the project directory — so you set them once and forget.

**One-time setup.** Install `mise` (see [Prerequisites](#prerequisites)), then from the repo root:

```bash
mise trust       # authorise mise.toml + .env for this project
mise install     # pin Foundry (and anything else mise.toml declares)
```

Create `.env` in the repo root with the values below. These match `scripts/run-settlement.mjs`, which is the source of truth.

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

# Flow 1 (notarize) — single transfer.
ZKTLSN_FROM_USER=alice
ZKTLSN_TO_USER=treasury
ZKTLSN_TRANSFER_AMOUNT=25

# Flow 2 (settle) — three transfers folded into one aggregated proof.
ZKTLSN_BATCH_FROM_USERS=alice,bob,alice
ZKTLSN_BATCH_TO_USERS=treasury,treasury,treasury
ZKTLSN_BATCH_AMOUNTS=25,10,15
```

Then, in four shells (each `cd`'d into the repo root so mise injects `.env`):

```bash
# 1. anvil (shell 1)
anvil --host 127.0.0.1 --port 8545

# 2. deploy contracts + generate fixture artifacts (shell 2, one-shot)
cargo run --release --bin fixture

# 3. demo ledger (shell 3, long-running)
cargo run --release --bin server

# 4. verifier service (shell 4, long-running)
cargo run --release --bin verifier

# 5. run the 3-transfer settlement batch (shell 2 again)
cargo run --release --bin settle
```

Step 5 emits the same `ZKTLSN_RESULT` JSON line the e2e test asserts on — identical flow, identical output.

## Forge tests

```bash
forge test -vvv
```

The Solidity gate + replay + VK-hash + tamper asserts in `evm/test/` consume fixture artifacts under `.data/evm/testdata/` produced by `cargo run --bin fixture` (step 2 of Flow 2). Run Flow 2's fixture step at least once before `forge test`.
