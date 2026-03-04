# zk-tlsn-example

Zero-knowledge TLS notarization system combining [TLSNotary](https://tlsnotary.org/) transcript capture with [Noir](https://noir-lang.org/)-based ZK proofs. Proves facts about encrypted web traffic (e.g., "my balance is above X") without revealing the full response.

## Prerequisites

Install the following tools:

**Rust** (`1.93.1` is auto-selected via `rust-toolchain.toml`):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

**Noir** ([docs](https://noir-lang.org/docs/)):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --version 1.0.0-beta.8
```

**Barretenberg** ([docs](https://barretenberg.aztec.network/docs/)) — only needed for standalone circuit proving/verifying outside of Rust:

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```

> **Network note:** Running Rust examples/tests that call `zktlsn::setup_barretenberg_srs()` requires internet access on first run to download CRS data from `https://crs.aztec.network`.

## Quick Start

```bash
git clone <repo-url> && cd zk-tlsn-example

# Compile the Noir circuit (generates target/circuit.json, required before cargo build)
nargo compile

# Build the project
cargo build --release

# Run all tests
cargo test --release
```

> **Version mismatch warning:** The `noir-rs` Rust crate pins to nargo **v1.0.0-beta.8**. Using a different nargo version to compile the circuit will cause a runtime abort (`SIGABRT: Rust cannot catch foreign exceptions`) because the Barretenberg C++ backend rejects incompatible bytecode formats.

## Contracts Dependencies

Install contract libraries locally (not tracked in git):

```bash
cd contracts
forge install --no-git foundry-rs/forge-std
forge install --no-git anhelinakruk/poseidon2-M31-solidity
```

## Test

```bash
cargo test --release                               # All workspace tests (15 tests, ~35s)
cargo test --package parser --release             # Parser crate only
cargo test --package tlsnotary --release          # TLS notarization protocol tests (~17s)
cargo test --package zktlsn --release             # ZK proof tests (~10s, runs Barretenberg)
cargo test --lib --release                        # Library tests only, skip doc-tests
```

## Lint & Format

```bash
cargo clippy                   # Lint
cargo fmt                      # Format (config in .rustfmt.toml)
cargo fmt -- --check           # Check only
```

## Noir Circuit

```bash
nargo test                                                                                    # Test circuit
nargo compile                                                                                 # Compile circuit
nargo execute                                                                                 # Generate witness
bb prove -b ./target/circuit.json -w ./target/circuit.gz --write_vk -o target/circuit         # Prove
bb verify -i ./target/circuit/public_inputs -p ./target/circuit/proof -k ./target/circuit/vk   # Verify
```

## Running the Examples

The full end-to-end flow requires three processes. Start them **in order** in separate terminals and wait for each to print its "listening" message before starting the next:

**Terminal 1 — Backend server** (serves balance data over TLS on `localhost:8443`):

```bash
cargo run --package zktlsn --release --example server
# Wait for: "TLS server listening on localhost:8443"
```

**Terminal 2 — Verifier/Notary** (QUIC-based notary service on `localhost:5000`):

```bash
cargo run --package zktlsn --release --example verifier
# Wait for: "Reliable streams server listening on [::1]:5000"
```

**Terminal 3 — Prover** (connects to both, generates and submits ZK proof):

```bash
cargo run --package zktlsn --release --example prover
```

The prover will:

1. Open one QUIC bi-directional stream to the Verifier
2. Run TLSNotary notarization over that stream using `tlsn::Session<Io>`
3. Make a TLS request to the Backend through the MPC-TLS protocol
4. Generate a ZK proof (HONK via Barretenberg) from the notarized transcript
5. Submit the proof and receive verification result on the same stream

On success you'll see: `Full ZK-TLS notarization and verification flow completed successfully!`

## Architecture

```
zktlsn (examples: prover, server, verifier)
  ├── tlsnotary   — TLS notarization protocol (wraps tlsn crate)
  ├── parser      — HTTP request/response parsing (pest PEG grammar)
  ├── server      — Backend HTTP server (axum, serves /api/balance/{username})
  ├── verifier    — QUIC-based single-stream notarization + ZK verification service
  ├── shared      — TLS/QUIC config, test utilities, smol executor
  └── circuit     — Noir ZK circuit (BLAKE3 commitment verification)
```

### Data Flow

1. **Notarization** — Prover opens one QUIC stream to Notary and runs the TLSN verifier/prover protocol over `Session<Io>` while making an HTTPS request to Backend.
2. **Selective Disclosure** — Prover reveals chosen fields from the HTTP response, keeping others committed (BLAKE3 hash + blinder).
3. **ZK Proof** — Prover generates a HONK proof (Noir circuit) proving the committed balance value matches its hash without revealing the value.
4. **Verification** — Notary validates proof and commitments, then returns verification result over the same QUIC stream.

### Noir Circuit

The circuit (`circuit/src/main.nr`) verifies:

```
BLAKE3(balance_value || blinder) == committed_hash
```

- **Public input:** committed hash (32 bytes)
- **Private inputs:** balance value (12-byte padded string), blinder (16 bytes)
- Compiled bytecode is embedded in the `zktlsn` crate at `target/circuit.json`

### Transport

| Path            | Protocol                                    |
| --------------- | ------------------------------------------- |
| Server ↔ Prover | HTTP/1.1 over TLS (rustls)                  |
| Prover ↔ Notary | QUIC (quinn, `runtime-smol`)                |
| Proof exchange  | Length-prefixed JSON on same QUIC bi-stream |

### Async Runtime

`smol` is the primary async executor. `tokio` is used only for IO adapters. Quinn is configured with `runtime-smol` (not tokio).
