# zk-tlsn-example

Zero-knowledge TLS notarization demo that combines [TLSNotary](https://tlsnotary.org/) transcript capture with a [Noir](https://noir-lang.org/) circuit. The project proves facts about encrypted HTTP responses without revealing the full response payload.

## What This Repo Does

The end-to-end flow has three moving parts:

1. A backend server returns balance data over TLS.
2. A prover notarizes that TLS session with a verifier/notary and selectively reveals only part of the HTTP response.
3. The prover generates a Noir/Barretenberg proof showing that the committed balance value matches the transcript commitment.

The Noir circuit in [`circuit/src/main.nr`](./circuit/src/main.nr) checks:

```text
BLAKE3(balance_value || blinder) == committed_hash
```

The Rust prover example now also writes transcript-derived circuit inputs to [`circuit/Prover.toml`](./circuit/Prover.toml), so the same data can be reused later with `nargo execute`.

## Prerequisites

Install the following tools before running anything:

### Rust

The workspace uses Rust `1.93.1` via [`rust-toolchain.toml`](./rust-toolchain.toml).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Noir

This repo depends on Noir `v1.0.0-beta.8`.

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --version 1.0.0-beta.8
```

### Barretenberg

Barretenberg is required for standalone circuit proving, Solidity verifier generation, and the Rust ZK proving path.

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```

### Important Notes

- `zktlsn::setup_barretenberg_srs()` downloads CRS data from `https://crs.aztec.network` on first use, so the first prover/test run needs internet access.
- The `noir-rs` crate in this repo is pinned to `nargo v1.0.0-beta.8`. Compiling the circuit with a different `nargo` version can break proving because the Barretenberg backend rejects incompatible bytecode formats.

## Quick Start

```bash
git clone <repo-url> && cd zk-tlsn-example

# Compile the Noir circuit first. This generates target/circuit.json,
# which is embedded by the Rust prover/verifier crates.
nargo compile

cargo build --release
cargo test --release
```

## Common Commands

### Rust

```bash
cargo test --package parser --release
cargo test --package tlsnotary --release
cargo test --package zktlsn --release
cargo clippy
cargo fmt -- --check
```

### Noir

Run these from the repo root unless noted otherwise:

```bash
nargo test
```

For witness generation and Barretenberg proving, use the dedicated `circuit` package as shown below.

## Run The Full Demo

The full notarization flow uses three terminals. Start them in order and wait for each process to print its listening message before moving to the next one.

### Terminal 1: Backend Server

```bash
cargo run --package zktlsn --release --example server
```

Expected log:

```text
TLS server listening on localhost:8443
```

### Terminal 2: Verifier / Notary

```bash
cargo run --package zktlsn --release --example verifier
```

Expected log:

```text
Reliable streams server listening on [::1]:5000
```

### Terminal 3: Prover

```bash
cargo run --package zktlsn --release --example prover
```

On success, the prover:

1. Notarizes the TLS session.
2. Generates transcript commitments and secrets.
3. Writes and prints [`circuit/Prover.toml`](./circuit/Prover.toml).
4. Generates the Rust-side HONK proof.
5. Sends the proof to the verifier and prints the verification outcome.

Successful completion ends with a log like:

```text
Full ZK-TLS notarization and verification flow completed successfully
```

## Reuse The Generated `Prover.toml` With Noir

After running the prover example, you can reuse the generated [`circuit/Prover.toml`](./circuit/Prover.toml) for standalone Noir and Barretenberg commands.

Run the following from the `circuit` directory:

```bash
cd circuit
nargo execute witness
```

That writes the witness to `./target/witness.gz`.

### Generate And Verify A Native Barretenberg Proof

```bash
bb prove -b ./target/circuit.json -w ./target/witness.gz --write_vk -o ./target/native
bb verify -k ./target/native/vk -p ./target/native/proof
```

Artifacts:

- `./target/native/proof`
- `./target/native/vk`

## Generate A Solidity Verifier

This flow follows the official Barretenberg guide and adapts it to this repo’s `circuit` package:

- Official guide: https://barretenberg.aztec.network/docs/how_to_guides/how-to-solidity-verifier

### 1. Generate A Witness

Use the transcript-derived [`Prover.toml`](./circuit/Prover.toml) produced by the prover example, then generate a witness:

```bash
cd circuit
nargo execute witness
```

### 2. Generate A Keccak Verification Key

For Solidity verification, Barretenberg expects the key and proof flow to use `keccak` as the oracle hash:

```bash
bb write_vk -b ./target/circuit.json -o ./target --oracle_hash keccak
```

This writes the verification key to `./target/vk`.

### 3. Generate A Proof Compatible With The Solidity Verifier

```bash
bb prove -b ./target/circuit.json -w ./target/witness.gz -o ./target/solidity --oracle_hash keccak
```

This produces:

- `./target/solidity/proof`
- `./target/solidity/public_inputs`

Use those generated artifacts as-is when verifying on-chain. Do not manually reorder or repack the public inputs.

### 4. Generate The Solidity Contract

```bash
bb write_solidity_verifier -k ./target/vk -o ./target/Verifier.sol
```

The generated contract is written to `./target/Verifier.sol`.

### 5. Compile And Deploy

One simple workflow is:

1. Open [Remix](https://remix.ethereum.org/).
2. Paste in `./target/Verifier.sol`.
3. Compile with optimization enabled.
4. Deploy the `Verifier` contract to an EVM chain that supports the required precompiles.

### 6. Verify On-Chain

Call the generated `verify(bytes proof, bytes32[] publicInputs)` entrypoint using:

- the bytes from `./target/solidity/proof`
- the public inputs from `./target/solidity/public_inputs`

The Barretenberg guide also notes that chain support depends on the usual elliptic-curve and modular-exponentiation precompiles. If deployment fails on a specific chain, check the current support notes in the official guide.

## Architecture

```text
zktlsn (examples: prover, server, verifier)
  ├── tlsnotary   - TLS notarization protocol wrapper
  ├── parser      - HTTP request/response parsing
  ├── server      - Backend HTTP server
  ├── shared      - TLS/QUIC config and test helpers
  ├── verifier    - QUIC notary and ZK verification service
  └── circuit     - Noir circuit
```

### Data Flow

1. The prover opens a QUIC stream to the verifier/notary.
2. The prover makes an HTTPS request to the backend through MPC-TLS.
3. TLSNotary commitments are produced for selected transcript ranges.
4. The Noir circuit proves that the committed balance value matches its BLAKE3 commitment.
5. The verifier validates both the TLSNotary transcript proof and the ZK proof.

## Project Layout

- [`zktlsn/examples/prover.rs`](./zktlsn/examples/prover.rs): full end-to-end prover example
- [`zktlsn/examples/verifier.rs`](./zktlsn/examples/verifier.rs): verifier/notary example
- [`zktlsn/examples/server.rs`](./zktlsn/examples/server.rs): test backend server
- [`zktlsn/src/prover.rs`](./zktlsn/src/prover.rs): Rust-side proof generation and Noir input export
- [`circuit/src/main.nr`](./circuit/src/main.nr): Noir circuit
