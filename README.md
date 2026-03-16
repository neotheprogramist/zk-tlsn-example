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

This repo uses `zkmopro/noir-rs v1.0.0-beta.8`, and that crate pins Noir and `nargo` to
`noir-lang/noir` commit `b33131574388d836341cea9b6380f3b1a8493eb8`.
Install that exact commit so the `nargo` CLI stays compatible with the Rust-side `noir-rs`
dependency. Do not rely only on the `1.0.0-beta.8` version label.

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --commit b33131574388d836341cea9b6380f3b1a8493eb8
nargo --version
```

### Barretenberg

Barretenberg is required for standalone circuit proving, Solidity verifier generation, and the Rust ZK proving path.
For this repo, the standalone `bb` CLI must match the Barretenberg version embedded by the pinned
`noir-rs` crate: `1.0.0-nightly.20250723`. Install that exact version so the `bb` CLI stays
compatible with the Rust-side `noir-rs` dependency.

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup -v 1.0.0-nightly.20250723
bb --version
```

### Foundry

Foundry provides the local EVM toolchain used in this repo for `forge`, `cast`, and `anvil`.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge --version
cast --version
anvil --version
```

### Important Notes

- `zktlsn::setup_barretenberg_srs()` downloads CRS data from `https://crs.aztec.network` on first use, so the first prover/test run needs internet access.
- Keep the installed `nargo` and `bb` CLIs aligned with the exact revisions above so they remain compatible with the Rust-side `noir-rs` crate. A matching semver label alone is not enough for `nargo`, and an older `bb` will generate incompatible proof and verifier artifacts.
- `settle` does not require any CLI tools at runtime. `nargo`, `bb`, and `forge` are only needed when you intentionally regenerate the embedded settlement artifacts with `fixture`.

## Quick Start

```bash
git clone <repo-url> && cd zk-tlsn-example

# Compile the Noir circuit first. This generates target/circuit.json,
# which is embedded by the Rust prover/verifier crates.
nargo compile

cargo build --release --all-features --all-targets --examples
cargo test --release --all-targets --all
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

### Foundry

```bash
forge soldeer install
forge build
forge lint
forge test --match-contract ZkTlsnVerifierTest -vv
anvil
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

## Generate Settlement Artifacts

`fixture` is the one dev-time command that regenerates the EVM settlement artifacts:

- `evm/src/generated/HonkVerifier.sol`
- `zktlsn/examples/support/deployment_artifacts.json`
- `evm/testdata/proof.bin`
- `evm/testdata/public_inputs.bin`
- `evm/testdata/public_inputs.json`

```bash
cargo run --package zktlsn --release --example fixture
```

The fixture generator:

1. Writes a deterministic [`circuit/Prover.toml`](./circuit/Prover.toml).
2. Runs the documented `nargo` and `bb` commands.
3. Generates the Rust-side keccak proof and public inputs.
4. Validates the raw generated verifier and copies it unchanged to [`evm/src/generated/HonkVerifier.sol`](./evm/src/generated/HonkVerifier.sol).
5. Writes Foundry fixtures under [`evm/testdata`](./evm/testdata).
6. Runs `forge build` and writes the linked deployment payload to [`zktlsn/examples/support/deployment_artifacts.json`](./zktlsn/examples/support/deployment_artifacts.json).

If you change the circuit, the generated verifier, or the wrapper contract, rerun `fixture` and rebuild the `settle` binary so the embedded deployment artifacts stay aligned with the proof system.

## Test On-Chain Settlement

There are two supported ways to test settlement locally:

1. A deterministic Foundry test path that regenerates fixtures and does not require the TLS server or verifier to be running.
2. A live end-to-end path where `settle` proves locally in Rust and verifies onchain through Alloy without invoking any CLI tools at runtime.

### Deterministic Settlement Test With Foundry

This path regenerates the verifier and fixtures, then runs the Solidity tests against Anvil-compatible proof artifacts:

```bash
cargo run --package zktlsn --release --example fixture
forge test --match-contract ZkTlsnVerifierTest -vv
```

The Foundry suite checks that:

1. `submitProof` accepts the committed fixture proof.
2. `gatedAction()` reverts before settlement.
3. `gatedAction()` succeeds after settlement.
4. Tampered proof bytes are rejected.
5. Tampered public inputs are rejected.

## Reuse The Generated `Prover.toml` With Noir

After running the prover example, you can reuse the generated [`circuit/Prover.toml`](./circuit/Prover.toml) for standalone Noir and Barretenberg commands.

Run the following from the `circuit` directory:

```bash
nargo execute witness
```

That writes the witness to `../target/witness.gz`.

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

### 1. Generate A Keccak Verification Key

For Solidity verification, Barretenberg expects the key and proof flow to use `keccak` as the oracle hash:

```bash
cd /path/to/zk-tlsn-example
nargo compile --force
cd circuit
nargo execute witness
cd ..
bb write_vk -b ./target/circuit.json -o ./target --oracle_hash keccak
```

This writes the verification key to `./target/vk`.

### 2. Generate A Proof Compatible With The Solidity Verifier

```bash
bb prove -b ./target/circuit.json -w ./target/witness.gz -o ./target/solidity --oracle_hash keccak
```

This produces:

- `./target/solidity/proof`
- `./target/solidity/public_inputs`

Use those generated artifacts as-is when verifying on-chain. Do not manually reorder or repack the public inputs.

### 3. Generate The Solidity Contract

```bash
bb write_solidity_verifier -k ./target/vk -o ./target/Verifier.sol
```

The raw generated contract is written to `./target/Verifier.sol`.

### 4. Validate And Copy The Generated Verifier

The supported repo workflow keeps the raw `bb` verifier unchanged. `fixture` validates `./target/Verifier.sol` against the expected circuit shape, copies it to `evm/src/generated/HonkVerifier.sol`, and writes the deployment manifest that `settle` embeds at compile time.

Use the supported repo workflow:

```bash
cargo run --package zktlsn --release --example fixture
forge test --match-contract ZkTlsnVerifierTest -vv
```

### 5. Run Live Settlement On Anvil

The live settle demo uses:

1. [`zktlsn/examples/settle.rs`](./zktlsn/examples/settle.rs) for TLSN + proof generation + Alloy-based deployment and contract calls
2. [`evm/src/generated/HonkVerifier.sol`](./evm/src/generated/HonkVerifier.sol) for the generated verifier
3. [`zktlsn/examples/support/deployment_artifacts.json`](./zktlsn/examples/support/deployment_artifacts.json) for the embedded deploy bytecode and verification key
4. [`evm/src/ZkTlsnVerifier.sol`](./evm/src/ZkTlsnVerifier.sol) as a thin stateful wrapper

Only `server`, `verifier`, `anvil`, and the `settle` binary are required at runtime. `settle` does not shell out to `nargo`, `bb`, or `forge`, and it does not read `out/` or `target/` when deploying.

Start the services in order:

### Terminal 1: Backend Server

```bash
cargo run --package zktlsn --release --example server
```

### Terminal 2: Verifier / Notary

```bash
cargo run --package zktlsn --release --example verifier
```

### Terminal 3: Anvil

```bash
anvil
```

### Terminal 4: Settle

```bash
cargo run --package zktlsn --release --example settle
```

Successful completion ends with a log like:

```text
Full ZK-TLS settle flow completed successfully
```

The example:

1. Reuses the existing TLSN flow to obtain transcript commitments.
2. Generates the native proof and completes the off-chain verifier handshake.
3. Generates the keccak proof and verification key locally with `noir-rs`.
4. Deploys the linked `HonkVerifier` and `ZkTlsnVerifier` contracts to Anvil through Alloy.
5. Submits a real transaction to `submitProof`.
6. Confirms success by reading `verified(address)` and calling `gatedAction()`.

If the embedded deployment manifest and the locally generated keccak verification key ever diverge, `settle` fails fast and tells you to rerun `fixture` and rebuild.

The final log line includes the deployed verifier address, wrapper address, and settlement transaction hash. You can confirm the on-chain result manually with `cast` by reusing the wrapper address from that log:

```bash
export RPC_URL=http://127.0.0.1:8545
export DEPLOYER=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
export WRAPPER=<wrapper address from the settle log>

cast call $WRAPPER "verified(address)(bool)" $DEPLOYER --rpc-url $RPC_URL
cast call $WRAPPER "gatedAction()(bool)" --from $DEPLOYER --rpc-url $RPC_URL
```

Both calls should return `true`. If you also want the transaction receipt, use the `tx_hash` printed by `settle`:

```bash
cast receipt <tx_hash> --rpc-url $RPC_URL
```

The Barretenberg guide also notes that chain support depends on the usual elliptic-curve and modular-exponentiation precompiles. If deployment fails on a specific chain, check the current support notes in the official guide.

## Architecture

```text
zktlsn (examples: prover, settle, server, verifier)
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
- [`zktlsn/examples/settle.rs`](./zktlsn/examples/settle.rs): end-to-end settle example that proves locally and verifies the keccak proof on Anvil
- [`zktlsn/examples/fixture.rs`](./zktlsn/examples/fixture.rs): deterministic fixture and verifier generator for Foundry
- [`zktlsn/examples/verifier.rs`](./zktlsn/examples/verifier.rs): verifier/notary example
- [`zktlsn/examples/server.rs`](./zktlsn/examples/server.rs): test backend server
- [`zktlsn/src/prover.rs`](./zktlsn/src/prover.rs): Rust-side proof generation and Noir input export
- [`evm/src/ZkTlsnVerifier.sol`](./evm/src/ZkTlsnVerifier.sol): stateful wrapper around the generated verifier
- [`evm/src/generated/HonkVerifier.sol`](./evm/src/generated/HonkVerifier.sol): raw Barretenberg-generated Solidity verifier copied from `./target/Verifier.sol`
- [`evm/test/ZkTlsnVerifier.t.sol`](./evm/test/ZkTlsnVerifier.t.sol): Foundry tests for the on-chain settlement path
- [`circuit/src/main.nr`](./circuit/src/main.nr): Noir circuit
