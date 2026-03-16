# zk-tlsn-example

Stablecoin demo built on TLSNotary + Noir + Barretenberg. A user makes one or more TLS-backed fiat transfers into a special account, proves those transfer attestations in zero knowledge, and mints the same amount of ERC-20 tokens onchain through either a single-transfer path or a recursively aggregated batch path.

## Overview

The server keeps an in-memory fiat ledger. Every transfer produces a fixed-width 32 byte attestation:

```text
{tx_id:010}{to_user_id:010}{amount:012}
```

The Noir attestation circuit in [circuits/attestation/src/main.nr](./circuits/attestation/src/main.nr) proves:

```text
BLAKE3(attestation || blinder) == committed_hash
```

and also proves that the public `tx_id`, `to_user_id`, and `amount` match the committed attestation bytes.

The onchain mint flow only succeeds when the attested `to_user_id` matches the server's configured special user.

## Repo Paths

- [zktlsn/examples/server.rs](./zktlsn/examples/server.rs): configurable TLS ledger server
- [zktlsn/examples/verifier.rs](./zktlsn/examples/verifier.rs): TLSNotary verifier/notary service
- [zktlsn/examples/prover.rs](./zktlsn/examples/prover.rs): live off-chain proof flow
- [zktlsn/examples/settle.rs](./zktlsn/examples/settle.rs): live proof + onchain mint flow
- [zktlsn/examples/settle_batch.rs](./zktlsn/examples/settle_batch.rs): live recursive batch proof + onchain mint flow
- [zktlsn/examples/fixture.rs](./zktlsn/examples/fixture.rs): deterministic verifier and fixture generator
- [evm/src/StableToken.sol](./evm/src/StableToken.sol): mintable demo ERC-20
- [evm/src/StableMintGate.sol](./evm/src/StableMintGate.sol): replay-protected mint gate around the generated verifier
- [evm/src/BatchMintGate.sol](./evm/src/BatchMintGate.sol): recursive batch mint gate keyed by the aggregated transfers root
- [evm/src/generated/HonkVerifier.sol](./evm/src/generated/HonkVerifier.sol): generated Barretenberg Solidity verifier
- [evm/src/generated/RecursiveHonkVerifier.sol](./evm/src/generated/RecursiveHonkVerifier.sol): generated recursive Barretenberg Solidity verifier
- [circuits/attestation/src/main.nr](./circuits/attestation/src/main.nr): attestation circuit for single-settlement proofs
- [circuits/null/src/main.nr](./circuits/null/src/main.nr): recursive zero-state bootstrap circuit
- [circuits/recursive/src/main.nr](./circuits/recursive/src/main.nr): recursive aggregation circuit

## Runtime Model

There are two separate modes:

1. Dev-time artifact generation with `fixture`
2. Runtime proving/settlement with `prover`, `settle`, and `settle_batch`

`fixture` uses CLI tools:

- `nargo`
- `bb`
- `forge`

`prover`, `settle`, and `settle_batch` do not shell out at runtime. They use:

- `noir-rs` for proof generation
- Alloy for chain deployment and calls
- embedded deployment artifacts generated ahead of time by `fixture`

## Prerequisites

### Rust

The workspace uses Rust `1.93.1` via [rust-toolchain.toml](./rust-toolchain.toml).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Noir

This repo uses `zkmopro/noir-rs v1.0.0-beta.8`, pinned to Noir commit `b33131574388d836341cea9b6380f3b1a8493eb8`.

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup --commit b33131574388d836341cea9b6380f3b1a8493eb8
```

### Barretenberg

This repo expects `bb 1.0.0-nightly.20250723`.

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup -v 1.0.0-nightly.20250723
```

### Foundry

Foundry is only required for `fixture` and Solidity tests.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge soldeer install
```

### Notes

- `cargo run --package zktlsn --release --example fixture` downloads and refreshes the cached SRS files under `./srs_cache/` for the attestation, null, and recursive circuits.
- `prover`, `verifier`, and `settle` reuse that cached SRS instead of downloading from `https://crs.aztec.network` at runtime.
- `settle_batch` reuses the same cached SRS set and embedded deployment artifacts.
- Keep `nargo` and `bb` aligned with the exact revisions above.
- If you only run already-built `server`, `verifier`, `prover`, `settle`, or `settle_batch`, you do not need `nargo`, `bb`, or `forge` available at runtime.

## One-Time Setup

```bash
git clone <repo-url>
cd zk-tlsn-example

nargo compile --force
cargo build --release --all-targets --examples
cargo run --package zktlsn --release --example fixture
```

If you changed the circuit or Solidity contracts, regenerate deterministic artifacts and rebuild the runtime binaries:

```bash
cargo run --package zktlsn --release --example fixture
cargo build -p zktlsn --release --example settle
cargo build -p zktlsn --release --example settle_batch
```

`fixture` refreshes:

- `srs_cache/attestation.srs`
- `srs_cache/null.srs`
- `srs_cache/recursive.srs`
- [evm/src/generated/HonkVerifier.sol](./evm/src/generated/HonkVerifier.sol)
- [evm/src/generated/RecursiveHonkVerifier.sol](./evm/src/generated/RecursiveHonkVerifier.sol)
- [evm/testdata/fixture.json](./evm/testdata/fixture.json)
- [evm/testdata/proof.bin](./evm/testdata/proof.bin)
- [evm/testdata/public_inputs.bin](./evm/testdata/public_inputs.bin)
- [evm/testdata/batch_fixture.json](./evm/testdata/batch_fixture.json)
- [evm/testdata/batch_proof.bin](./evm/testdata/batch_proof.bin)
- [evm/testdata/batch_public_inputs.bin](./evm/testdata/batch_public_inputs.bin)
- [zktlsn/examples/support/deployment_artifacts.json](./zktlsn/examples/support/deployment_artifacts.json)

## Default Demo State

The server starts with:

- `alice=100`
- `bob=40`
- `treasury=0`
- special user = `treasury`

The transfer into `treasury` is what makes a transfer eligible for onchain minting.

## Deterministic Verification

These are the core checks for the repo:

```bash
nargo test
cargo test -p parser --release --lib
cargo test -p server --release --lib
cargo test -p tlsnotary --release --lib
cargo test -p zktlsn --release --lib
cargo check -p zktlsn --examples
cargo run --package zktlsn --release --example fixture
forge lint
forge test --match-contract BatchMintGateTest -vv
forge test --match-contract StableMintGateTest -vv
forge test --match-contract ZkTlsnVerifierTest -vv
```

`StableMintGateTest` is the primary onchain suite. It covers:

- valid mint from the deterministic fixture proof
- replay rejection by `tx_id`
- rejection when `to_user_id` does not match the special user
- tampered proof rejection
- tampered public input rejection

`BatchMintGateTest` covers the recursive batch path:

- valid mint from the deterministic batch fixture proof
- replay rejection by `transfers_root`
- rejection when the aggregated `to_user_id` does not match the special user
- rejection when the recursive verifier key hashes do not match the expected batch circuits
- tampered proof rejection
- tampered public input rejection

## Live E2E Setup

Open three terminals and keep these services running:

Terminal 1:

```bash
cargo run --package zktlsn --release --example server
```

Terminal 2:

```bash
cargo run --package zktlsn --release --example verifier
```

Terminal 3:

```bash
anvil
```

Once those are running, use the commands below from a fourth terminal.

## Live Off-Chain Proof Flow

This proves the TLS-backed transfer attestation and sends the native proof to the off-chain verifier only.

```bash
cargo run --package zktlsn --release --example prover
```

Default flow:

- from user: `alice`
- to user: `treasury`
- amount: `25`

Expected result:

- TLSNotary session succeeds
- Noir/native proof is generated locally
- verifier confirms the proof

Successful completion logs:

```text
Native transfer proof verified successfully
```

## Live Onchain Settlement Flow

This is the full deposit-to-mint path:

1. create a server transfer
2. fetch the attestation over TLS
3. generate TLSNotary proof + native proof + keccak proof locally
4. verify the native proof off-chain
5. deploy `HonkVerifier`, `StableToken`, and `StableMintGate` with Alloy
6. call `proveAndMint`
7. verify `claimedTxId(tx_id)` and the minted token balance

Run:

```bash
cargo run --package zktlsn --release --example settle
```

Default flow:

- from user: `alice`
- to user: `treasury`
- amount: `25`
- mint recipient: Anvil account `0`

Expected result:

```text
Stablecoin settlement completed successfully ... verifier=<address> token=<address> gate=<address> recipient=<address> tx_hash=<hash>
```

`settle` is runtime-standalone:

- it does not invoke `nargo`, `bb`, or `forge`
- it does not read `out/` or `target/` during deployment
- it uses the deployment manifest embedded at compile time
- it fails fast if the embedded verification key does not match the locally generated keccak verification key

## Live Recursive Batch Settlement Flow

This is the aggregated deposit-to-mint path:

1. create N server transfers
2. fetch each attestation over TLS and prove it through TLSNotary
3. generate N inner proofs plus a recursive chain locally
4. derive one final keccak proof for the aggregated batch
5. deploy `RecursiveHonkVerifier`, `StableToken`, and `BatchMintGate` with Alloy
6. call `batchMint`
7. verify `claimedRoot(transfers_root)` and the minted token balance

Run:

```bash
cargo run --package zktlsn --release --example settle_batch
```

Default flow:

- from users: `alice,bob,alice`
- to users: `treasury,treasury,treasury`
- amounts: `25,10,15`
- batch size: `3`
- mint recipient: Anvil account `0`

Expected result:

```text
Batch settlement completed successfully ... verifier=<address> token=<address> gate=<address> recipient=<address> tx_hash=<hash>
```

Custom batch example:

```bash
cargo run --package zktlsn --release --example settle_batch -- \
  --from-users alice,bob \
  --to-users treasury,treasury \
  --amounts 12,8
```

Current replay semantics for the batch demo are keyed by `transfers_root`. That is intentionally weaker than single-settlement replay protection by `tx_id`, and should be treated as demo-only behavior for now.

## Negative Scenarios

Transfer to a non-special user. This should fail before any onchain work:

```bash
cargo run --package zktlsn --release --example settle -- \
  --from-user bob \
  --to-user alice \
  --amount 10
```

Expected result:

```text
transfer tx <id> is not eligible for minting: destination user 'alice' ... does not match configured special user 'treasury'
```

Insufficient server balance. This should fail before proof generation:

```bash
cargo run --package zktlsn --release --example settle -- \
  --from-user bob \
  --to-user treasury \
  --amount 100
```

Expected result:

```text
failed to create transfer attestation: server returned 400 Bad Request: insufficient balance for 'bob': have <x>, need 100
```

## Manual Onchain Checks

After a successful `settle` run, use the printed `token`, `gate`, `recipient`, and `tx_id`:

```bash
export RPC_URL=http://127.0.0.1:8545
export TOKEN=<token address>
export GATE=<gate address>
export RECIPIENT=<recipient address>
export TX_ID=<tx id>

cast call $GATE "claimedTxId(uint256)(bool)" $TX_ID --rpc-url $RPC_URL
cast call $TOKEN "balanceOf(address)(uint256)" $RECIPIENT --rpc-url $RPC_URL
```

Expected results:

- `claimedTxId(tx_id) == true`
- `balanceOf(recipient) == amount * 1e18`

After a successful `settle_batch` run, use the printed `token`, `gate`, `recipient`, and the `transfers_root` from the logs or [evm/testdata/batch_fixture.json](./evm/testdata/batch_fixture.json):

```bash
export RPC_URL=http://127.0.0.1:8545
export TOKEN=<token address>
export GATE=<gate address>
export RECIPIENT=<recipient address>
export TRANSFERS_ROOT=<transfers root>

cast call $GATE "claimedRoot(bytes32)(bool)" $TRANSFERS_ROOT --rpc-url $RPC_URL
cast call $TOKEN "balanceOf(address)(uint256)" $RECIPIENT --rpc-url $RPC_URL
```

Expected results:

- `claimedRoot(transfers_root) == true`
- `balanceOf(recipient) == sum(amounts) * 1e18`

## Useful Runtime Flags

`server`:

- `--listen-addr`
- `--user <username=balance>`
- `--special-user`

`prover` and `settle`:

- `--server-addr`
- `--server-name`
- `--verifier-addr`
- `--from-user`
- `--to-user`
- `--amount`

`settle` only:

- `--anvil-rpc-url`
- `--anvil-private-key`
- `--mint-recipient`

`settle_batch` only:

- `--from-users alice,bob,...`
- `--to-users treasury,treasury,...`
- `--amounts 25,10,...`
- `--anvil-rpc-url`
- `--anvil-private-key`
- `--mint-recipient`

## Environment Variables

Server:

- `ZKTLSN_SERVER_LISTEN_ADDR`
- `ZKTLSN_SERVER_USERS`
- `ZKTLSN_SERVER_SPECIAL_USER`

Examples:

- `ZKTLSN_SERVER_ADDR`
- `ZKTLSN_SERVER_NAME`
- `ZKTLSN_VERIFIER_ADDR`
- `ZKTLSN_FROM_USER`
- `ZKTLSN_TO_USER`
- `ZKTLSN_TRANSFER_AMOUNT`
- `ZKTLSN_ANVIL_RPC_URL`
- `ZKTLSN_ANVIL_PRIVATE_KEY`
- `ZKTLSN_MINT_RECIPIENT`

## Architecture

```text
zktlsn/examples/settle
  -> POST /api/transfers
  -> GET /api/attestations/{tx_id} over TLS + TLSNotary
  -> derive Noir inputs from the committed attestation
  -> native proof to off-chain verifier
  -> keccak proof to onchain HonkVerifier
  -> StableMintGate verifies proof, prevents replay, mints StableToken
```

```text
zktlsn/examples/settle_batch
  -> POST /api/transfers for each batch item
  -> GET /api/attestations/{tx_id} over TLS + TLSNotary for each transfer
  -> derive Noir inputs for each committed attestation
  -> native proof to off-chain verifier for each transfer
  -> recursive aggregation chain over inner proofs
  -> final keccak proof to onchain RecursiveHonkVerifier
  -> BatchMintGate verifies proof, prevents replay by transfers root, mints StableToken
```
