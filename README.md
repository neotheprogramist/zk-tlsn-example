# zk-tlsn-example

Stablecoin settlement demo built on TLSNotary, Noir, and Barretenberg.

The current implementation targets latest `nargo`/`bb` and uses a CLI-only proving backend. A client produces an attestation proof for a fiat transfer. The verifier checks that proof against the TLSNotary transcript and, on success, signs a compact transfer ticket. A settlement circuit verifies those signed tickets, sums the mint amount, computes a batch root, and emits one final proof for onchain settlement.

## Architecture

Every fiat transfer yields a fixed-width 32 byte attestation:

```text
{tx_id:010}{to_user_id:010}{amount:012}
```

The flow is:

1. The prover generates an attestation proof with [circuits/attestation/src/main.nr](./circuits/attestation/src/main.nr).
2. The verifier checks the TLSNotary transcript binding and verifies the attestation proof with `bb verify`.
3. On success, the verifier signs a transfer ticket `(tx_id, to_user_id, amount)` with a fixed secp256k1 key.
4. [circuits/null/src/main.nr](./circuits/null/src/main.nr) produces a bootstrap proof with zero state. The recursive circuit in [circuits/recursive/src/main.nr](./circuits/recursive/src/main.nr) then folds each attestation proof into the chain using `verify_proof_with_type`, enforcing a shared `to_user_id`, accumulating `total_amount`, and computing `transfers_root` via Pedersen hashing.
5. [evm/src/SettlementMintGate.sol](./evm/src/SettlementMintGate.sol) verifies the final settlement proof, prevents replay by `transfers_root`, and mints [evm/src/StableToken.sol](./evm/src/StableToken.sol).

`single-settle` is only a wrapper around the canonical settlement pipeline with batch size `1`.

## Key Paths

- [zktlsn/examples/server.rs](./zktlsn/examples/server.rs): in-memory fiat ledger
- [zktlsn/examples/verifier.rs](./zktlsn/examples/verifier.rs): TLSNotary verifier plus ticket signer
- [zktlsn/examples/prover.rs](./zktlsn/examples/prover.rs): off-chain attestation proof flow
- [zktlsn/examples/settle.rs](./zktlsn/examples/settle.rs): canonical onchain settlement example
- [zktlsn/examples/single-settle.rs](./zktlsn/examples/single-settle.rs): one-transfer wrapper around `settle`
- [zktlsn/examples/fixture.rs](./zktlsn/examples/fixture.rs): deterministic settlement fixture generator
- [zktlsn/examples/support/settlement_demo.rs](./zktlsn/examples/support/settlement_demo.rs): runtime settlement orchestration
- [verifier/src/protocol.rs](./verifier/src/protocol.rs): proof verification and signed-ticket issuance
- [zktlsn/src/ticket.rs](./zktlsn/src/ticket.rs): ticket hash and secp256k1 signing helpers
- [evm/src/SettlementMintGate.sol](./evm/src/SettlementMintGate.sol): onchain mint gate
- [evm/src/generated/SettlementHonkVerifier.sol](./evm/src/generated/SettlementHonkVerifier.sol): generated Solidity verifier

[circuits/null/src/main.nr](./circuits/null/src/main.nr) serves as the bootstrap circuit for the recursive settlement chain, producing the initial zero-state proof that anchors the first recursive step.

## Toolchain

Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Noir:

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup
```

Barretenberg:

```bash
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
bbup
```

Foundry:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge soldeer install
```

The code validates the expected CLI versions at runtime:

- `nargo 1.0.0-beta.19`
- `bb 4.0.0-nightly.20260120`

## Environment

Copy [.env.example](./.env.example) to `.env` if you want defaults loaded by your shell.

Important variables:

- `ZKTLSN_SERVER_USERS=alice=100,bob=40,treasury=0`
- `ZKTLSN_SERVER_SPECIAL_USER=treasury`
- `ZKTLSN_FROM_USER=alice`
- `ZKTLSN_TO_USER=treasury`
- `ZKTLSN_TRANSFER_AMOUNT=25`
- `ZKTLSN_BATCH_FROM_USERS=alice,bob,alice`
- `ZKTLSN_BATCH_TO_USERS=treasury,treasury,treasury`
- `ZKTLSN_BATCH_AMOUNTS=25,10,15`
- `ZKTLSN_ANVIL_RPC_URL=http://127.0.0.1:8545`
- `ZKTLSN_ANVIL_PRIVATE_KEY=...`
- `ZKTLSN_MINT_RECIPIENT=...`
- `ZKTLSN_VERIFIER_TICKET_PRIVATE_KEY=...`

The verifier private key defines the signer baked into the settlement circuit constants. If you change it, rerun `fixture`.

## One-Time Setup

```bash
git clone <repo-url>
cd zk-tlsn-example

nargo compile --force
cargo build --release --all-targets --examples
```

`fixture` regenerates:

- [evm/src/generated/SettlementHonkVerifier.sol](./evm/src/generated/SettlementHonkVerifier.sol)
- [evm/testdata/settlement_fixture.json](./evm/testdata/settlement_fixture.json)
- [evm/testdata/settlement_proof.bin](./evm/testdata/settlement_proof.bin)
- [evm/testdata/settlement_public_inputs.bin](./evm/testdata/settlement_public_inputs.bin)
- [zktlsn/examples/support/deployment_artifacts.json](./zktlsn/examples/support/deployment_artifacts.json)
- `target/settlement_deployment.json` after it deploys contracts to the running Anvil instance

## Deterministic Checks

Offline checks:

```bash
nargo compile --force
nargo test
cargo check -p zktlsn --examples
cargo check -p verifier
forge lint
forge test --match-contract SettlementMintGateTest -vv
```

Anvil-backed artifact and deployment refresh:

```bash
anvil
cargo run --package zktlsn --release --example fixture
```

`fixture` now deploys contracts, so it requires a running Anvil-compatible RPC.

`SettlementMintGateTest` covers:

- valid settlement from the deterministic fixture
- replay rejection by `transfers_root`
- wrong destination rejection
- tampered proof rejection
- tampered public input rejection

## Live E2E

Run these in separate terminals:

```bash
cargo run --package zktlsn --release --example server
```

```bash
cargo run --package zktlsn --release --example verifier
```

```bash
anvil
```

After Anvil is running, deploy the settlement contracts once with:

```bash
cargo run --package zktlsn --release --example fixture
```

`fixture` is responsible for:

- generating the deterministic settlement artifacts
- generating the Solidity verifier and embedded deployment artifacts
- deploying the verifier, token, and settlement gate to the current Anvil chain
- writing the local deployment manifest to `target/settlement_deployment.json`

Then run canonical settlement:

```bash
cargo run --package zktlsn --release --example settle
```

Single-transfer wrapper:

```bash
cargo run --package zktlsn --release --example single-settle
```

The default batch is:

- `alice -> treasury : 25`
- `bob -> treasury : 10`
- `alice -> treasury : 15`

Expected result: one settlement proof that mints `50 * 1e18` tokens to the configured recipient.

Repeated `settle` runs against the same Anvil instance reuse the deployment from
`target/settlement_deployment.json` and mint into the same token contract. The recipient balance
therefore accumulates across runs until Anvil is reset. Rerunning `fixture` on the same chain will
deploy a new verifier/token/gate set and overwrite `target/settlement_deployment.json` to point at
that new deployment.

To inspect the recipient's ERC-20 balance with `cast`, use the `token=` address printed by the
`settle` example and the recipient address from the log output. If you do not pass
`--mint-recipient`, the recipient defaults to Anvil account `0`
(`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`).

```bash
cast call --rpc-url http://127.0.0.1:8545 "$TOKEN" "balanceOf(address)(uint256)" "$RECIPIENT"
```

On a fresh default Anvil run, that `balanceOf` value is:

- `0` before the first `settle`
- `50000000000000000000` after the first default `25 + 10 + 15` settlement
- `100000000000000000000` after running the same default `settle` flow a second time on the same deployment

Those exact numbers assume a fresh `server` process with the default ledger state and a fresh
Anvil instance that has already been initialized by `fixture`.

## Design Notes

- The server-side artifact boundary stays stable: attestation proof bytes, public inputs, and VK bytes are still produced before settlement.
- The recursive settlement circuit uses `verify_proof_with_type` with proof type `6` (UltraHonk ZK) to fold attestation proofs into a running batch state.
- The signed-ticket design preserves mobile proving while keeping the latest CLI toolchain and a sound server-side authorization step.
