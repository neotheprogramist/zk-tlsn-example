# stwo-circuit

ZK circuits for a privacy-preserving P2P fiat-crypto exchange built on Stwo (M31 STARKs) and TLSNotary.

## Prerequisites

### 1. Local Anvil node

```
anvil
```

### 2. Deploy contracts

```
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### 3. Trusted server

Create `trusted-stwo-server/.env`:

```toml
TRUSTED_SERVER_PRIVATE_KEY_HEX="a731c83a8c388ff4a8bd05c429ca250ca09c8a444c8110515db297379899ce8b"
TRUSTED_SERVER_ADDR="0.0.0.0:8080"
```

Start:

```
cargo run -p trusted-stwo-server
```

---

## Circuits

### `withdraw_circuit`

Single-deposit withdrawal. Proves knowledge of `(secret, nullifier)` matching a commitment in the deposit Merkle tree and outputs a spend nullifier.

**Public outputs:** `[root, nullifier, token, amount, recipient, 0]`

---

### `recursive_withdraw_circuit`

Aggregates N withdrawal proofs into one. Uses a null circuit as the base and a recursive step that verifies two sub-proofs and enforces `token_a == token_b` and `recipient_a == recipient_b`.

**Public outputs:** `[root_acc, nullifier_acc, token, total_amount, 0, recipient]`

The server reconstructs `root_acc` and `nullifier_acc` off-chain via poseidon fold chains and checks them against circuit outputs before signing.

---

### `offer_circuit`

Single-deposit offer creation. Proves ownership of a deposit and computes `offerCommitment` in-circuit:

```
offerCommitment = poseidon(
  poseidon(offerSecret, offerNullifier),
  amount, token, fiatAmount, currencyHash, revTagHash, offerRefundSnHash
)
```

**Public outputs:** `[root, nullifier, token, amount, offerCommitment, 0, offerRefundSnHash, fiatAmount, currencyHash, revTagHash]`

`fiatAmount`, `currencyHash`, `revTagHash` are ZK-proven and bound to `offerCommitment`. They are verified server-side at settlement against the TLSN transcript — they never go on-chain.

---

### `offer_spend_cancel_circuit`

Proves membership of an offer in the `offersTree` and outputs a spend nullifier for it. Used by the buyer's settlement flow.

**Public outputs:** `[offersRoot, offerNullifier, token, amount, offerCommitment, outputCommitment]`

---

### `recursive_create_offer_circuit`

Aggregates N withdrawal proofs into a batch offer (without a recipient constraint). Uses a null offer circuit as the base and a recursive accumulator that enforces `token_a == token_b`.

Terminal step adds offer-specific outputs proven in ZK.

**Public outputs (terminal):** `[root_acc, nullifier_acc, token, total_amount, offerCommitment, 0, offerRefundSnHash, fiatAmount, currencyHash, revTagHash]`

---

## System flow

```
Owner                     ZK Circuit               Trusted Server        Contract
  │                           │                          │                  │
  │── deposit ────────────────────────────────────────────────────────────► │ depositTree
  │                           │                          │                  │
  │── prove withdrawal ──────►│ withdraw_circuit         │                  │
  │   or offer_circuit        │ or offer_circuit         │                  │
  │                           │──── STARK proof ────────►│ verify STARK     │
  │                           │                          │── sign claim ───►│ createOffer /
  │                           │                          │                  │ withdraw
  │                           │                          │                  │
  │                                                      │                  │
Buyer                                                    │                  │
  │── TLSN: pay fiat ─────────────────────────────────────────────────────  │
  │── prove offer_spend ─────►│ offer_spend_circuit      │                  │
  │                           │──── STARK proof ────────►│ verify STARK     │
  │                           │                          │── sign settlement│
  │                           │         (check TLSN fiatAmount/revTag/currency vs offer)
  │                           │                          │                  │
  │── verifyTransaction ────────────────────────────────────────────────── ►│ release funds
```

**Settlement soundness:** The trusted server re-verifies its own ECDSA signature over the offer claim (stateless), extracts `fiatAmount`/`currencyHash`/`revTagHash` from the ZK-proven circuit outputs, and compares them against the TLSN transcript. Only if they match does it sign the settlement claim.

---

## E2E tests

| Test file | What it covers |
|---|---|
| `e2e_deposit_withdraw.rs` | Single-deposit withdraw proof → on-chain `withdraw` |
| `e2e_recursive_deposit_withdraw.rs` | Batch recursive withdraw → on-chain `recursiveWithdraw` |
| `e2e_create_cancel_offer.rs` | Single-deposit offer creation and cancellation |
| `e2e_offer_transaction_settlement.rs` | Full flow: offer → TLSN bank session → settlement → withdraw |
| `e2e_recursive_create_offer.rs` | Batch recursive offer creation → on-chain `recursiveCreateOffer` |

Run a specific test (trusted server and Anvil must be running):

```
cargo test -p stwo-circuit --test e2e_offer_transaction_settlement -- --nocapture
```

### Allowlist roots

Each circuit has a stable preprocessed Merkle root that the trusted server uses as an allowlist to accept only known circuit shapes. When a circuit is modified, run the corresponding root-stability test to obtain new constants and update `trusted-stwo-server/src/verify.rs`:

```
cargo test -p stwo-circuit test_recursive_offer_root_stabilises -- --nocapture
```
