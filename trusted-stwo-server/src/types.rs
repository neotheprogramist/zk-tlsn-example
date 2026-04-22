use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignRequest {
    pub proof_id: String,

    /// base64(bincode(PcsConfig))
    pub pcs_config_b64: String,
    /// base64(bincode(ExtendedStarkProof<Blake2sM31MerkleHasher>))
    pub stark_proof_b64: String,

    pub channel_salt: u32,
    pub interaction_pow_nonce: u64,

    pub claim_log_sizes: Vec<u32>,
    pub claim_output_values: Vec<[u32; 4]>,

    pub interaction_claimed_sums: Vec<[u32; 4]>,

    pub stage1_trace_log_sizes: Vec<u32>,
    pub stage2_trace_log_sizes: Vec<u32>,

    /// From preprocessed circuit metadata.
    pub preprocessed_trace_log_sizes: Vec<u32>,
    pub preprocessed_column_ids: Vec<String>,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignResponse {
    pub proof_id: String,
    pub verified: bool,
    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    /// 65-byte ECDSA signature encoded as hex: r(32)|s(32)|v(1), where v is 27/28.
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,
    /// EVM address (0x-prefixed hex) derived from secp256k1 public key.
    pub signer_address: String,
    /// Uncompressed public key (0x04 + 64 bytes), 0x-prefixed hex.
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,
}

/// Request for verifying a recursive batch-withdrawal proof and signing the result.
///
/// In addition to the standard STARK proof fields (same as `VerifyAndSignRequest`),
/// the caller must supply the ordered lists of nullifiers and Merkle roots that were
/// used across all deposits in the batch.  The server reconstructs both poseidon hash
/// chains and checks them against the corresponding circuit public outputs before signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignRecursiveWithdrawRequest {
    // ── STARK proof fields (identical to VerifyAndSignRequest) ──────────────
    pub proof_id: String,

    /// base64(bincode(PcsConfig))
    pub pcs_config_b64: String,
    /// base64(bincode(ExtendedStarkProof<Blake2sM31MerkleHasher>))
    pub stark_proof_b64: String,

    pub channel_salt: u32,
    pub interaction_pow_nonce: u64,

    pub claim_log_sizes: Vec<u32>,
    pub claim_output_values: Vec<[u32; 4]>,

    pub interaction_claimed_sums: Vec<[u32; 4]>,

    pub stage1_trace_log_sizes: Vec<u32>,
    pub stage2_trace_log_sizes: Vec<u32>,

    pub preprocessed_trace_log_sizes: Vec<u32>,
    pub preprocessed_column_ids: Vec<String>,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,

    // ── Batch-specific fields ────────────────────────────────────────────────
    /// Nullifiers for each deposit in the batch, in aggregation order.
    /// The server computes poseidon(poseidon(...poseidon(0, n0)...), nk)
    /// and checks it equals claim_output_values[IDX_NULLIFIER_ACC].
    pub nullifiers: Vec<u32>,

    /// Merkle roots used by each deposit in the batch, in aggregation order.
    /// The server computes poseidon(poseidon(...poseidon(0, r0)...), rk)
    /// and checks it equals claim_output_values[IDX_ROOT_ACC].
    pub merkle_roots: Vec<u32>,
}

/// Response from the recursive withdraw endpoint.
///
/// The signature covers a claim that commits to the full nullifier list, the full
/// Merkle root list, and the key public outputs (token, amount, recipient).
/// The contract must:
///   1. Verify the signature against claim_hash.
///   2. Recompute poseidon(poseidon(...0, n0...), nk) and check each nullifier is unspent.
///   3. Check each Merkle root is in the contract's accepted historical root set.
///   4. Execute the withdrawal for `total_amount` of `token` to `recipient`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignRecursiveWithdrawResponse {
    pub proof_id: String,
    pub verified: bool,

    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,

    /// 65-byte ECDSA signature over message_hash: r(32)|s(32)|v(1), v is 27/28.
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,

    pub signer_address: String,
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,

    // ── Signed payload (pass these to the contract) ──────────────────────────
    /// Full ordered list of nullifiers — contract marks each as spent.
    pub nullifiers: Vec<u32>,
    /// Full ordered list of Merkle roots — contract checks each against its root set.
    pub merkle_roots: Vec<u32>,
    /// Token identifier from the circuit.
    pub token: u32,
    /// Total withdrawal amount aggregated across all deposits.
    pub total_amount: u32,
    /// Recipient address (field element).
    pub recipient: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignRecursiveCreateOfferRequest {
    pub proof_id: String,
    pub pcs_config_b64: String,
    pub stark_proof_b64: String,
    pub channel_salt: u32,
    pub interaction_pow_nonce: u64,
    pub claim_log_sizes: Vec<u32>,
    /// 7 public outputs from the terminal offer circuit:
    /// [0] root_acc, [1] nullifier_acc, [2] token, [3] total_amount,
    /// [4] offerCommitment (PROVEN in circuit), [5] 0, [6] offerRefundSnHash (PROVEN)
    pub claim_output_values: Vec<[u32; 4]>,
    pub interaction_claimed_sums: Vec<[u32; 4]>,
    pub stage1_trace_log_sizes: Vec<u32>,
    pub stage2_trace_log_sizes: Vec<u32>,
    pub preprocessed_trace_log_sizes: Vec<u32>,
    pub preprocessed_column_ids: Vec<String>,
    pub output_addresses: Vec<usize>,
    pub n_blake_gates: usize,
    pub nullifiers: Vec<u32>,
    pub merkle_roots: Vec<u32>,
    /// H(offer_secret, offer_secret) — offer identifier on-chain (not in circuit output).
    pub secret_hash: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAndSignRecursiveCreateOfferResponse {
    pub proof_id: String,
    pub verified: bool,
    pub proof_hash_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,
    pub signer_address: String,
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,
    pub nullifiers: Vec<u32>,
    pub merkle_roots: Vec<u32>,
    pub token: u32,
    pub total_amount: u32,
    /// offerCommitment extracted from circuit output[4] — proven in ZK, not server-computed.
    pub offer_commitment: u32,
    /// offerRefundSnHash extracted from circuit output[6] — proven in ZK.
    pub offer_refund_sn_hash: u32,
    pub secret_hash: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub signer_public_key_hex: String,
    pub signer_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTransactionSettlementRequest {
    pub transaction_id_hex: String,
    pub fiat_amount: u64,
    pub crypto_amount: u64,
    pub secret_nullifier_hash: u64,
    pub buyer_address: String,
    pub token_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTransactionSettlementResponse {
    pub transaction_id_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,
    pub signer_address: String,
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTlsnAndSignSettlementRequest {
    pub transcript_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTlsnAndSignSettlementResponse {
    pub verified: bool,
    pub comment_data: String,
    pub rev_tag: String,
    pub fiat_amount: u64,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,
    pub signer_address: String,
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,
}

/// Verifies a TLSN HTTP transcript (Revolut-mock) and signs a on-chain settlement claim.
/// The TLSN proof attests the fiat payment; the remaining fields bind the on-chain transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTlsnAndSignTransactionSettlementRequest {
    pub transcript_response: String,
    pub transaction_id_hex: String,
    pub crypto_amount: u64,
    pub secret_nullifier_hash: u64,
    pub buyer_address: String,
    pub token_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTlsnAndSignTransactionSettlementResponse {
    pub verified: bool,
    pub comment_data: String,
    pub rev_tag: String,
    pub fiat_amount: u64,
    pub transaction_id_hex: String,
    pub claim_hash_hex: String,
    pub message_hash_hex: String,
    pub signature_hex: String,
    pub signature_r_hex: String,
    pub signature_s_hex: String,
    pub signature_v: u8,
    pub signer_address: String,
    pub signer_public_key_hex: String,
    pub signed_at_unix: i64,
}
