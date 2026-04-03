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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub signer_public_key_hex: String,
    pub signer_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
}
