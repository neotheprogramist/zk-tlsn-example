use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZkTlsnError {
    #[error("No received commitments found in transcript")]
    NoReceivedCommitments,

    #[error("No received secrets found in transcript")]
    NoReceivedSecrets,

    #[error("Invalid commitment direction, expected Received")]
    InvalidCommitmentDirection,

    #[error("Invalid hash algorithm, expected SHA256")]
    InvalidHashAlgorithm,

    #[error("Hash verification failed: computed hash does not match committed hash")]
    HashVerificationFailed,

    #[error("Circuit bytecode not found in program.json")]
    BytecodeNotFound,

    #[error(transparent)]
    JsonParseError(#[from] serde_json::Error),

    #[error("Verification key mismatch")]
    VerificationKeyMismatch,

    #[error("Committed hash does not match proof")]
    CommittedHashMismatch,

    #[error("Proof is invalid")]
    InvalidProof,

    #[error("STARK proof verification failed: {0}")]
    StwoError(#[from] stwo_circuit::VerifyError),

    #[error(
        "Balance too large: balance length {balance_length} + prefix {prefix_length} + suffix {suffix_length} exceeds total length {total_length}"
    )]
    BalanceTooLarge {
        balance_length: usize,
        total_length: usize,
        prefix_length: usize,
        suffix_length: usize,
    },

    #[error("Invalid balance format: {0}")]
    InvalidBalanceFormat(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Invalid commitment length: expected {expected} bytes, got {actual} bytes")]
    InvalidCommitmentLength { expected: usize, actual: usize },
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
