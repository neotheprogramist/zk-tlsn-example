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

    #[error("Failed to generate ZK proof: {0}")]
    ProofGenerationFailed(String),

    #[error("Failed to parse JSON: {0}")]
    JsonParseError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
