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

    #[error("Noir error: {0}")]
    NoirError(String),
}

pub type Result<T> = std::result::Result<T, ZkTlsnError>;
