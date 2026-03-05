use stwo::core::{
    channel::Channel, fields::qm31::SecureField, pcs::TreeVec, proof::StarkProof, vcs::MerkleHasher,
};

use crate::blake3::{BlakeStatement0, BlakeStatement1};

#[derive(Debug)]
pub enum VerifyError {
    LogupImbalance(SecureField),
    StarkVerification,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::LogupImbalance(sum) => {
                write!(
                    f,
                    "logup claimed sums do not balance (got {sum:?}, expected zero)"
                )
            }
            VerifyError::StarkVerification => write!(f, "STARK verification failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofData<H: MerkleHasher> {
    pub commitment_stmt0: CommitmentStatement0,
    pub blake_stmt1: BlakeStatement1,
    pub proof: StarkProof<H>,
}

impl<H: MerkleHasher> std::fmt::Debug for ProofData<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofData")
            .field("log_size", &self.commitment_stmt0.log_size)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CommitmentStatement0 {
    pub log_size: u32,
    pub committed_hash: [u8; 32],
}

impl CommitmentStatement0 {
    pub fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
        for chunk in self.committed_hash.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            channel.mix_u64(u64::from_le_bytes(bytes));
        }
    }

    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        BlakeStatement0 {
            log_size: self.log_size,
        }
        .log_sizes()
    }

    pub fn committed_hash_words(&self) -> [u32; 8] {
        std::array::from_fn(|i| {
            let start = i * 4;
            let mut word = [0u8; 4];
            word.copy_from_slice(&self.committed_hash[start..start + 4]);
            u32::from_le_bytes(word)
        })
    }
}
