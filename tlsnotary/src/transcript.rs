use tlsn::transcript::{
    Direction, TranscriptCommitment, TranscriptSecret,
    hash::{PlaintextHash, PlaintextHashSecret},
};

pub fn extract_received_commitments(
    transcript_commitments: &[TranscriptCommitment],
) -> Vec<&PlaintextHash> {
    transcript_commitments
        .iter()
        .filter_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .collect()
}

pub fn extract_received_secrets(
    transcript_secrets: &[TranscriptSecret],
) -> Vec<&PlaintextHashSecret> {
    transcript_secrets
        .iter()
        .filter_map(|secret| match secret {
            TranscriptSecret::Hash(hash) if hash.direction == Direction::Received => Some(hash),
            _ => None,
        })
        .collect()
}
