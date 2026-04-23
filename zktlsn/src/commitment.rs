use std::collections::{BTreeMap, HashMap};

use tlsnotary::{Direction, PlaintextHash, TranscriptCommitment};

use crate::{Result, ZkTlsnError};

const MAX_KEY_TO_COMMITMENT_GAP: usize = 3;

#[derive(Debug, Clone)]
pub struct BoundCommitment {
    pub key_range: std::ops::Range<usize>,
    pub hash: PlaintextHash,
}

pub fn bind_commitments_to_keys(
    parsed_response: &tlsnotary::parser::redacted::Response,
    transcript_commitments: &[TranscriptCommitment],
) -> Result<HashMap<String, BoundCommitment>> {
    let mut commitments_by_position: BTreeMap<usize, &PlaintextHash> = BTreeMap::new();
    for commitment in transcript_commitments {
        if let TranscriptCommitment::Hash(hash) = commitment
            && hash.direction == Direction::Received
        {
            let start = hash.idx.min().ok_or(ZkTlsnError::InvalidInput {
                context: "commitment binding",
                details: String::from("received transcript commitment is missing range start"),
            })?;
            commitments_by_position.insert(start, hash);
        }
    }

    let bindings = parsed_response
        .body
        .iter()
        .filter_map(|(keypath, body_field)| {
            if let tlsnotary::parser::redacted::Body::KeyValue { key, value } = body_field
                && value.is_none()
            {
                find_nearest_commitment(&commitments_by_position, key.end).map(|hash| {
                    (
                        keypath.clone(),
                        BoundCommitment {
                            key_range: key.clone(),
                            hash: hash.clone(),
                        },
                    )
                })
            } else {
                None
            }
        })
        .collect();

    Ok(bindings)
}

fn find_nearest_commitment<'a>(
    commitments_by_position: &'a BTreeMap<usize, &'a PlaintextHash>,
    key_end: usize,
) -> Option<&'a PlaintextHash> {
    commitments_by_position
        .range(key_end..)
        .take_while(|(start, _)| (*start).saturating_sub(key_end) <= MAX_KEY_TO_COMMITMENT_GAP)
        .map(|(_, hash)| *hash)
        .next()
}
