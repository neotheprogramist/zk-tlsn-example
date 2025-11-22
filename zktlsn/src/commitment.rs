use std::collections::{BTreeMap, HashMap};

use tlsnotary::{Direction, PlaintextHash, TranscriptCommitment};

use crate::Result;

#[derive(Debug, Clone)]
pub struct BoundCommitment {
    pub key_range: std::ops::Range<usize>,
    pub hash: PlaintextHash,
}

pub fn bind_commitments_to_keys(
    parsed_response: &parser::redacted::Response,
    transcript_commitments: &[TranscriptCommitment],
) -> Result<HashMap<String, BoundCommitment>> {
    let commitments_by_position: BTreeMap<usize, &PlaintextHash> = transcript_commitments
        .iter()
        .filter_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash) if hash.direction == Direction::Received => {
                Some((hash.idx.min().unwrap(), hash))
            }
            _ => None,
        })
        .collect();

    let bindings = parsed_response
        .body
        .iter()
        .filter_map(|(keypath, body_field)| {
            if let parser::redacted::Body::KeyValue { key, value } = body_field
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
        .take_while(|(start, _)| *start - key_end <= 2)
        .map(|(_, hash)| *hash)
        .next()
}
