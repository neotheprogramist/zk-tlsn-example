//! Host-side verifier. Delegates the STARK check to `zkp::Verifier` and
//! recomputes the public-input digest the prover packed into the proof.

use crate::{
    air::{AIR_KIND_TAG_MAX, AirKind},
    error::{Error, Result},
    hash::public_input_digest,
    types::PublicInputs,
};

#[derive(Clone, Debug)]
pub struct VerifyOutput {
    pub air_kind_tag: u32,
    pub air_kind_name: String,
    pub digest_hi: u32,
    pub digest_lo: u32,
    pub verified: bool,
}

#[derive(Default)]
pub struct Verifier;

impl Verifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify a vault proof. Every leaf kind requires `expected_public_inputs`;
    /// only `ActionRoot` merge proofs may pass `None` (the merge envelope's
    /// in-circuit child verification is the binding).
    pub fn verify(
        &self,
        bytes: &[u8],
        expected_public_inputs: Option<&str>,
    ) -> Result<VerifyOutput> {
        let zkp_out = zkp::Verifier::new().verify(bytes)?;
        let air_kind_tag = if zkp_out.lo == zkp_out.hi {
            zkp_out.lo
        } else {
            AirKind::ActionRoot.tag()
        };
        let air_kind = AirKind::from_tag(air_kind_tag).ok_or(Error::AirKindOutOfRange {
            tag: air_kind_tag,
            max: AIR_KIND_TAG_MAX,
        })?;

        let (digest_hi, digest_lo) = match (air_kind, expected_public_inputs) {
            (AirKind::ActionRoot, _) => (0, 0),
            (_, Some(json)) => {
                let pi: PublicInputs = serde_json::from_str(json)?;
                public_input_digest(&serde_json::to_value(&pi)?)
            }
            (kind, None) => return Err(Error::PublicInputsRequired { kind }),
        };

        Ok(VerifyOutput {
            air_kind_tag,
            air_kind_name: air_kind.name().to_owned(),
            digest_hi,
            digest_lo,
            verified: true,
        })
    }
}
