use crate::AttestationError;

pub const TX_ID_WIDTH: usize = 10;
pub const USER_ID_WIDTH: usize = 10;
pub const AMOUNT_WIDTH: usize = 12;
pub const ATTESTATION_LEN: usize = TX_ID_WIDTH + USER_ID_WIDTH + AMOUNT_WIDTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiatTransferAttestation {
    pub tx_id: u64,
    pub to_user_id: u64,
    pub amount: u64,
}

impl FiatTransferAttestation {
    pub const fn new(tx_id: u64, to_user_id: u64, amount: u64) -> Self {
        Self {
            tx_id,
            to_user_id,
            amount,
        }
    }
}

pub fn encode_transfer_attestation(
    attestation: FiatTransferAttestation,
) -> Result<String, AttestationError> {
    ensure_fits(attestation.tx_id, TX_ID_WIDTH, "tx_id")?;
    ensure_fits(attestation.to_user_id, USER_ID_WIDTH, "to_user_id")?;
    ensure_fits(attestation.amount, AMOUNT_WIDTH, "amount")?;

    Ok(format!(
        "{tx_id:0TX_ID_WIDTH$}{to_user_id:0USER_ID_WIDTH$}{amount:0AMOUNT_WIDTH$}",
        tx_id = attestation.tx_id,
        to_user_id = attestation.to_user_id,
        amount = attestation.amount,
    ))
}

pub fn parse_transfer_attestation(
    value: &str,
) -> Result<FiatTransferAttestation, AttestationError> {
    if value.len() != ATTESTATION_LEN {
        return Err(AttestationError::InvalidLength {
            expected: ATTESTATION_LEN,
            actual: value.len(),
        });
    }

    let tx_id = parse_segment(value.get(..TX_ID_WIDTH), "tx_id")?;
    let to_user_id = parse_segment(
        value.get(TX_ID_WIDTH..TX_ID_WIDTH + USER_ID_WIDTH),
        "to_user_id",
    )?;
    let amount = parse_segment(
        value.get(TX_ID_WIDTH + USER_ID_WIDTH..ATTESTATION_LEN),
        "amount",
    )?;

    Ok(FiatTransferAttestation::new(tx_id, to_user_id, amount))
}

fn parse_segment(segment: Option<&str>, label: &'static str) -> Result<u64, AttestationError> {
    let text = segment.ok_or(AttestationError::MissingSegment(label))?;
    match text.parse::<u64>() {
        Ok(value) => Ok(value),
        Err(source) => Err(AttestationError::InvalidSegment { label, source }),
    }
}

fn ensure_fits(value: u64, width: usize, label: &'static str) -> Result<(), AttestationError> {
    // PROOF: attestation widths are small compile-time constants in this module,
    // so u32::try_from(width) cannot fail — asserting the proof via expect here
    // keeps the error path uniform for the caller.
    let width = u32::try_from(width).expect("attestation width fits in u32");
    let limit = 10_u64
        .checked_pow(width)
        .expect("attestation width decimal limit fits in u64");

    if value >= limit {
        return Err(AttestationError::SegmentTooWide {
            label,
            value,
            width,
        });
    }
    Ok(())
}
