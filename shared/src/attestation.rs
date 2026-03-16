use crate::SharedError;

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
) -> Result<String, SharedError> {
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

pub fn parse_transfer_attestation(value: &str) -> Result<FiatTransferAttestation, SharedError> {
    if value.len() != ATTESTATION_LEN {
        return Err(SharedError::InvalidAttestation(format!(
            "expected {ATTESTATION_LEN} bytes, got {}",
            value.len()
        )));
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

fn parse_segment(segment: Option<&str>, label: &str) -> Result<u64, SharedError> {
    segment
        .ok_or_else(|| SharedError::InvalidAttestation(format!("missing {label} segment")))?
        .parse::<u64>()
        .map_err(|error| SharedError::InvalidAttestation(format!("invalid {label}: {error}")))
}

fn ensure_fits(value: u64, width: usize, label: &str) -> Result<(), SharedError> {
    let width = u32::try_from(width)
        .map_err(|_| SharedError::InvalidAttestation(format!("invalid width for {label}")))?;
    let limit = 10_u64
        .checked_pow(width)
        .ok_or_else(|| SharedError::InvalidAttestation(format!("width overflow for {label}")))?;

    (value < limit).then_some(()).ok_or_else(|| {
        SharedError::InvalidAttestation(format!(
            "{label} value {value} exceeds {width}-digit limit"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ATTESTATION_LEN, FiatTransferAttestation, encode_transfer_attestation,
        parse_transfer_attestation,
    };

    #[test]
    fn test_transfer_attestation_roundtrip() {
        let encoded = encode_transfer_attestation(FiatTransferAttestation::new(1, 3, 25))
            .expect("encoded attestation");

        assert_eq!(encoded.len(), ATTESTATION_LEN);
        assert_eq!(
            parse_transfer_attestation(&encoded).expect("parsed attestation"),
            FiatTransferAttestation::new(1, 3, 25)
        );
    }
}
