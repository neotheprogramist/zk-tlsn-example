mod attestation;
mod error;

pub use attestation::{
    AMOUNT_WIDTH, ATTESTATION_LEN, FiatTransferAttestation, TX_ID_WIDTH, USER_ID_WIDTH,
    encode_transfer_attestation, parse_transfer_attestation,
};
pub use error::AttestationError;
