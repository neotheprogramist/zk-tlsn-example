use blake3::Hasher;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{Deserialize, Serialize};

use crate::{Result, ZkTlsnError};

pub const VERIFIER_TICKET_PRIVATE_KEY_ENV: &str = "ZKTLSN_VERIFIER_TICKET_PRIVATE_KEY";

const TICKET_DOMAIN_SEPARATOR: &[u8; 16] = b"zktlsn-ticket-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransferTicket {
    pub tx_id: u64,
    pub to_user_id: u64,
    pub amount: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct TicketSigner {
    signing_key: SigningKey,
}

impl TicketSigner {
    pub fn from_env() -> Result<Self> {
        let value = std::env::var(VERIFIER_TICKET_PRIVATE_KEY_ENV)
            .ok()
            .ok_or(ZkTlsnError::MissingConfig(VERIFIER_TICKET_PRIVATE_KEY_ENV))?;
        Self::from_hex(&value)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let decoded = hex::decode(value.trim_start_matches("0x"))?;
        if decoded.len() != 32 {
            return Err(ZkTlsnError::TicketKeyLength {
                actual: decoded.len(),
            });
        }

        let signing_key = SigningKey::from_slice(&decoded)?;
        Ok(Self { signing_key })
    }

    pub fn public_key_coordinates(&self) -> Result<([u8; 32], [u8; 32])> {
        let encoded = self.signing_key.verifying_key().to_encoded_point(false);
        let x = encoded
            .x()
            .ok_or(ZkTlsnError::TicketPublicKeyCoordinate("x"))?;
        let y = encoded
            .y()
            .ok_or(ZkTlsnError::TicketPublicKeyCoordinate("y"))?;

        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(x);
        y_bytes.copy_from_slice(y);
        Ok((x_bytes, y_bytes))
    }

    pub fn sign_ticket(
        &self,
        tx_id: u64,
        to_user_id: u64,
        amount: u64,
    ) -> Result<SignedTransferTicket> {
        let message_hash = ticket_message_hash(tx_id, to_user_id, amount);
        let signature: Signature = self.signing_key.sign_prehash(&message_hash)?;

        Ok(SignedTransferTicket {
            tx_id,
            to_user_id,
            amount,
            signature: signature.to_bytes().to_vec(),
        })
    }

    pub fn sign_padding_ticket(&self) -> Result<SignedTransferTicket> {
        self.sign_ticket(0, 0, 0)
    }

    pub fn verify_ticket(&self, ticket: &SignedTransferTicket) -> Result<()> {
        ticket.verify_with(self.signing_key.verifying_key())
    }
}

impl SignedTransferTicket {
    pub fn signature_array(&self) -> Result<[u8; 64]> {
        if self.signature.len() != 64 {
            return Err(ZkTlsnError::TicketSignatureLength {
                actual: self.signature.len(),
            });
        }

        let mut output = [0u8; 64];
        output.copy_from_slice(&self.signature);
        Ok(output)
    }

    pub fn verify_with(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let signature = Signature::from_slice(&self.signature_array()?)?;
        let message_hash = ticket_message_hash(self.tx_id, self.to_user_id, self.amount);
        verifying_key.verify_prehash(&message_hash, &signature)?;
        Ok(())
    }
}

pub(crate) fn ticket_message_hash(tx_id: u64, to_user_id: u64, amount: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(TICKET_DOMAIN_SEPARATOR);
    hasher.update(&tx_id.to_be_bytes());
    hasher.update(&to_user_id.to_be_bytes());
    hasher.update(&amount.to_be_bytes());
    *hasher.finalize().as_bytes()
}
