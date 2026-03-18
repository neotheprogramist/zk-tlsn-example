use blake3::Hasher;
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde::{Deserialize, Serialize};

use crate::{Result, ZkTlsnError};

pub const VERIFIER_TICKET_PRIVATE_KEY_ENV: &str = "ZKTLSN_VERIFIER_TICKET_PRIVATE_KEY";
pub const DEFAULT_VERIFIER_TICKET_PRIVATE_KEY: &str =
    "0x4c0883a69102937d6231471b5dbb6204fe512961708279cc06f3c4ec4b9ce2a1";

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
    pub fn from_env_or_default() -> Result<Self> {
        let value = std::env::var(VERIFIER_TICKET_PRIVATE_KEY_ENV)
            .unwrap_or_else(|_| DEFAULT_VERIFIER_TICKET_PRIVATE_KEY.to_string());
        Self::from_hex(&value)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let decoded = hex::decode(value.trim_start_matches("0x")).map_err(|error| {
            ZkTlsnError::InvalidInput(format!("invalid verifier ticket private key hex: {error}"))
        })?;
        if decoded.len() != 32 {
            return Err(ZkTlsnError::InvalidInput(format!(
                "verifier ticket private key must be 32 bytes, got {}",
                decoded.len()
            )));
        }

        let signing_key = SigningKey::from_slice(&decoded).map_err(|error| {
            ZkTlsnError::InvalidInput(format!("invalid verifier ticket private key: {error}"))
        })?;
        Ok(Self { signing_key })
    }

    pub fn public_key_coordinates(&self) -> Result<([u8; 32], [u8; 32])> {
        let encoded = self.signing_key.verifying_key().to_encoded_point(false);
        let x = encoded.x().ok_or_else(|| {
            ZkTlsnError::InvalidInput("verifier ticket public key is missing x coordinate".into())
        })?;
        let y = encoded.y().ok_or_else(|| {
            ZkTlsnError::InvalidInput("verifier ticket public key is missing y coordinate".into())
        })?;

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
        let signature: Signature =
            self.signing_key
                .sign_prehash(&message_hash)
                .map_err(|error| {
                    ZkTlsnError::InvalidInput(format!("failed to sign ticket: {error}"))
                })?;

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
}

impl SignedTransferTicket {
    pub fn signature_array(&self) -> Result<[u8; 64]> {
        if self.signature.len() != 64 {
            return Err(ZkTlsnError::InvalidInput(format!(
                "ticket signature must be 64 bytes, got {}",
                self.signature.len()
            )));
        }

        let mut output = [0u8; 64];
        output.copy_from_slice(&self.signature);
        Ok(output)
    }
}

pub fn ticket_message_hash(tx_id: u64, to_user_id: u64, amount: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(TICKET_DOMAIN_SEPARATOR);
    hasher.update(&tx_id.to_be_bytes());
    hasher.update(&to_user_id.to_be_bytes());
    hasher.update(&amount.to_be_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{Signature, signature::hazmat::PrehashVerifier};

    use crate::test_fixtures::load_settlement_fixture;

    use super::{
        DEFAULT_VERIFIER_TICKET_PRIVATE_KEY, SignedTransferTicket, TicketSigner,
        ticket_message_hash,
    };

    #[test]
    fn ticket_signer_matches_fixture_signature_for_fixed_payload() {
        let signer =
            TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY).expect("load signer");
        let ticket = signer.sign_ticket(1, 3, 25).expect("sign ticket");
        let fixture = load_settlement_fixture();

        assert_eq!(ticket.tx_id, 1);
        assert_eq!(ticket.to_user_id, 3);
        assert_eq!(ticket.amount, 25);
        assert_eq!(ticket, fixture.tickets[0]);
    }

    #[test]
    fn ticket_message_hash_is_stable() {
        assert_eq!(ticket_message_hash(1, 3, 25), ticket_message_hash(1, 3, 25));
    }

    #[test]
    fn sign_padding_ticket_uses_zero_payload() {
        let signer =
            TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY).expect("load signer");
        let ticket = signer.sign_padding_ticket().expect("sign padding ticket");

        assert_eq!(
            ticket,
            SignedTransferTicket {
                tx_id: 0,
                to_user_id: 0,
                amount: 0,
                signature: ticket.signature.clone(),
            }
        );
    }

    #[test]
    fn public_key_coordinates_match_default_signer() {
        let signer =
            TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY).expect("load signer");
        let (x, y) = signer.public_key_coordinates().expect("derive public key");

        assert_eq!(
            hex::encode(x),
            "2c2e805d45c1fa95c2f5ced4f774524b749c7d2ca134971accc14e805261ad8e"
        );
        assert_eq!(
            hex::encode(y),
            "1c2840d91f8fa6902215d3f627d8e6f1b50d917e133cd853db93dcef8c0bfa01"
        );
    }

    #[test]
    fn ticket_signature_verifies_against_signer_public_key() {
        let signer =
            TicketSigner::from_hex(DEFAULT_VERIFIER_TICKET_PRIVATE_KEY).expect("load signer");
        let ticket = signer.sign_ticket(3, 3, 15).expect("sign ticket");
        let signature = Signature::from_slice(&ticket.signature).expect("parse signature");

        signer
            .signing_key
            .verifying_key()
            .verify_prehash(
                &ticket_message_hash(ticket.tx_id, ticket.to_user_id, ticket.amount),
                &signature,
            )
            .expect("verify ticket signature");
    }

    #[test]
    fn malformed_private_key_hex_is_rejected() {
        let error = TicketSigner::from_hex("0x1234zz")
            .err()
            .expect("invalid hex should fail");
        assert!(
            error
                .to_string()
                .contains("invalid verifier ticket private key hex")
        );
    }

    #[test]
    fn short_private_key_is_rejected() {
        let error = TicketSigner::from_hex("0x1234")
            .err()
            .expect("short key should fail");
        assert!(error.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn signature_array_rejects_wrong_length() {
        let ticket = SignedTransferTicket {
            tx_id: 1,
            to_user_id: 3,
            amount: 25,
            signature: vec![0u8; 63],
        };

        let error = ticket
            .signature_array()
            .expect_err("wrong-length signature should fail");
        assert!(
            error
                .to_string()
                .contains("ticket signature must be 64 bytes")
        );
    }
}
