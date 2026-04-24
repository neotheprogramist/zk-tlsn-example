use secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use tiny_keccak::{Hasher, Keccak};

pub struct Signer {
    secp: Secp256k1<secp256k1::All>,
    secret_key: SecretKey,
    public_key: PublicKey,
    address: [u8; 20],
}

pub struct EvmSignature {
    pub signature_65: [u8; 65],
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl Signer {
    pub fn from_env_or_random() -> Result<Self, String> {
        let secp = Secp256k1::new();

        let secret_key = if let Ok(hex_key) = std::env::var("TRUSTED_SERVER_PRIVATE_KEY_HEX") {
            parse_secret_key_hex(&hex_key)?
        } else {
            let seed = format!(
                "trusted-stwo-server:{}:{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            );
            derive_secret_key_from_seed(seed.as_bytes())?
        };

        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = address_from_pubkey(&public_key);

        Ok(Self {
            secp,
            secret_key,
            public_key,
            address,
        })
    }

    pub fn from_private_key_hex(hex_key: &str) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let secret_key = parse_secret_key_hex(hex_key)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = address_from_pubkey(&public_key);

        Ok(Self {
            secp,
            secret_key,
            public_key,
            address,
        })
    }

    pub fn public_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.public_key.serialize_uncompressed()))
    }

    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// Recovers the signer address (0x-prefixed hex) from a 65-byte EVM signature (r|s|v).
    pub fn recover_address(&self, digest32: [u8; 32], sig65: &[u8]) -> Result<String, String> {
        if sig65.len() != 65 {
            return Err(format!("signature must be 65 bytes, got {}", sig65.len()));
        }
        let v = sig65[64];
        let recovery_id_raw = if v >= 27 { v - 27 } else { v };
        let recid = RecoveryId::from_i32(i32::from(recovery_id_raw))
            .map_err(|e| format!("invalid recovery id: {e}"))?;
        let msg = Message::from_digest_slice(&digest32)
            .map_err(|e| format!("invalid digest: {e}"))?;
        let mut compact = [0u8; 64];
        compact.copy_from_slice(&sig65[0..64]);
        let recoverable = RecoverableSignature::from_compact(&compact, recid)
            .map_err(|e| format!("invalid signature: {e}"))?;
        let pubkey = self
            .secp
            .recover_ecdsa(&msg, &recoverable)
            .map_err(|e| format!("recovery failed: {e}"))?;
        let addr = address_from_pubkey(&pubkey);
        Ok(format!("0x{}", hex::encode(addr)))
    }

    pub fn sign_digest(&self, digest32: [u8; 32]) -> Result<EvmSignature, String> {
        let msg = Message::from_digest_slice(&digest32)
            .map_err(|e| format!("invalid digest length: {e}"))?;

        let sig: RecoverableSignature = self.secp.sign_ecdsa_recoverable(&msg, &self.secret_key);
        let (recid, compact) = sig.serialize_compact();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&compact[0..32]);
        s.copy_from_slice(&compact[32..64]);

        let v = recovery_id_to_evm_v(recid);

        let mut sig65 = [0u8; 65];
        sig65[0..64].copy_from_slice(&compact);
        sig65[64] = v;

        Ok(EvmSignature {
            signature_65: sig65,
            r,
            s,
            v,
        })
    }
}

fn recovery_id_to_evm_v(recid: RecoveryId) -> u8 {
    recid.to_i32() as u8 + 27
}

fn parse_secret_key_hex(hex_key: &str) -> Result<SecretKey, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid private key hex: {e}"))?;
    if bytes.len() != 32 {
        return Err("private key must be 32 bytes".to_string());
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&bytes);
    SecretKey::from_slice(&sk).map_err(|e| format!("invalid secp256k1 private key: {e}"))
}

fn derive_secret_key_from_seed(seed: &[u8]) -> Result<SecretKey, String> {
    let mut counter = 0u64;
    loop {
        let mut k = Keccak::v256();
        k.update(seed);
        k.update(&counter.to_be_bytes());
        let mut out = [0u8; 32];
        k.finalize(&mut out);

        if let Ok(sk) = SecretKey::from_slice(&out) {
            return Ok(sk);
        }
        counter = counter.saturating_add(1);
        if counter == u64::MAX {
            return Err("failed to derive valid secp256k1 key from seed".to_string());
        }
    }
}

fn address_from_pubkey(pubkey: &PublicKey) -> [u8; 20] {
    let uncompressed = pubkey.serialize_uncompressed();
    let mut k = Keccak::v256();
    k.update(&uncompressed[1..]);
    let mut out = [0u8; 32];
    k.finalize(&mut out);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[12..]);
    addr
}
