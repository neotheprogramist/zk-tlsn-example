use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::types::VerifyAndSignResponse;

#[derive(Clone)]
pub struct ServerStore {
    responses: Arc<RwLock<HashMap<String, VerifyAndSignResponse>>>,
}

impl ServerStore {
    pub async fn connect(_database_url: &str) -> Result<Self, String> {
        Ok(Self {
            responses: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn get_cached_response(
        &self,
        proof_id: &str,
    ) -> Result<Option<VerifyAndSignResponse>, String> {
        Ok(self.responses.read().await.get(proof_id).cloned())
    }

    pub async fn persist_signed_response(
        &self,
        proof_id: &str,
        _nullifier_key: &str,
        response: &VerifyAndSignResponse,
        _maybe_refund_commitment: Option<&str>,
        _maybe_nullifier_root_before: Option<&str>,
        _maybe_nullifier_root_after: Option<&str>,
    ) -> Result<(), String> {
        self.responses
            .write()
            .await
            .insert(proof_id.to_string(), response.clone());
        Ok(())
    }
}

pub fn limb_key(limbs: [u32; 4]) -> String {
    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        limbs[0], limbs[1], limbs[2], limbs[3]
    )
}
