use axum::{extract::FromRequestParts, http::request::Parts};
use hyper::upgrade::OnUpgrade;

use crate::errors::NotaryServerError;

/// Extractor that captures the OnUpgrade handle for later use.
/// The actual upgrade happens after returning a 101 response.
pub struct StreamUpgrade {
    pub on_upgrade: OnUpgrade,
}

impl<S> FromRequestParts<S> for StreamUpgrade
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let on_upgrade =
            parts
                .extensions
                .remove::<OnUpgrade>()
                .ok_or(NotaryServerError::BadProverRequest(
                    "Upgrade header is not set for stream client".to_string(),
                ))?;

        Ok(Self { on_upgrade })
    }
}
