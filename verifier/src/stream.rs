use axum::{extract::FromRequestParts, http::request::Parts};
use hyper::upgrade::{OnUpgrade, Upgraded};

use crate::errors::NotaryServerError;

pub struct StreamUpgrade {
    pub upgraded: Upgraded,
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

        let upgraded = on_upgrade.await.unwrap();

        Ok(Self { upgraded })
    }
}
