use std::path::Path;

use async_compat::Compat;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use shared::{TestTlsConfig, get_or_create_test_tls_config};
use tlsnotary::{CertificateDer, ProtocolConfigValidator, RootCertStore, Verifier, VerifierConfig};

use crate::{NotarizationResult, NotaryGlobals, SessionPhase, stream::StreamUpgrade};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
    pub session_id: String,
}

pub async fn notarize(
    stream_upgrade: StreamUpgrade,
    State(notary_globals): State<NotaryGlobals>,
    Query(params): Query<NotarizationRequestQuery>,
) -> Response {
    {
        let store = notary_globals.store.lock().await;
        if !matches!(
            store.get(&params.session_id),
            Some(SessionPhase::Notarization)
        ) {
            return (StatusCode::BAD_REQUEST, "Invalid session").into_response();
        }
    }

    let session_id = params.session_id.clone();
    let on_upgrade = stream_upgrade.on_upgrade;

    smol::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(_) => return,
        };

        let TestTlsConfig { cert_bytes, .. } =
            get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
                .unwrap();

        let verifier_config = VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(cert_bytes)],
            })
            .protocol_config_validator(
                ProtocolConfigValidator::builder()
                    .max_sent_data(notary_globals.notarization_config.max_sent_data)
                    .max_recv_data(notary_globals.notarization_config.max_recv_data)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let verifier = Verifier::builder()
            .verifier_config(verifier_config)
            .build()
            .unwrap();

        let upgraded = TokioIo::new(upgraded);

        let verifier_output = match verifier.verify(Compat::new(upgraded)).await {
            Ok(output) => output,
            Err(_) => return,
        };

        let request = String::from_utf8(verifier_output.transcript.sent_unsafe().to_vec())
            .expect("Sent data should be valid UTF-8");
        let response_bytes = verifier_output.transcript.received_unsafe().to_vec();
        let response =
            String::from_utf8(response_bytes.clone()).expect("Received data should be valid UTF-8");

        let result = NotarizationResult {
            server_name: verifier_output.server_name.to_string(),
            request,
            response,
            response_bytes,
            transcript_commitments: verifier_output.transcript_commitments,
        };

        notary_globals
            .store
            .lock()
            .await
            .insert(session_id, SessionPhase::Verification(result));
    })
    .detach();

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "tcp")
        .body(axum::body::Body::empty())
        .unwrap()
}
