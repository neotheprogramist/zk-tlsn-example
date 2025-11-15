use futures::{AsyncRead, AsyncWrite};
use tlsn::{
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript},
    verifier::{Verifier, VerifierConfig, VerifyConfig},
};

use crate::{error::ZkTlsNotaryError, transcript::extract_received_commitments};

#[derive(Debug)]
pub struct VerifierOutput {
    pub transcript: PartialTranscript,
    pub server_name: String,
}

pub async fn verify<T>(
    socket: T,
    verifier_config: VerifierConfig,
) -> Result<VerifierOutput, ZkTlsNotaryError>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    tracing::info!(component = "verifier", phase = "verify", status = "started");

    let verifier = Verifier::new(verifier_config);

    let verifier_output = verifier
        .verify(socket, &VerifyConfig::default())
        .await
        .map_err(|e| ZkTlsNotaryError::VerifyFailed(e.to_string()))?;

    let server_name = verifier_output
        .server_name
        .ok_or(ZkTlsNotaryError::MissingField("server name"))?;

    let transcript = verifier_output
        .transcript
        .ok_or(ZkTlsNotaryError::MissingField("transcript"))?;

    let received_commitments =
        extract_received_commitments(&verifier_output.transcript_commitments);
    let received_commitment = received_commitments
        .first()
        .ok_or(ZkTlsNotaryError::MissingField("received hash commitment"))?;

    if received_commitment.direction != Direction::Received {
        return Err(ZkTlsNotaryError::InvalidTranscript(
            "Expected received direction for commitment".into(),
        ));
    }

    if received_commitment.hash.alg != HashAlgId::SHA256 {
        return Err(ZkTlsNotaryError::InvalidTranscript(
            "Expected SHA256 hash algorithm".into(),
        ));
    }

    tracing::info!(
        component = "verifier",
        phase = "verify",
        status = "completed",
        server_name = %server_name
    );
    Ok(VerifierOutput {
        transcript,
        server_name: server_name.to_string(),
    })
}
