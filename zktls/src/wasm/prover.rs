use std::sync::Arc;

use futures::AsyncReadExt;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_sys::WebTransportBidirectionalStream;

use super::{WasmRuntime, io::WebTransportIo};
use crate::{
    Error, Prover as CoreProver, transfer_request, transfer_request_reveal,
    transfer_response_reveal, transfer_tls_configs,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsProverInputs {
    pub server_name: String,
    pub server_cert_der: Vec<u8>,
    pub tx_id: u64,
}

#[derive(Debug, Serialize)]
pub struct JsProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub response_body: Vec<u8>,
    pub commitment_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum VerificationOutcome {
    #[serde(rename = "success")]
    Success {},
}

#[wasm_bindgen]
pub struct Prover(CoreProver);

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(constructor)]
    pub fn new(inputs_json: &str) -> Result<Prover, JsError> {
        Ok(Self(build_inner(inputs_json)?))
    }

    pub async fn prove_streams(
        self,
        verifier_stream: WebTransportBidirectionalStream,
        server_stream: WebTransportBidirectionalStream,
    ) -> Result<JsValue, JsError> {
        let verifier_io = WebTransportIo::from_bidi(verifier_stream)?;
        let server_io = WebTransportIo::from_bidi(server_stream)?;
        let (mut verifier_io, output) = self.0.prove(verifier_io, server_io).await?;
        read_verification_outcome(&mut verifier_io).await?;
        let js_output = JsProverOutput {
            sent: output.sent,
            received: output.received,
            response_body: output.response_body,
            commitment_count: output.transcript_commitments.len(),
        };
        let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(js_output.serialize(&serializer)?)
    }
}

fn build_inner(inputs_json: &str) -> Result<CoreProver, Error> {
    let inputs: JsProverInputs = serde_json::from_str(inputs_json)?;
    let (tls_client_config, tls_commit_config) =
        transfer_tls_configs(inputs.server_cert_der, &inputs.server_name)?;
    Ok(CoreProver::new(
        Arc::new(WasmRuntime),
        tls_client_config,
        tls_commit_config,
        transfer_request(inputs.tx_id)?,
        transfer_request_reveal(),
        transfer_response_reveal(),
    ))
}

async fn read_verification_outcome(io: &mut WebTransportIo) -> Result<(), Error> {
    const MAX_FRAME_BYTES: usize = 1 << 20;

    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    let VerificationOutcome::Success {} = serde_json::from_slice(&payload)?;
    Ok(())
}
