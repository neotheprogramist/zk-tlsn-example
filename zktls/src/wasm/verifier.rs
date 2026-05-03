use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tlsn::{
    config::verifier::VerifierConfig,
    webpki::{CertificateDer, RootCertStore},
};
use wasm_bindgen::prelude::*;
use web_sys::WebTransportBidirectionalStream;

use super::{WasmRuntime, io::WebTransportIo};
use crate::{
    Error,
    policy::{standard_protocol_policy, standard_request_policy},
    verifier::{Verifier as CoreVerifier, VerifierConfigBundle, VerifierOutput},
};

#[derive(Debug, Deserialize)]
pub struct JsVerifierInputs {
    pub server_cert_der: Vec<u8>,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
}

#[derive(Debug, Serialize)]
pub struct JsVerifierOutput {
    pub server_name: String,
    pub commitment_count: usize,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Verifier(CoreVerifier);

#[wasm_bindgen]
impl Verifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn verify_stream(
        &self,
        inputs_json: &str,
        prover_stream: WebTransportBidirectionalStream,
    ) -> Result<JsValue, JsError> {
        let (verifier_config, max_sent, max_recv) = parse_inputs(inputs_json)?;
        let io = WebTransportIo::from_bidi(prover_stream)?;
        let (_io, output) = self
            .0
            .verify(
                VerifierConfigBundle {
                    runtime: Arc::new(WasmRuntime),
                    config: verifier_config,
                },
                io,
                standard_protocol_policy(max_sent, max_recv),
                standard_request_policy(),
            )
            .await?;
        let js_output = into_js_output(output);
        let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(js_output.serialize(&serializer)?)
    }
}

fn parse_inputs(inputs_json: &str) -> Result<(VerifierConfig, usize, usize), Error> {
    let inputs: JsVerifierInputs = serde_json::from_str(inputs_json)?;
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(inputs.server_cert_der)],
        })
        .build()?;
    Ok((verifier_config, inputs.max_sent_data, inputs.max_recv_data))
}

fn into_js_output(output: VerifierOutput) -> JsVerifierOutput {
    let sent = output.transcript.sent_unsafe().to_vec();
    let received = output.transcript.received_unsafe().to_vec();
    JsVerifierOutput {
        server_name: output.server_name,
        commitment_count: output.transcript_commitments.len(),
        sent,
        received,
    }
}
