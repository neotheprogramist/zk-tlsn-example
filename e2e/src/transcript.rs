use tracing::info;

use crate::proof::NotarizedFlow;

pub fn log_notarized_flow(flow: &NotarizedFlow) {
    info!(
        commitment_count = flow.commitment_count,
        request_len = flow.request_text.len(),
        response_len = flow.response_text.len(),
        "Prover notarisation complete"
    );
    info!("Prover request text:\n{}", flow.request_text);
    info!("Prover response text:\n{}", flow.response_text);
}
