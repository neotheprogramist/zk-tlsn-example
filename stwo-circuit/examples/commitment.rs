use stwo_circuit::{compute_commitment_hash, prove_commitment, verify_proof};
use tracing_subscriber::{EnvFilter, fmt};

// Only release mode
fn main() {
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    let x = b"123456789012";
    let blinder = [0u8; 16];
    let hash = compute_commitment_hash(x, &blinder);

    tracing::info!(hash = ?hash, "Computed commitment hash");
    let proof_data = prove_commitment(x, blinder, hash, 4);
    tracing::info!("Proof generated");

    match verify_proof(proof_data) {
        Ok(()) => tracing::info!("Verification: OK"),
        Err(err) => tracing::error!("Verification failed: {err}"),
    }
}
