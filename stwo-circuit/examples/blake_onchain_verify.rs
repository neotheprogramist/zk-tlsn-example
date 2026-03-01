#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

#[cfg(not(feature = "onchain-rpc"))]
fn main() {
    eprintln!("Enable feature `onchain-rpc` to run this example.");
}

#[cfg(feature = "onchain-rpc")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use alloy::primitives::Address;
    use serde_json;
    use stwo_circuit::{
        build_blake_onchain_input, compute_commitment_hash,
        prove_commitment, verify_onchain_call, verify_proof,
    };

    let rpc_url = std::env::var("RPC_URL")
        .map_err(|_| "Missing RPC_URL env var (e.g. http://127.0.0.1:8545)")?;
    let verifier_address: Address = std::env::var("VERIFIER_ADDRESS")
        .map_err(|_| "Missing VERIFIER_ADDRESS env var")?
        .parse()?;

    let x = b"123456789012";
    let blinder = [0u8; 16];
    let hash = compute_commitment_hash(x, &blinder);

    let proof_data = prove_commitment(x, blinder, hash, 4);
    verify_proof(proof_data.clone())?;

    let onchain_input = build_blake_onchain_input(&proof_data)?;

    // Save onchain_input to proof.json
    let json = serde_json::to_string_pretty(&onchain_input)?;
    std::fs::write("proof.json", json)?;
    println!("Saved onchain input to proof.json");

    // Print composition poly info for debugging
    println!("\n=== Composition Polynomial Debug Info ===");
    println!("coeffs0 length: {}", onchain_input.proof.composition_poly.coeffs0.len());
    println!("coeffs1 length: {}", onchain_input.proof.composition_poly.coeffs1.len());
    println!("coeffs2 length: {}", onchain_input.proof.composition_poly.coeffs2.len());
    println!("coeffs3 length: {}", onchain_input.proof.composition_poly.coeffs3.len());
    if !onchain_input.proof.composition_poly.coeffs0.is_empty() {
        println!("First 4 coeffs0: {:?}", &onchain_input.proof.composition_poly.coeffs0[..4.min(onchain_input.proof.composition_poly.coeffs0.len())]);
    }
    println!();

    let ok = verify_onchain_call(&rpc_url, verifier_address, &onchain_input)?;
    println!("on-chain verify result: {ok}");

    Ok(())
}
