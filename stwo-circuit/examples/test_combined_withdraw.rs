use macro_rules_attribute::apply;
use smol_macros::main;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    WithdrawInputs, compute_commitment_hash, prove_withdraw, verify_withdraw,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[apply(main!)]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .init();

    tracing::info!("Starting combined withdraw circuit test");

    let balance_fragment = b"100         ";
    let blinder = [42u8; 16];
    let commitment_hash = compute_commitment_hash(balance_fragment, &blinder);

    tracing::info!(
        commitment_hash = ?commitment_hash,
        "Step 1: TLSN commitment generated"
    );

    let secret = BaseField::from_u32_unchecked(12345);
    let nullifier = BaseField::from_u32_unchecked(67890);
    let amount = BaseField::from_u32_unchecked(100);
    let token_address = BaseField::from_u32_unchecked(0xABCD);

    tracing::info!(
        secret = secret.0,
        nullifier = nullifier.0,
        amount = amount.0,
        "Step 2: User deposit parameters"
    );

    let merkle_siblings = vec![
        BaseField::from_u32_unchecked(11111),
        BaseField::from_u32_unchecked(22222),
        BaseField::from_u32_unchecked(33333),
        BaseField::from_u32_unchecked(44444),
        BaseField::from_u32_unchecked(55555),
    ];
    let merkle_index = 1;

    use stwo_circuit::{
        poseidon_chain::{gen_poseidon_chain_trace, ChainInputs},
        merkle_membership::{gen_merkle_trace, MerkleInputs},
    };

    let deposit_inputs = ChainInputs::for_deposit(secret, nullifier, amount, token_address);
    let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
    let deposit_leaf = deposit_outputs.leaf;

    let merkle_inputs_temp = MerkleInputs::new(
        deposit_leaf,
        merkle_siblings.clone(),
        merkle_index,
        BaseField::from_u32_unchecked(0),
    );
    let (_, computed_root) = gen_merkle_trace(4, &merkle_inputs_temp);
    let merkle_root = computed_root;

    tracing::info!(
        merkle_root = merkle_root.0,
        merkle_depth = merkle_siblings.len(),
        "Step 3: Merkle tree parameters"
    );

    let inputs = WithdrawInputs {
        balance_fragment: balance_fragment.to_vec(),
        blinder,
        commitment_hash,
        secret,
        nullifier,
        amount,
        token_address,
        merkle_siblings,
        merkle_index,
        merkle_root,
    };

    tracing::info!("Step 4: WithdrawInputs created");

    let log_size = 8;
    let proof = match prove_withdraw(inputs, log_size) {
        Ok(p) => {
            tracing::info!("✅ Proof generated successfully!");
            tracing::info!(
                "Proof metadata: log_size={}, merkle_depth={}",
                p.log_size,
                p.merkle_depth
            );
            p
        }
        Err(e) => {
            tracing::error!("❌ Proof generation failed: {}", e);
            panic!("Proof generation failed");
        }
    };

    match verify_withdraw(proof.clone()) {
        Ok(()) => {
            tracing::info!("✅ Proof verified successfully!");
        }
        Err(e) => {
            tracing::error!("❌ Proof verification failed: {}", e);
            panic!("Proof verification failed");
        }
    }

    tracing::info!("========== Proof Summary ==========");
    tracing::info!("Public inputs:");
    tracing::info!("  - Merkle root: {}", proof.merkle_root.0);
    tracing::info!("  - Nullifier: {}", proof.nullifier.0);
    tracing::info!("  - Amount: {}", proof.amount.0);
    tracing::info!("  - Token: {}", proof.token_address.0);
    tracing::info!("Circuit parameters:");
    tracing::info!("  - Log size: {}", proof.log_size);
    tracing::info!("  - Merkle depth: {}", proof.merkle_depth);
    tracing::info!("=====================================");

    tracing::info!("🎉 Combined withdraw circuit test completed successfully!");
}
