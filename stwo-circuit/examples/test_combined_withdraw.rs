use alloy::primitives::Address;
use macro_rules_attribute::apply;
use smol_macros::main;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    WithdrawInputs, build_onchain_verification_input, compute_commitment_hash, prove_withdraw,
    verify_onchain_call, verify_withdraw,
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
        merkle_membership::{MerkleInputs, gen_merkle_trace},
        poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
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

    let rpc_url = std::env::var("RPC_URL").ok();
    let verifier_address = std::env::var("VERIFIER_ADDRESS").ok();
    if let (Some(rpc_url), Some(verifier_address)) = (rpc_url, verifier_address) {
        tracing::info!("Step 6: On-chain verify call");
        let input = match build_onchain_verification_input(&proof) {
            Ok(input) => input,
            Err(err) => {
                tracing::error!("❌ Failed to build on-chain verify input: {}", err);
                panic!("Failed to build on-chain verify input");
            }
        };
        tracing::info!(
            "On-chain payload: roots={}, trees={}, tree0_cols={}, tree1_cols={}, tree2_cols={}, n_draws={}",
            input.tree_roots.len(),
            input.tree_column_log_sizes.len(),
            input.tree_column_log_sizes.first().map(|v| v.len()).unwrap_or(0),
            input.tree_column_log_sizes.get(1).map(|v| v.len()).unwrap_or(0),
            input.tree_column_log_sizes.get(2).map(|v| v.len()).unwrap_or(0),
            input.n_draws,
        );

        let verifier_address: Address = match verifier_address.parse() {
            Ok(address) => address,
            Err(err) => {
                tracing::error!("❌ Invalid VERIFIER_ADDRESS: {}", err);
                panic!("Invalid verifier address");
            }
        };

        match verify_onchain_call(&rpc_url, verifier_address, input) {
            Ok(true) => tracing::info!("✅ On-chain verification returned true"),
            Ok(false) => {
                tracing::error!("❌ On-chain verification returned false");
                panic!("On-chain verification returned false");
            }
            Err(err) => {
                tracing::error!("❌ On-chain verification call failed: {}", err);
                panic!("On-chain verification call failed");
            }
        }
    } else {
        tracing::info!(
            "On-chain verification skipped (set RPC_URL and VERIFIER_ADDRESS to enable it)"
        );
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
