use alloy::{
    primitives::{Address, U256},
    sol,
};
use clap::Parser;
use stwo::core::fields::m31::BaseField;
use stwo_circuit::{
    WithdrawInputs, build_onchain_verification_input,
    offchain_merkle::OffchainMerkleTree,
    poseidon_chain::{ChainInputs, gen_poseidon_chain_trace},
    prove_withdraw, send_withdraw_with_proof_tx, simulate_withdraw_with_proof_call,
    verify_withdraw,
};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

mod chain;
mod tlsn;

pub(crate) const MERKLE_SIBLING_DEPTH: usize = 31;
pub(crate) const M31_MODULUS: u32 = 2_147_483_647;
pub(crate) const ANVIL_TOPUP_BALANCE_HEX: &str = "0x3635C9ADC5DEA000000000";

#[derive(Debug, Parser)]
#[command(name = "test_e2e_server_withdraw")]
pub(crate) struct AppState {
    #[arg(long, env = "RPC_URL", default_value = "http://127.0.0.1:8545")]
    pub rpc_url: String,
    #[arg(long, env = "VERIFIER_ADDRESS")]
    pub verifier_address: Address,
    #[arg(long, env = "PRIVACY_POOL_ADDRESS")]
    pub privacy_pool_address: Address,
    #[arg(long, env = "WITHDRAW_TOKEN")]
    pub withdraw_token: Address,
    #[arg(long, env = "TLSN_VERIFIER_ADDR", default_value = "[::1]:5000")]
    pub tlsn_verifier_addr: String,
    #[arg(long, env = "TLS_SERVER_ADDR", default_value = "localhost:8443")]
    pub tls_server_addr: String,
    #[arg(
        long,
        env = "WITHDRAW_RECIPIENT",
        default_value = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    )]
    pub withdraw_recipient: Address,
    #[arg(
        long,
        env = "POOL_OWNER_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub owner_private_key: String,
    #[arg(long, env = "WITHDRAW_SECRET", default_value_t = 12345u32)]
    pub withdraw_secret: u32,
    #[arg(long, env = "WITHDRAW_NULLIFIER", default_value_t = 67890u32)]
    pub withdraw_nullifier: u32,
    #[arg(
        long,
        env = "WITHDRAW_GAS_LIMIT",
        default_value_t = 12_000_000_000_000u64
    )]
    pub withdraw_gas_limit: u64,
    #[arg(
        long,
        env = "WITHDRAW_MAX_FEE_PER_GAS",
        default_value_t = 2_000_000_000u128
    )]
    pub withdraw_max_fee_per_gas: u128,
    #[arg(
        long,
        env = "WITHDRAW_MAX_PRIORITY_FEE_PER_GAS",
        default_value_t = 1_000_000_000u128
    )]
    pub withdraw_max_priority_fee_per_gas: u128,
}

impl AppState {
    fn from_env() -> Self {
        Self::parse()
    }
}

sol! {
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
    }

    interface IPrivacyPool {
        function setVerifier(address verifier) external;
        function deposit(uint256 secretNullifierHash, uint256 amount, address token) external;
        function withdraw(
            uint256 root,
            uint256 nullifier,
            address token,
            uint256 amount,
            address recipient,
            bytes calldata verifyCalldata
        ) external;
        function getNextLeafIndex() external view returns (uint64);
        function getCurrentRoot() external view returns (uint256);
    }
}

fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_span_events(FmtSpan::NONE)
        .init();

    smol::block_on(async {
        let app = AppState::from_env();
        tracing::info!("Step 1: Running TLSN and extracting committed balance + blinder");
        let (balance_fragment, blinder, commitment_hash) = tlsn::run_tlsn_balance_query(&app).await;
        let parsed_amount = tlsn::parse_amount_from_fragment(&balance_fragment);
        tracing::info!(
            parsed_amount,
            "Amount extracted from TLSN committed fragment"
        );
        let amount = BaseField::from_u32_unchecked(parsed_amount);
        let token_address =
            BaseField::from_u32_unchecked(chain::address_to_m31(app.withdraw_token));

        tracing::info!("Step 2: Preparing pool state and performing real deposit");

        chain::ensure_owner_has_eth_for_gas(&app).await;
        chain::send_set_verifier_tx(&app)
            .await
            .expect("Failed to send setVerifier tx");

        let mut offchain_tree: OffchainMerkleTree = chain::build_offchain_merkle_tree(&app).await;
        let merkle_index = u32::try_from(offchain_tree.leaf_count())
            .unwrap_or_else(|_| panic!("Off-chain tree leaf_count does not fit u32"));
        if let Some(merkle_index_onchain) = chain::try_call_next_leaf_index(&app).await {
            assert_eq!(
                merkle_index,
                merkle_index_onchain as u32,
                "Off-chain leaf count mismatch with contract next index"
            );
        } else {
            tracing::warn!(
                merkle_index,
                "getNextLeafIndex unavailable; using off-chain leaf count"
            );
        }

        let effective_secret_u32 = app.withdraw_secret.wrapping_add(merkle_index);
        let effective_nullifier_u32 = app.withdraw_nullifier.wrapping_add(merkle_index);
        let secret = BaseField::from_u32_unchecked(effective_secret_u32);
        let nullifier = BaseField::from_u32_unchecked(effective_nullifier_u32);
        tracing::info!(
            merkle_index,
            effective_secret = effective_secret_u32,
            effective_nullifier = effective_nullifier_u32,
            "Using per-run secret/nullifier derived from merkle index"
        );

        let deposit_inputs = ChainInputs::for_deposit(secret, nullifier, amount, token_address);
        let (_, deposit_outputs) = gen_poseidon_chain_trace(4, deposit_inputs);
        let offchain_index = offchain_tree.add_leaf(deposit_outputs.leaf);
        assert_eq!(
            offchain_index as u32, merkle_index,
            "Off-chain inserted index mismatch"
        );
        let (merkle_siblings, _) = offchain_tree.path(offchain_index as usize);
        let expected_root = offchain_tree.root();

        let secret_nullifier_hash = deposit_outputs.secret_nullifier_hash;
        let deposit_amount_u64 = amount.0 as u64;
        tracing::info!(
            merkle_depth = MERKLE_SIBLING_DEPTH,
            "Built Merkle siblings from off-chain tree"
        );

        chain::send_approve_tx(&app, U256::from(deposit_amount_u64))
            .await
            .expect("Failed to send approve tx");
        chain::send_deposit_tx(
            &app,
            U256::from(secret_nullifier_hash.0),
            U256::from(deposit_amount_u64),
        )
        .await
        .expect("Failed to send deposit tx");

        let merkle_root = expected_root;
        if let Some(merkle_root_u256) = chain::try_call_current_root(&app).await {
            let merkle_root_u32 = u32::try_from(merkle_root_u256).unwrap_or_else(|_| {
                panic!("Current root doesn't fit M31/u32: {merkle_root_u256}")
            });
            let onchain_root = BaseField::from_u32_unchecked(merkle_root_u32);
            assert_eq!(
                onchain_root, expected_root,
                "On-chain root mismatch vs off-chain reconstructed root"
            );
        } else {
            tracing::warn!(
                expected_root = expected_root.0,
                "getCurrentRoot unavailable; using off-chain expected root"
            );
        }

        let inputs = WithdrawInputs {
            balance_fragment,
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

        tracing::info!("Step 3: Generating combined proof");
        let proof = prove_withdraw(inputs, 8).expect("Proof generation failed");
        verify_withdraw(proof.clone()).expect("Off-chain verification failed");

        tracing::info!("Step 4: Building on-chain verification payload");
        let verify_input =
            build_onchain_verification_input(&proof).expect("Failed to build onchain input");

        tracing::info!("Step 5: Calling real PrivacyPool.withdraw transaction");
        simulate_withdraw_with_proof_call(
            &app.rpc_url,
            app.privacy_pool_address,
            U256::from(proof.merkle_root.0),
            U256::from(proof.nullifier.0),
            app.withdraw_token,
            U256::from(proof.amount.0),
            app.withdraw_recipient,
            &verify_input,
        )
        .await
        .unwrap_or_else(|e| panic!("Preflight withdraw simulation failed: {e}"));

        send_withdraw_with_proof_tx(
            &app.rpc_url,
            &app.owner_private_key,
            app.privacy_pool_address,
            U256::from(proof.merkle_root.0),
            U256::from(proof.nullifier.0),
            app.withdraw_token,
            U256::from(proof.amount.0),
            app.withdraw_recipient,
            &verify_input,
        )
        .await
        .expect("Failed to send withdraw transaction");

        tracing::info!("✅ Full E2E passed: deposit -> server amount -> proof -> withdraw");
    });
}
