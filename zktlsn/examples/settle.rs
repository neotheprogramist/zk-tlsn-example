#[path = "support/deployment_artifacts.rs"]
mod deployment_artifacts;

use std::{future::IntoFuture, net::SocketAddr, path::Path};

use alloy::{
    hex,
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{Address, FixedBytes, TxHash},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
};
use alloy_sol_types::{SolCall, SolConstructor};
use anyhow::{Context, Result, ensure};
use async_compat::{Compat, CompatExt};
use futures::AsyncWriteExt;
use http_body_util::{BodyExt, Empty};
use hyper::{StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use quinn::Endpoint;
use shared::{
    TestQuicConfig, TestTlsConfig, get_or_create_test_quic_config, get_or_create_test_tls_config,
    init_logging,
};
use smol::net::TcpStream;
use tlsnotary::{
    CertificateDer, HashAlgId, MpcTlsConfig, ProveConfig, ProverConfig, RootCertStore, ServerName,
    Session, TlsClientConfig, TlsCommitConfig, TranscriptCommitConfig, TranscriptCommitmentKind,
    prover::{RevealConfig, reveal_request, reveal_response},
};
use tracing::{error, info, instrument};
use verifier::{ProofMessage, VerificationOutcome};
use zktlsn::{KeccakProof, PaddingConfig, Proof, SettlementBundle, generate_settlement_bundle};

use crate::deployment_artifacts::{PreparedArtifacts, load_embedded_artifacts};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;
const ANVIL_RPC_URL: &str = "http://127.0.0.1:8545";
const ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

sol! {
    contract ZkTlsnVerifier {
        constructor(address verifier_);
        function submitProof(bytes calldata proof, bytes32[] calldata publicInputs) external;
        function verified(address account) external view returns (bool isVerified);
        function gatedAction() external view returns (bool allowed);
    }
}

#[derive(Clone, Copy)]
struct OnchainContracts {
    verifier: Address,
    wrapper: Address,
}

struct SettleFlowOutcome {
    verification_result: VerificationOutcome,
    bundle: SettlementBundle,
}

fn main() {
    zktlsn::setup_barretenberg_srs().expect("failed to setup Barretenberg SRS");
    init_logging("info");

    smol::block_on(async {
        if let Err(error) = run().await {
            error!(error = %error, "settle flow failed");
            std::process::exit(1);
        }
    });
}

#[instrument]
async fn run() -> Result<()> {
    let settle_flow = connect_and_settle().await?;
    ensure!(
        settle_flow.verification_result.success,
        "verification failed: {}",
        settle_flow.verification_result.message
    );

    let artifacts = load_deployment_artifacts(&settle_flow.bundle)
        .context("failed to load deployment artifacts")?;
    let (provider, deployer) = connect_anvil().context("failed to connect to Anvil")?;
    let contracts = deploy_contracts(&provider, &artifacts)
        .await
        .context("failed to deploy settlement contracts")?;
    let tx_hash = submit_proof_onchain(
        &provider,
        deployer,
        contracts.wrapper,
        &settle_flow.bundle.keccak_proof,
    )
    .await
    .context("failed to submit settlement proof")?;

    ensure!(
        read_verified(&provider, contracts.wrapper, deployer)
            .await
            .context("failed to read verified(account)")?,
        "wrapper contract did not record the deployer as verified"
    );
    ensure!(
        call_gated_action(&provider, contracts.wrapper, deployer)
            .await
            .context("failed to call gatedAction()")?,
        "gatedAction() returned false"
    );

    info!(
        server_name = %settle_flow.verification_result.server_name,
        verified_fields = ?settle_flow.verification_result.verified_fields,
        verifier = %contracts.verifier,
        wrapper = %contracts.wrapper,
        tx_hash = %tx_hash,
        "Full ZK-TLS settle flow completed successfully"
    );
    Ok(())
}

#[instrument(skip(stream), fields(phase = "notarize+prove+settle"))]
async fn run_single_stream_settle_flow<IO>(stream: IO) -> Result<SettleFlowOutcome>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(Compat::new(stream));
    let (driver, mut handle) = session.split();
    let driver_task = smol::spawn(driver);

    let TestTlsConfig { cert_bytes, .. } =
        get_or_create_test_tls_config(Path::new("test_cert.pem"), Path::new("test_key.pem"))
            .context("failed to load TLS test configuration")?;
    let (tls_client_config, tls_commit_config) =
        create_prover_config(cert_bytes).context("failed to create prover TLS configuration")?;

    let prover = handle
        .new_prover(
            ProverConfig::builder()
                .build()
                .map_err(tlsnotary::Error::from)
                .context("failed to build prover config")?,
        )?
        .commit(tls_commit_config)
        .await
        .context("failed to commit prover configuration")?;

    let prover_server_socket = TcpStream::connect("localhost:8443")
        .await
        .context("failed to connect to backend TLS server")?;
    let (tls_connection, prover_fut) = prover
        .connect(tls_client_config, prover_server_socket)
        .await
        .context("failed to establish MPC-TLS connection")?;
    let tls_connection = TokioIo::new(Compat::new(tls_connection));

    let (mut request_sender, connection) = hyper::client::conn::http1::handshake(tls_connection)
        .await
        .context("failed to create HTTP/1 client over MPC-TLS")?;

    let request_task = async move {
        let response = request_sender
            .send_request(create_test_request().context("failed to build test request")?)
            .await
            .context("failed to send backend request")?;
        ensure!(
            response.status() == StatusCode::OK,
            "unexpected backend status: {}",
            response.status()
        );

        response
            .collect()
            .await
            .context("failed to collect backend response body")
            .map(|collected| collected.to_bytes())
    };

    let (prover_result, connection_result, response_result) =
        futures::join!(prover_fut, connection, request_task);
    let mut prover = prover_result.context("TLSNotary prover future failed")?;
    connection_result.context("HTTP connection task failed")?;
    let _response_body = response_result?;

    let transcript = prover.transcript().clone();
    let received_transcript = transcript.received().to_vec();
    let mut prove_config_builder = ProveConfig::builder(&transcript);
    prove_config_builder.server_identity();

    let mut transcript_commit_builder = TranscriptCommitConfig::builder(&transcript);
    transcript_commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::BLAKE3,
    });

    reveal_request(
        transcript.sent(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &create_request_reveal_config(),
    )
    .context("failed to configure request transcript reveal")?;
    reveal_response(
        transcript.received(),
        &mut prove_config_builder,
        &mut transcript_commit_builder,
        &create_response_reveal_config(),
    )
    .context("failed to configure response transcript reveal")?;

    prove_config_builder.transcript_commit(
        transcript_commit_builder
            .build()
            .map_err(tlsnotary::Error::from)
            .context("failed to build transcript commit config")?,
    );
    let prove_config = prove_config_builder
        .build()
        .map_err(tlsnotary::Error::from)
        .context("failed to build proof config")?;

    let prover_output = prover
        .prove(&prove_config)
        .await
        .context("failed to generate TLSNotary proof")?;
    prover.close().await.context("failed to close prover")?;
    handle.close();
    let mut stream = driver_task.await.context("TLSNotary driver failed")?;

    let bundle = generate_settlement_bundle(
        &prover_output.transcript_commitments,
        &prover_output.transcript_secrets,
        &received_transcript,
        PaddingConfig::new(12),
    )
    .context("failed to build settlement bundle")?;
    let verification_result = submit_native_proof(&mut stream, bundle.native_proof.clone())
        .await
        .context("failed to submit native proof to verifier")?;

    Ok(SettleFlowOutcome {
        verification_result,
        bundle,
    })
}

#[instrument]
async fn connect_and_settle() -> Result<SettleFlowOutcome> {
    let TestQuicConfig { client_config, .. } =
        get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem"))
            .await
            .context("failed to load QUIC test configuration")?;
    let client_addr: SocketAddr = "[::]:0".parse().context("invalid client socket address")?;
    let verifier_addr: SocketAddr = "[::1]:5000".parse().context("invalid verifier address")?;

    let mut endpoint = Endpoint::client(client_addr).context("failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(verifier_addr, "localhost")
        .context("failed to start QUIC connection")?
        .await
        .context("failed to connect to verifier")?;
    let (send, recv) = connection
        .open_bi()
        .await
        .context("failed to open QUIC bidirectional stream")?;

    run_single_stream_settle_flow(tokio::io::join(recv, send)).await
}

async fn submit_native_proof<IO>(stream: &mut IO, proof: Proof) -> Result<VerificationOutcome>
where
    IO: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    ProofMessage::new(proof)
        .write_to(stream)
        .await
        .context("failed to write proof message to verifier")?;
    let verification_result = VerificationOutcome::read_from(stream)
        .await
        .context("failed to read verification result")?;
    stream
        .close()
        .await
        .context("failed to close verifier stream")?;
    Ok(verification_result)
}

fn connect_anvil() -> Result<(impl Provider, Address)> {
    let signer: PrivateKeySigner = ANVIL_PRIVATE_KEY
        .parse()
        .context("failed to parse Anvil private key")?;
    let deployer = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(
        ANVIL_RPC_URL
            .parse()
            .context("failed to parse Anvil RPC URL")?,
    );

    Ok((provider, deployer))
}

fn load_deployment_artifacts(bundle: &SettlementBundle) -> Result<PreparedArtifacts> {
    let artifacts = load_embedded_artifacts()?;
    ensure!(
        artifacts.verification_key == bundle.keccak_proof.verification_key,
        "embedded deployment artifacts do not match the generated keccak verification key; rerun `cargo run --package zktlsn --release --example fixture` and rebuild the `settle` binary"
    );
    Ok(artifacts)
}

async fn deploy_contracts<P>(
    provider: &P,
    artifacts: &PreparedArtifacts,
) -> Result<OnchainContracts>
where
    P: Provider,
{
    let library = deploy_bytecode(
        provider,
        artifacts.verifier_library_bytecode.clone(),
        "verifier library",
    )
    .await?;
    let verifier_bytecode = link_verifier_bytecode(
        &artifacts.verifier_bytecode_template,
        &artifacts.verifier_link_reference,
        library,
    )
    .context("failed to link verifier bytecode")?;
    let verifier = deploy_bytecode(provider, verifier_bytecode, "verifier").await?;

    let constructor = ZkTlsnVerifier::constructorCall {
        verifier_: verifier,
    };
    let wrapper = deploy_bytecode(
        provider,
        artifacts
            .wrapper_bytecode
            .iter()
            .copied()
            .chain(constructor.abi_encode().into_iter())
            .collect(),
        "wrapper",
    )
    .await?;

    Ok(OnchainContracts { verifier, wrapper })
}

async fn deploy_bytecode<P>(provider: &P, bytecode: Vec<u8>, label: &str) -> Result<Address>
where
    P: Provider,
{
    let pending = provider
        .send_transaction(TransactionRequest::default().with_deploy_code(bytecode))
        .compat()
        .await
        .with_context(|| format!("failed to submit {label} deployment"))?;
    let receipt = pending
        .get_receipt()
        .compat()
        .await
        .with_context(|| format!("failed to fetch {label} deployment receipt"))?;

    ensure!(receipt.status(), "{label} deployment failed");
    receipt.contract_address().context(format!(
        "{label} deployment receipt did not include a contract address"
    ))
}

async fn submit_proof_onchain<P>(
    provider: &P,
    deployer: Address,
    wrapper: Address,
    proof: &KeccakProof,
) -> Result<TxHash>
where
    P: Provider,
{
    let public_inputs = proof
        .public_inputs
        .iter()
        .copied()
        .map(FixedBytes::<32>::from)
        .collect::<Vec<_>>();
    let call = ZkTlsnVerifier::submitProofCall {
        proof: proof.solidity_proof.clone().into(),
        publicInputs: public_inputs,
    };
    let pending = provider
        .send_transaction(
            TransactionRequest::default()
                .with_from(deployer)
                .with_to(wrapper)
                .with_input(call.abi_encode()),
        )
        .compat()
        .await
        .context("failed to submit settlement transaction")?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .compat()
        .await
        .context("failed to fetch settlement receipt")?;
    ensure!(
        receipt.status(),
        "submitProof transaction failed: {tx_hash}"
    );
    Ok(tx_hash)
}

async fn read_verified<P>(provider: &P, wrapper: Address, deployer: Address) -> Result<bool>
where
    P: Provider,
{
    let call = ZkTlsnVerifier::verifiedCall { account: deployer };
    let response = provider
        .call(
            TransactionRequest::default()
                .with_from(deployer)
                .with_to(wrapper)
                .with_input(call.abi_encode()),
        )
        .decode_resp::<ZkTlsnVerifier::verifiedCall>()
        .into_future()
        .compat()
        .await
        .context("verified(address) call failed")?;
    response.context("failed to decode verified(address) response")
}

async fn call_gated_action<P>(provider: &P, wrapper: Address, deployer: Address) -> Result<bool>
where
    P: Provider,
{
    let call = ZkTlsnVerifier::gatedActionCall {};
    let response = provider
        .call(
            TransactionRequest::default()
                .with_from(deployer)
                .with_to(wrapper)
                .with_input(call.abi_encode()),
        )
        .decode_resp::<ZkTlsnVerifier::gatedActionCall>()
        .into_future()
        .compat()
        .await
        .context("gatedAction() call failed")?;
    response.context("failed to decode gatedAction() response")
}

fn link_verifier_bytecode(
    bytecode_template: &str,
    link_reference: &deployment_artifacts::LinkReference,
    library_address: Address,
) -> Result<Vec<u8>> {
    let mut bytecode = bytecode_template
        .strip_prefix("0x")
        .context("verifier bytecode must be 0x-prefixed")?
        .to_string();
    let link_range = link_range(bytecode.len(), link_reference)?;
    bytecode.replace_range(link_range, &format!("{library_address:x}"));
    hex::decode(bytecode).context("failed to decode linked verifier bytecode")
}

fn link_range(
    bytecode_len: usize,
    reference: &deployment_artifacts::LinkReference,
) -> Result<std::ops::Range<usize>> {
    let start = reference
        .start
        .checked_mul(2)
        .context("verifier link start overflow")?;
    let length = reference
        .length
        .checked_mul(2)
        .context("verifier link length overflow")?;
    let end = start
        .checked_add(length)
        .context("verifier link end overflow")?;
    ensure!(
        end <= bytecode_len,
        "verifier link reference is out of bounds for bytecode of length {}",
        bytecode_len / 2
    );
    Ok(start..end)
}

fn create_prover_config(
    cert_bytes: Vec<u8>,
) -> tlsnotary::Result<(TlsClientConfig, TlsCommitConfig)> {
    let server_name = ServerName::Dns("localhost".to_string().try_into().map_err(|error| {
        tlsnotary::Error::InvalidInput(format!("invalid DNS server name 'localhost': {error}"))
    })?);

    let tls_client_config = TlsClientConfig::builder()
        .server_name(server_name)
        .root_store(RootCertStore {
            roots: vec![CertificateDer(cert_bytes)],
        })
        .build()?;

    let tls_commit_config = TlsCommitConfig::builder()
        .protocol(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .build()?;

    Ok((tls_client_config, tls_commit_config))
}

fn create_test_request() -> Result<hyper::Request<Empty<Bytes>>> {
    hyper::Request::builder()
        .method("GET")
        .uri("/api/balance/alice")
        .header("content-type", "application/json")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(Into::into)
}

fn create_request_reveal_config() -> RevealConfig {
    RevealConfig {
        reveal_headers: vec!["content-type".into()],
        commit_headers: vec!["connection".into()],
        reveal_body_fields: vec![],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![],
    }
}

fn create_response_reveal_config() -> RevealConfig {
    use tlsnotary::{BodyFieldConfig, KeyValueCommitConfig};

    RevealConfig {
        reveal_headers: vec![],
        commit_headers: vec![],
        reveal_body_fields: vec![BodyFieldConfig::Quoted(".username".into())],
        commit_body_fields: vec![],
        reveal_keys_commit_values: vec![KeyValueCommitConfig::with_padding(".balance".into(), 12)],
    }
}
