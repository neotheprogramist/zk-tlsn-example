use std::{net::SocketAddr, path::Path};

use axum::body::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{StatusCode, Uri};
use hyper_util::rt::TokioIo;
use quinn::Endpoint;
use shared::{SmolExecutor, TestQuicConfig, get_or_create_test_quic_config};
use tokio::io::{AsyncRead, AsyncWrite, join};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::NONE)
        .with_test_writer()
        .try_init()
        .unwrap();

    smol::block_on(async {
        let TestQuicConfig { client_config, .. } =
            get_or_create_test_quic_config(Path::new("cert.pem"), Path::new("key.pem")).await;
        let addr: SocketAddr = "[::]:0".parse().unwrap();

        let mut endpoint = Endpoint::client(addr).unwrap();
        endpoint.set_default_client_config(client_config);
        tracing::info!("Reliable streams server listening on {}", addr);

        let server_addr: SocketAddr = "[::1]:5000".parse().unwrap();
        let conn = endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = join(recv, send);

        let uri = Uri::from_static("/session");
        let (status_code, response) = send_request(stream, uri, Bytes::new()).await;
        let response = String::from_utf8(response).unwrap();

        dbg!(status_code);
        dbg!(response);
    });
}

pub async fn send_request<IO>(stream: IO, uri: Uri, body: Bytes) -> (StatusCode, Vec<u8>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(SmolExecutor::default(), stream)
        .await
        .unwrap();

    let request_task = async move {
        let req = hyper::Request::builder()
            .method("POST")
            .uri(uri)
            .header("Connection", "close")
            .header("content-type", "application/json")
            .body(Full::new(body))
            .expect("valid request");

        let res = sender.send_request(req).await.unwrap();

        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();

        (status, body)
    };

    let (conn_result, response) = futures::join!(conn, request_task);
    conn_result.unwrap();
    response
}
