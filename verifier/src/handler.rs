use axum::Router;
use hyper::{Request, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, join};
use tower::Service;

pub async fn handle(incoming: quinn::Incoming, tower_service: Router) {
    let connection = incoming.await.unwrap();
    let remote_addr = connection.remote_address();
    tracing::info!("Connection established from {}", remote_addr);

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                tracing::info!("Connection closed by peer");
                break;
            }
            Err(e) => {
                tracing::error!("Error accepting stream: {}", e);
                break;
            }
        };

        // Combine SendStream and RecvStream into a single bidirectional stream
        // join() creates a tokio::io type, so we wrap with Compat for futures compatibility
        let stream = join(recv, send);
        smol::spawn(handle_stream(stream, tower_service.clone())).detach();
    }
}

async fn handle_stream<IO>(stream: IO, tower_service: Router)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = TokioIo::new(stream);

    let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
        tower_service.clone().call(request)
    });

    tracing::info!(
        component = "server",
        phase = "serve_connection",
        status = "started"
    );

    // Use HTTP/1.1 to support connection upgrades (required for notarization)
    hyper::server::conn::http1::Builder::new()
        .serve_connection(stream, hyper_service)
        .with_upgrades()
        .await
        .unwrap();

    tracing::info!(
        component = "server",
        phase = "serve_connection",
        status = "completed"
    );
}
