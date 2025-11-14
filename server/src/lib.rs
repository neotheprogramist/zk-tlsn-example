pub mod app;
pub mod client;
pub mod handler;

pub use client::{ClientError, Response, send_request};
pub use handler::{ConnectionError, handle_connection};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::{StatusCode, Uri};
    use shared::create_test_tls_config;
    use tokio::io::duplex;

    use crate::{app::get_app, handle_connection, send_request};

    #[tokio::test]
    async fn test_https_get_balance_existing_user() {
        let mut balances = HashMap::new();
        balances.insert("alice".to_string(), 100);
        let app = get_app(balances);

        let test_tls_config = create_test_tls_config().unwrap();
        let (client_cnx, server_cnx) = duplex(1024 * 1024);

        let server_task = tokio::spawn(async move {
            handle_connection(app, test_tls_config.server_config, server_cnx).await
        });

        let client_task = tokio::spawn(async move {
            send_request(
                Uri::from_static("/api/balance/alice"),
                test_tls_config.client_config,
                client_cnx,
            )
            .await
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        let response = client_result
            .expect("Client task should complete")
            .expect("Client should receive response successfully");

        assert_eq!(response.status, StatusCode::OK);

        let body_str =
            String::from_utf8(response.body).expect("Response body should be valid UTF-8");
        assert!(body_str.contains("alice"));
        assert!(body_str.contains("100"));

        let _ = server_result.expect("Server task should complete");
    }
}
