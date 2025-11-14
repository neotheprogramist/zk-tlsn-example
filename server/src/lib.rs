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

        let server_task = handle_connection(app, test_tls_config.server_config, server_cnx);

        let client_task = send_request(
            Uri::from_static("/api/balance/alice"),
            test_tls_config.client_config,
            client_cnx,
        );

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        server_result.expect("Server task should complete");
        let response = client_result.expect("Client task should complete");

        assert_eq!(response.status, StatusCode::OK);

        let body_str =
            String::from_utf8(response.body).expect("Response body should be valid UTF-8");
        assert!(body_str.contains("alice"));
        assert!(body_str.contains("100"));
    }
}
