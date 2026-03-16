pub mod app;
pub mod client;
pub mod handler;

pub use client::{CapturedTraffic, ClientError, send_request};
pub use handler::{ConnectionError, handle_connection};
pub use shared::SmolExecutor;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::{body::Body, http::Request as AxumRequest};
    use http_body_util::BodyExt;
    use hyper::Uri;
    use parser::{JsonFieldRangeExt, standard::Response};
    use shared::create_test_tls_config;
    use smol::net::unix::UnixStream;
    use tower::ServiceExt;

    use crate::{
        app::{AppConfig, InitialUser, TransferRequest, TransferResponse, get_app},
        handle_connection, send_request,
    };

    fn test_app() -> axum::Router {
        get_app(AppConfig {
            users: vec![
                InitialUser::new("alice", 100),
                InitialUser::new("bob", 40),
                InitialUser::new("treasury", 0),
            ],
            special_username: String::from("treasury"),
        })
        .expect("app should build")
    }

    async fn seed_transfer(app: &axum::Router, to_username: &str) -> TransferResponse {
        let request = TransferRequest {
            from_username: String::from("alice"),
            to_username: String::from(to_username),
            amount: 25,
        };
        let response = app
            .clone()
            .oneshot(
                AxumRequest::builder()
                    .method("POST")
                    .uri("/api/transfers")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("transfer request json"),
                    ))
                    .expect("transfer request"),
            )
            .await
            .expect("transfer response");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("transfer body")
            .to_bytes();
        serde_json::from_slice(&body).expect("transfer json")
    }

    #[test]
    fn test_https_get_attestation_existing_transfer() {
        shared::init_test_logging();

        smol::block_on(async {
            let app = test_app();
            let transfer = seed_transfer(&app, "treasury").await;

            let test_tls_config = create_test_tls_config().unwrap();
            let (client_cnx, server_cnx) = UnixStream::pair().unwrap();

            let server_task = handle_connection(app, test_tls_config.server_config, server_cnx);

            let client_task = send_request(
                Uri::from_str(&format!("/api/attestations/{}", transfer.tx_id))
                    .expect("attestation uri"),
                test_tls_config.client_config,
                client_cnx,
            );

            let (server_result, client_result) = futures::join!(server_task, client_task);

            server_result.expect("Server task should complete");
            let traffic = client_result.expect("Client task should complete");

            // Parse response to check status and body via the parser
            let raw_response_str = String::from_utf8(traffic.raw_response.clone())
                .expect("Response should be valid UTF-8");

            let parsed_response =
                Response::from_str(&raw_response_str).expect("Should parse response");

            assert_eq!(
                &raw_response_str[parsed_response.protocol_version.clone()],
                "HTTP/1.1"
            );
            assert_eq!(
                &raw_response_str[parsed_response.status_code.clone()],
                "200"
            );
            assert_eq!(&raw_response_str[parsed_response.status.clone()], "OK");

            let attestation_field = parsed_response
                .body
                .get(".attestation")
                .expect("Should find attestation field");
            let amount_field = parsed_response
                .body
                .get(".amount")
                .expect("Should find amount field");

            if let parser::standard::Body::KeyValue { key, value } = attestation_field {
                let attestation_key_range = key.with_quotes_and_colon();
                let attestation_val_range = value.with_quotes();
                let attestation_str =
                    &raw_response_str[attestation_key_range.start..attestation_val_range.end];
                assert_eq!(
                    attestation_str,
                    format!("\"attestation\":\"{}\"", transfer.attestation)
                );
            } else {
                panic!("attestation should be a KeyValue");
            }

            if let parser::standard::Body::KeyValue { key, value } = amount_field {
                let amount_key_range = key.with_quotes_and_colon();
                let amount_str = &raw_response_str[amount_key_range.start..value.end];
                assert_eq!(amount_str, "\"amount\":25");
            } else {
                panic!("amount should be a KeyValue");
            }
        });
    }

    #[test]
    fn test_parser_extracts_ranges_from_request_and_response() {
        shared::init_test_logging();

        smol::block_on(async {
            let app = test_app();
            let transfer = seed_transfer(&app, "bob").await;

            let test_tls_config = create_test_tls_config().unwrap();
            let (client_cnx, server_cnx) = UnixStream::pair().unwrap();

            let server_task = handle_connection(app, test_tls_config.server_config, server_cnx);

            let client_task = send_request(
                Uri::from_str(&format!("/api/attestations/{}", transfer.tx_id))
                    .expect("attestation uri"),
                test_tls_config.client_config,
                client_cnx,
            );

            let (server_result, client_result) = futures::join!(server_task, client_task);

            server_result.unwrap();
            let traffic = client_result.unwrap();

            let raw_request_str = String::from_utf8(traffic.raw_request.clone())
                .expect("Request should be valid UTF-8");

            let parsed_request = parser::standard::Request::from_str(&raw_request_str)
                .expect("Should parse request");

            assert_eq!(&raw_request_str[parsed_request.method.clone()], "GET");
            assert_eq!(
                &raw_request_str[parsed_request.url.clone()],
                format!("/api/attestations/{}", transfer.tx_id)
            );
            assert_eq!(
                &raw_request_str[parsed_request.protocol_version.clone()],
                "HTTP/1.1"
            );

            let content_type_headers = parsed_request
                .headers
                .get("content-type")
                .expect("Should find content-type header in request");

            assert_eq!(content_type_headers.len(), 1);

            let content_type_header = &content_type_headers[0];
            // Construct the full header range including name, separator, value, and newline
            let request_content_type_str = &raw_request_str[content_type_header
                .name
                .header_full_range(&content_type_header.value.with_newline())];
            assert_eq!(
                request_content_type_str,
                "content-type: application/json\r\n"
            );

            assert_eq!(
                parsed_request.body.len(),
                0,
                "GET request should have no body fields"
            );

            let raw_response_str = String::from_utf8(traffic.raw_response.clone())
                .expect("Response should be valid UTF-8");

            let parsed_response =
                Response::from_str(&raw_response_str).expect("Should parse response");

            assert_eq!(
                &raw_response_str[parsed_response.protocol_version.clone()],
                "HTTP/1.1"
            );
            assert_eq!(
                &raw_response_str[parsed_response.status_code.clone()],
                "200"
            );
            assert_eq!(&raw_response_str[parsed_response.status.clone()], "OK");

            let content_type_headers = parsed_response
                .headers
                .get("content-type")
                .expect("Should find content-type header");

            assert_eq!(content_type_headers.len(), 1);

            let content_type_header = &content_type_headers[0];
            let header_full_str = &raw_response_str[content_type_header
                .name
                .header_full_range(&content_type_header.value.with_newline())];
            assert_eq!(header_full_str, "content-type: application/json\r\n");

            let tx_id_field = parsed_response
                .body
                .get(".txId")
                .expect("Should find txId field");
            let attestation_field = parsed_response
                .body
                .get(".attestation")
                .expect("Should find attestation field");

            if let parser::standard::Body::KeyValue { key, value } = tx_id_field {
                let tx_id_key_range = key.with_quotes_and_colon();
                let tx_id_str = &raw_response_str[tx_id_key_range.start..value.end];
                assert_eq!(tx_id_str, "\"txId\":1");
            } else {
                panic!("txId should be a KeyValue");
            }

            if let parser::standard::Body::KeyValue { key, value } = attestation_field {
                let attestation_key_range = key.with_quotes_and_colon();
                let attestation_val_range = value.with_quotes();
                let attestation_str =
                    &raw_response_str[attestation_key_range.start..attestation_val_range.end];
                assert_eq!(
                    attestation_str,
                    format!("\"attestation\":\"{}\"", transfer.attestation)
                );
            } else {
                panic!("attestation should be a KeyValue");
            }
        });
    }
}
