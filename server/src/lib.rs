pub mod app;
pub mod client;
pub mod executor;
pub mod handler;

pub use client::{CapturedTraffic, ClientError, send_request};
pub use executor::SmolExecutor;
pub use handler::{ConnectionError, handle_connection};

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use hyper::Uri;
    use parser::{JsonFieldRangeExt, standard::Response};
    use shared::create_test_tls_config;
    use smol::net::unix::UnixStream;

    use crate::{app::get_app, handle_connection, send_request};

    #[test]
    fn test_https_get_balance_existing_user() {
        shared::init_test_logging();

        smol::block_on(async {
            let mut balances = HashMap::new();
            balances.insert("alice".to_string(), 100);
            let app = get_app(balances);

            let test_tls_config = create_test_tls_config().unwrap();
            let (client_cnx, server_cnx) = UnixStream::pair().unwrap();

            let server_task = handle_connection(app, test_tls_config.server_config, server_cnx);

            let client_task = send_request(
                Uri::from_static("/api/balance/alice"),
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

            let username_field = parsed_response
                .body
                .get(".username")
                .expect("Should find username field");
            let balance_field = parsed_response
                .body
                .get(".balance")
                .expect("Should find balance field");

            if let parser::standard::Body::KeyValue { key, value } = username_field {
                let username_key_range = key.with_quotes_and_colon();
                let username_val_range = value.with_quotes();
                let username_str =
                    &raw_response_str[username_key_range.start..username_val_range.end];
                assert_eq!(username_str, "\"username\":\"alice\"");
            } else {
                panic!("username should be a KeyValue");
            }

            if let parser::standard::Body::KeyValue { key, value } = balance_field {
                let balance_key_range = key.with_quotes_and_colon();
                let balance_str = &raw_response_str[balance_key_range.start..value.end];
                assert_eq!(balance_str, "\"balance\":100");
            } else {
                panic!("balance should be a KeyValue");
            }
        });
    }

    #[test]
    fn test_parser_extracts_ranges_from_request_and_response() {
        shared::init_test_logging();

        smol::block_on(async {
            let mut balances = HashMap::new();
            balances.insert("alice".to_string(), 100);
            let app = get_app(balances);

            let test_tls_config = create_test_tls_config().unwrap();
            let (client_cnx, server_cnx) = UnixStream::pair().unwrap();

            let server_task = handle_connection(app, test_tls_config.server_config, server_cnx);

            let client_task = send_request(
                Uri::from_static("/api/balance/alice"),
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
                "/api/balance/alice"
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

            let username_field = parsed_response
                .body
                .get(".username")
                .expect("Should find username field");
            let balance_field = parsed_response
                .body
                .get(".balance")
                .expect("Should find balance field");

            if let parser::standard::Body::KeyValue { key, value } = username_field {
                let username_key_range = key.with_quotes_and_colon();
                let username_val_range = value.with_quotes();
                let username_str =
                    &raw_response_str[username_key_range.start..username_val_range.end];
                assert_eq!(username_str, "\"username\":\"alice\"");
            } else {
                panic!("username should be a KeyValue");
            }

            if let parser::standard::Body::KeyValue { key, value } = balance_field {
                let balance_key_range = key.with_quotes_and_colon();
                let balance_str = &raw_response_str[balance_key_range.start..value.end];
                assert_eq!(balance_str, "\"balance\":100");
            } else {
                panic!("balance should be a KeyValue");
            }
        });
    }
}
