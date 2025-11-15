pub mod app;
pub mod client;
pub mod executor;
pub mod handler;

pub use client::{ClientError, Response, send_request};
pub use executor::SmolExecutor;
pub use handler::{ConnectionError, handle_connection};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::{StatusCode, Uri};
    use parser::{BodySearchable, HeaderSearchable, ResponseParser};
    use shared::create_test_tls_config;
    use smol::net::unix::UnixStream;

    use crate::{app::get_app, handle_connection, send_request};

    #[test]
    fn test_https_get_balance_existing_user() {
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
            let response = client_result.expect("Client task should complete");

            assert_eq!(response.status, StatusCode::OK);

            let body_str =
                String::from_utf8(response.body).expect("Response body should be valid UTF-8");
            assert!(body_str.contains("alice"));
            assert!(body_str.contains("100"));
        });
    }

    #[test]
    fn test_parser_extracts_ranges_from_request_and_response() {
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
            let response = client_result.expect("Client task should complete");

            assert_eq!(response.status, StatusCode::OK);

            let raw_request_str = String::from_utf8(response.raw_request.clone())
                .expect("Request should be valid UTF-8");

            eprintln!("Raw request:\n{}", raw_request_str);
            eprintln!("Raw request bytes: {:?}", raw_request_str.as_bytes());

            let parsed_request = parser::RequestParser::parse_request(&raw_request_str)
                .expect("Should parse request");

            let request_line_range = parsed_request.get_request_line_range();
            let request_line_str = &raw_request_str[request_line_range];
            assert!(request_line_str.contains("GET /api/balance/alice HTTP/1.1"));

            let request_header_ranges = parsed_request
                .get_header_ranges(&["content-type"])
                .expect("Should find content-type header in request");

            assert_eq!(request_header_ranges.len(), 1);

            let request_content_type_str = &raw_request_str[request_header_ranges[0].clone()];
            assert!(request_content_type_str.contains("application/json"));

            let raw_response_str = String::from_utf8(response.raw_response.clone())
                .expect("Response should be valid UTF-8");

            eprintln!("Raw response:\n{}", raw_response_str);
            eprintln!("Raw response bytes: {:?}", raw_response_str.as_bytes());

            let parsed_response =
                ResponseParser::parse_response(&raw_response_str).expect("Should parse response");

            let header_ranges = parsed_response
                .get_header_ranges(&["content-type"])
                .expect("Should find content-type header");

            assert_eq!(header_ranges.len(), 1);

            let content_type_range = &header_ranges[0];
            let content_type_str = &raw_response_str[content_type_range.clone()];
            assert!(content_type_str.contains("application/json"));

            let body_ranges = parsed_response
                .get_body_keypaths_ranges(&["username", "balance"])
                .expect("Should find username and balance fields");

            assert_eq!(body_ranges.len(), 2);

            let username_str = &raw_response_str[body_ranges[0].clone()];
            assert_eq!(username_str, "\"username\":\"alice\"");

            let balance_str = &raw_response_str[body_ranges[1].clone()];
            assert_eq!(balance_str, "\"balance\":100");
        });
    }
}
