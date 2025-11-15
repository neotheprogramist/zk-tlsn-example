pub mod app;
pub mod client;
pub mod executor;
pub mod handler;

pub use client::{CapturedTraffic, ClientError, send_request};
pub use executor::SmolExecutor;
pub use handler::{ConnectionError, handle_connection};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::Uri;
    use parser::{BodySearchable, HeaderSearchable, ResponseParser};
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
                ResponseParser::parse_response(&raw_response_str).expect("Should parse response");

            // Check status line using exact equality
            let status_line_range = parsed_response.get_status_line_range();
            let status_line_str = &raw_response_str[status_line_range];
            assert_eq!(status_line_str, "HTTP/1.1 200 OK\r\n");

            // Use parser to get exact body keypaths
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

            let parsed_request = parser::RequestParser::parse_request(&raw_request_str)
                .expect("Should parse request");

            let request_line_range = parsed_request.get_request_line_range();
            let request_line_str = &raw_request_str[request_line_range];
            assert_eq!(request_line_str, "GET /api/balance/alice HTTP/1.1\r\n");

            let request_header_ranges = parsed_request
                .get_header_ranges(&["content-type"])
                .expect("Should find content-type header in request");

            assert_eq!(request_header_ranges.len(), 1);

            let request_content_type_str = &raw_request_str[request_header_ranges[0].clone()];
            assert_eq!(
                request_content_type_str,
                "content-type: application/json\r\n"
            );

            let raw_response_str = String::from_utf8(traffic.raw_response.clone())
                .expect("Response should be valid UTF-8");

            let parsed_response =
                ResponseParser::parse_response(&raw_response_str).expect("Should parse response");

            // Check status line using exact equality
            let status_line_range = parsed_response.get_status_line_range();
            let status_line_str = &raw_response_str[status_line_range];
            assert_eq!(status_line_str, "HTTP/1.1 200 OK\r\n");

            let header_ranges = parsed_response
                .get_header_ranges(&["content-type"])
                .expect("Should find content-type header");

            assert_eq!(header_ranges.len(), 1);

            let content_type_range = &header_ranges[0];
            let content_type_str = &raw_response_str[content_type_range.clone()];
            assert_eq!(content_type_str, "content-type: application/json\r\n");

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
