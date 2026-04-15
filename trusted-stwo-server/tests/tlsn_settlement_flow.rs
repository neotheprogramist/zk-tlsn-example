use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use server::app::get_app;
use tower::util::ServiceExt;
use trusted_stwo_server::{
    Signer, router,
    types::{VerifyTlsnAndSignSettlementRequest, VerifyTlsnAndSignSettlementResponse},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_mock_server_to_trusted_server_tlsn_settlement_signing() {
    // 1) Query mock Revolut-like server endpoint.
    let mock_app = get_app(HashMap::new());
    let mock_req = Request::builder()
        .method("GET")
        .uri("/api/transfer/txn-comment-abc")
        .body(Body::empty())
        .expect("mock request");
    let mock_resp = mock_app.oneshot(mock_req).await.expect("mock response");
    assert_eq!(mock_resp.status(), StatusCode::OK);

    let mut transcript = String::from("HTTP/1.1 200 OK\r\n");
    for (name, value) in mock_resp.headers() {
        let v = value.to_str().expect("header utf8");
        transcript.push_str(&format!("{}: {}\r\n", name.as_str(), v));
    }
    transcript.push_str("\r\n");
    let body_bytes = mock_resp
        .into_body()
        .collect()
        .await
        .expect("collect mock body")
        .to_bytes();
    transcript.push_str(std::str::from_utf8(&body_bytes).expect("body utf8"));

    // 2) Send transcript to trusted server for verification + extraction + signing.
    let signer = Arc::new(
        Signer::from_private_key_hex(
            "a731c83a8c388ff4a8bd05c429ca250ca09c8a444c8110515db297379899ce8b",
        )
        .expect("signer"),
    );
    let trusted_app = router(signer);

    let trusted_req = Request::builder()
        .method("POST")
        .uri("/verify-tlsn-and-sign-settlement")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&VerifyTlsnAndSignSettlementRequest {
                transcript_response: transcript,
            })
            .expect("serialize trusted request"),
        ))
        .expect("trusted request");

    let trusted_resp = trusted_app
        .oneshot(trusted_req)
        .await
        .expect("trusted response");
    let trusted_status = trusted_resp.status();
    let trusted_body = trusted_resp
        .into_body()
        .collect()
        .await
        .expect("collect trusted body")
        .to_bytes();
    assert_eq!(
        trusted_status,
        StatusCode::OK,
        "trusted response body: {}",
        String::from_utf8_lossy(&trusted_body)
    );
    let parsed: VerifyTlsnAndSignSettlementResponse =
        serde_json::from_slice(&trusted_body).expect("decode trusted response");

    println!(
        "[TLSN settlement] signing payload => comment_data='{}', rev_tag='{}', fiat_amount={}",
        parsed.comment_data, parsed.rev_tag, parsed.fiat_amount
    );
    println!(
        "[TLSN settlement] hashes => claim_hash={}, message_hash={}",
        parsed.claim_hash_hex, parsed.message_hash_hex
    );
    println!(
        "[TLSN settlement] signature => signer={}, v={}, r={}, s={}",
        parsed.signer_address, parsed.signature_v, parsed.signature_r_hex, parsed.signature_s_hex
    );

    assert!(parsed.verified);
    assert_eq!(parsed.comment_data, "txn-comment-abc");
    assert_eq!(parsed.rev_tag, "@alice");
    assert_eq!(parsed.fiat_amount, 123);
    assert!(parsed.signature_hex.starts_with("0x"));
    assert!(parsed.claim_hash_hex.starts_with("0x"));
    assert!(parsed.message_hash_hex.starts_with("0x"));
}
