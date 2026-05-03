use tlsn::config::tls_commit::TlsCommitProtocolConfig;

pub fn standard_protocol_policy(
    max_sent_data: usize,
    max_recv_data: usize,
) -> impl FnOnce(&TlsCommitProtocolConfig) -> Result<(), String> {
    move |protocol| {
        let TlsCommitProtocolConfig::Mpc(mpc) = protocol else {
            return Err("expected MPC-TLS protocol".to_string());
        };
        if mpc.max_sent_data() > max_sent_data {
            return Err(format!(
                "max_sent_data {} exceeds limit {}",
                mpc.max_sent_data(),
                max_sent_data
            ));
        }
        if mpc.max_recv_data() > max_recv_data {
            return Err(format!(
                "max_recv_data {} exceeds limit {}",
                mpc.max_recv_data(),
                max_recv_data
            ));
        }
        Ok(())
    }
}

pub fn standard_request_policy() -> impl FnOnce(bool, bool) -> Result<(), String> {
    |server_identity_revealed, reveal_payload_present| {
        if !server_identity_revealed {
            return Err("missing required server identity reveal".to_string());
        }
        if !reveal_payload_present {
            return Err("missing required transcript reveal payload".to_string());
        }
        Ok(())
    }
}
