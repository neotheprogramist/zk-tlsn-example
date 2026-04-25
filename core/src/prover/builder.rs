use std::sync::Arc;

use http_body_util::Empty;
use hyper::{Request, body::Bytes};
use tlsn::{
    config::{tls::TlsClientConfig, tls_commit::TlsCommitConfig},
    hash::HashAlgId,
};

use super::{Prover, reveal::RevealConfig};
use crate::transport::Runtime;

pub struct ProverBuilder {
    pub(super) runtime: Arc<dyn Runtime>,
    pub(super) tls_client_config: TlsClientConfig,
    pub(super) tls_commit_config: TlsCommitConfig,
    pub(super) request: Request<Empty<Bytes>>,
    pub(super) request_reveal_config: RevealConfig,
    pub(super) response_reveal_config: RevealConfig,
    pub(super) hash_alg: HashAlgId,
}

impl ProverBuilder {
    #[must_use]
    pub fn request_reveal_config(mut self, config: RevealConfig) -> Self {
        self.request_reveal_config = config;
        self
    }

    #[must_use]
    pub fn response_reveal_config(mut self, config: RevealConfig) -> Self {
        self.response_reveal_config = config;
        self
    }

    #[must_use]
    pub fn hash_alg(mut self, alg: HashAlgId) -> Self {
        self.hash_alg = alg;
        self
    }

    #[must_use]
    pub fn build(self) -> Prover {
        Prover {
            runtime: self.runtime,
            tls_client_config: self.tls_client_config,
            tls_commit_config: self.tls_commit_config,
            request: self.request,
            request_reveal_config: self.request_reveal_config,
            response_reveal_config: self.response_reveal_config,
            hash_alg: self.hash_alg,
        }
    }
}
