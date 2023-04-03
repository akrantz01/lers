use super::{
    common::{ChallengeAuthorization, Challenges, SolverHandle},
    Solver,
};
use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

mod error;
#[cfg(test)]
mod smoke;
mod stream;

/// A bare-bones implementation of a solver for the TLS-ALPN-01 challenge.
#[derive(Clone, Debug, Default)]
pub struct TlsAlpn01Solver {
    challenges: Challenges,
}

impl TlsAlpn01Solver {
    /// Create a new solver
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl Solver for TlsAlpn01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut challenges = self.challenges.write();
        challenges.insert(
            token,
            ChallengeAuthorization {
                domain,
                key_authorization,
            },
        );

        Ok(())
    }

    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut challenges = self.challenges.write();
        challenges.remove(token);

        Ok(())
    }
}

#[derive(Debug)]
struct ChallengeServer {
    challenges: Challenges,
}

#[cfg(test)]
mod tests {}
