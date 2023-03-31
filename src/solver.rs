//! ACME challenge solvers
//!
//! There are currently two supported challenge solver types:
//! [HTTP-01](Http01Solver) and [DNS-01](dns).
//!
//! ## HTTP-01
//! The HTTP-01 solver works by making a file available containing a random token and fingerprint
//! of your account key, proving control over the website to the CA. This is the most commonly used
//! ACME challenge due to its ease of integration with popular web server platforms.
//!
//! However, it can only work over port `80` and the challenge file must be accessible on all
//! servers resolved by the domain.
//!
//! ## DNS-01
//! The DNS-01 solver works by creating a TXT record for your domain containing a random token and
//! fingerprint of your account key, similar to the HTTP-01 challenge. This is particularly useful
//! when you have more than one web server or port `80` is blocked. Furthermore, it is the only way
//! to issue [wildcard certificates](https://en.wikipedia.org/wiki/Wildcard_certificate).
//!
//! However, you will need to deal with the potential security threat of keeping DNS API credentials
//! on your server.

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    time::Duration,
};

#[cfg(feature = "dns-01")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-01")))]
pub mod dns;
#[cfg(feature = "http-01")]
mod http;

use crate::responses::ChallengeType;
#[cfg(feature = "http-01")]
#[cfg_attr(docsrs, doc(cfg(feature = "http-01")))]
pub use http::{Http01Solver, Http01SolverHandle};

/// Enables implementing a custom challenge solver.
///
/// Solvers must be able to handle multiple challenges at once as authorizations are solved in
/// parallel.
#[async_trait::async_trait]
pub trait Solver {
    /// Makes the solution to a challenge available to be solved.
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Used to clean-up the challenge if [`Solver::present`] ends in a non-error state.
    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// How many attempts to make before timing out. Defaults to 30 tries.
    fn attempts(&self) -> usize {
        30
    }

    /// How long to wait between successive checks. Defaults to 2 seconds.
    fn interval(&self) -> Duration {
        Duration::from_secs(2)
    }
}

/// Used by [`Solver`]s to convert an arbitrary error to a boxed trait object.
pub fn boxed_err<E>(e: E) -> Box<dyn std::error::Error + Send + Sync + 'static>
where
    E: std::error::Error + Send + Sync + 'static,
{
    Box::new(e)
}

/// Handle solving a given challenge using the configured solver(s)
#[derive(Default)]
pub(crate) struct SolverManager {
    solvers: HashMap<ChallengeType, Box<dyn Solver>>,
}

impl SolverManager {
    /// Set the DNS-01 solver
    pub fn set_dns01_solver(&mut self, solver: Box<dyn Solver>) {
        self.solvers.insert(ChallengeType::Dns01, solver);
    }

    /// Set the HTTP-01 solver
    pub fn set_http01_solver(&mut self, solver: Box<dyn Solver>) {
        self.solvers.insert(ChallengeType::Http01, solver);
    }

    /// Set the TLS-ALPN-01 solver
    pub fn set_tls_alpn01_solver(&mut self, solver: Box<dyn Solver>) {
        self.solvers.insert(ChallengeType::TlsAlpn01, solver);
    }

    /// Get the solver for the challenge type
    pub fn get(&self, type_: ChallengeType) -> Option<&dyn Solver> {
        self.solvers.get(&type_).map(AsRef::as_ref)
    }
}

impl Debug for SolverManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let solvers = self.solvers.keys().collect::<Vec<&ChallengeType>>();

        // `Solver` doesn't implement debug, so we'll display what solvers are registered instead
        f.debug_struct("SolverManager")
            .field("registered", &solvers)
            .finish()
    }
}
