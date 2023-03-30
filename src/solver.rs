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
    ) -> Result<(), Box<dyn std::error::Error + Send + 'static>>;

    /// Used to clean-up the challenge if [`Solver::present`] ends in a non-error state.
    async fn cleanup(&self, token: &str)
        -> Result<(), Box<dyn std::error::Error + Send + 'static>>;

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
pub fn boxed_err<E>(e: E) -> Box<dyn std::error::Error + Send + 'static>
where
    E: std::error::Error + Send + 'static,
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
