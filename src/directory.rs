use crate::solver::SolverManager;
use crate::{
    account::{AccountBuilder, NoPrivateKey},
    api::{responses::DirectoryMeta, Api},
    error::Result,
    Solver,
};
use reqwest::Client;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// The Let's Encrypt production ACMEv2 API
pub const LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The Let's Encrypt staging ACMEv2 API
pub const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// A builder used to create a [`Directory`]
pub struct DirectoryBuilder {
    url: String,
    client: Option<Client>,
    max_nonces: usize,
    solvers: SolverManager,
}

impl DirectoryBuilder {
    /// Creates a new builder with the specified directory root URL.
    pub fn new(url: String) -> Self {
        DirectoryBuilder {
            url,
            client: None,
            max_nonces: 10,
            solvers: SolverManager::default(),
        }
    }

    /// Use a custom [`reqwest::Client`] for all outbount HTTP requests
    /// to the ACME server.
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the maximum number of nonces to keep, defaults to 10
    pub fn max_nonces(mut self, max: usize) -> Self {
        self.max_nonces = max;
        self
    }

    /// Set the DNS-01 solver
    pub fn set_dns01_solver(mut self, solver: Box<dyn Solver>) -> Self {
        self.solvers.set_dns01_solver(solver);
        self
    }

    /// Set the HTTP-01 solver
    pub fn set_http01_solver(mut self, solver: Box<dyn Solver>) -> Self {
        self.solvers.set_http01_solver(solver);
        self
    }

    /// Set the TLS-ALPN-01 solver
    pub fn set_tls_alpn01_solver(mut self, solver: Box<dyn Solver>) -> Self {
        self.solvers.set_tls_alpn01_solver(solver);
        self
    }

    /// Build a [`Directory`] using the given parameters.
    ///
    /// If no http client is specified, a default client will be created with
    /// the user-agent `lers/<version>`.
    pub async fn build(self) -> Result<Directory> {
        let client = self
            .client
            .unwrap_or_else(|| Client::builder().user_agent(USER_AGENT).build().unwrap());

        let api = Api::from_url(self.url, client, self.max_nonces, self.solvers).await?;

        Ok(Directory(api))
    }
}

/// Entry point for accessing an ACME API
#[derive(Clone, Debug)]
pub struct Directory(Api);

impl Directory {
    /// Build a new directory with the specified root URL
    pub fn builder<S: Into<String>>(url: S) -> DirectoryBuilder {
        DirectoryBuilder::new(url.into())
    }

    /// Access the builder to lookup an existing or create a new account
    pub fn account(&self) -> AccountBuilder<NoPrivateKey> {
        AccountBuilder::<NoPrivateKey>::new(self.0.clone())
    }

    /// Get optional metadata about the directory
    #[inline(always)]
    pub fn meta(&self) -> &DirectoryMeta {
        self.0.meta()
    }
}

#[cfg(test)]
mod tests {
    use super::{Directory, LETS_ENCRYPT_STAGING_URL};
    use crate::test::directory;

    #[tokio::test]
    async fn initialize_lets_encrypt() {
        let directory = Directory::builder(LETS_ENCRYPT_STAGING_URL)
            .build()
            .await
            .unwrap();

        assert_eq!(
            directory.meta().terms_of_service,
            Some("https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf".into())
        );
        assert_eq!(
            directory.meta().website,
            Some("https://letsencrypt.org/docs/staging-environment/".into())
        );
        assert_eq!(
            directory.meta().caa_identities,
            Some(vec!["letsencrypt.org".into()])
        );
        assert_eq!(directory.meta().external_account_required, None);
    }

    #[tokio::test]
    async fn initialize_pebble() {
        let directory = directory().await;

        assert_eq!(
            directory.meta().terms_of_service,
            Some("data:text/plain,Do%20what%20thou%20wilt".into())
        );
        assert_eq!(directory.meta().website, None);
        assert_eq!(directory.meta().caa_identities, None);
        assert_eq!(directory.meta().external_account_required, Some(false));
    }
}
