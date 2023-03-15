use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// The Let's Encrypt production ACMEv2 API
pub const LETS_ENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The Let's Encrypt staging ACMEv2 API
pub const LETS_ENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// A builder used to create a [`Directory`]
pub struct DirectoryBuilder {
    url: String,
    client: Option<Client>,
}

impl DirectoryBuilder {
    /// Creates a new builder with the specified directory root URL.
    pub fn new(url: String) -> Self {
        DirectoryBuilder { url, client: None }
    }

    /// Use a custom [`reqwest::Client`] for all outbount HTTP requests
    /// to the ACME server.
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Build a [`Directory`] using the given parameters.
    ///
    /// If no http client is specified, a default client will be created with
    /// the user-agent `lers/<version>`.
    pub async fn build(self) -> Result<Arc<Directory>, reqwest::Error> {
        let client = self
            .client
            .unwrap_or_else(|| Client::builder().user_agent(USER_AGENT).build().unwrap());

        let info = client.get(self.url).send().await?.json().await?;

        Ok(Arc::new(Directory { info, client }))
    }
}

/// Entry point for accessing an ACME API
#[derive(Debug)]
pub struct Directory {
    client: Client,
    info: DirectoryInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryInfo {
    new_nonce: String,
    new_account: String,
    new_order: String,
    revoke_cert: String,
    key_change: String,
    new_authz: Option<String>,
    #[serde(default)]
    meta: DirectoryMeta,
}

/// Metadata about a directory.
///
/// Directories are not required to provide this information.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}

impl Directory {
    /// Build a new directory with the specified root URL
    pub fn builder<S: Into<String>>(url: S) -> DirectoryBuilder {
        DirectoryBuilder::new(url.into())
    }

    /// Get optional metadata about the directory
    #[inline(always)]
    pub fn meta(&self) -> &DirectoryMeta {
        &self.info.meta
    }
}

#[cfg(test)]
mod tests {
    use super::{Directory, LETS_ENCRYPT_STAGING_URL};

    #[tokio::test]
    async fn initialize() {
        // TODO: use Let's Encrypt Pebble for testing (https://github.com/letsencrypt/pebble)
        let directory = Directory::builder(LETS_ENCRYPT_STAGING_URL)
            .build()
            .await
            .unwrap();

        assert_eq!(
            directory.info.new_nonce,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce"
        );
        assert_eq!(
            directory.info.new_account,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct"
        );
        assert_eq!(
            directory.info.new_order,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"
        );
        assert_eq!(
            directory.info.revoke_cert,
            "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
        );
        assert_eq!(
            directory.info.key_change,
            "https://acme-staging-v02.api.letsencrypt.org/acme/key-change"
        );
        assert_eq!(directory.info.new_authz, None);
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
}
