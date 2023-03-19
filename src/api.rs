use crate::error::{Error, Result};
use openssl::pkey::{PKey, Private};
use reqwest::{header, Client, Response};
use serde::Serialize;
use std::sync::Arc;

mod jws;
mod nonce;
pub mod responses;

pub use jws::Error as JWSError;
use responses::ErrorType;

#[derive(Debug)]
pub(crate) struct Api(Arc<ApiInner>);

#[derive(Debug)]
struct ApiInner {
    client: Client,
    urls: responses::Directory,
    nonces: nonce::Pool,
}

impl Api {
    /// Construct the API for a directory from a URL
    pub(crate) async fn from_url(url: String, client: Client, max_nonces: usize) -> Result<Api> {
        let urls = client.get(url).send().await?.json().await?;

        let inner = ApiInner {
            client,
            urls,
            nonces: nonce::Pool::new(max_nonces),
        };
        Ok(Api(Arc::new(inner)))
    }

    /// Get optional metadata about the directory
    #[inline(always)]
    pub(crate) fn meta(&self) -> &responses::DirectoryMeta {
        &self.0.urls.meta
    }

    /// Retrieve the next nonce from the pool
    #[inline(always)]
    async fn next_nonce(&self) -> Result<String> {
        self.0
            .nonces
            .get(&self.0.urls.new_nonce, &self.0.client)
            .await
    }

    /// Perform an authenticated request to the API
    async fn request<S: Serialize>(
        &self,
        url: &str,
        body: S,
        private_key: &PKey<Private>,
        account_id: Option<&str>,
    ) -> Result<Response> {
        let payload = serde_json::to_string(&body)?;
        let mut attempt = 0;

        loop {
            attempt += 1;

            let nonce = self.next_nonce().await?;
            let body = jws::sign(url, nonce, &payload, private_key, account_id)?;
            let body = serde_json::to_vec(&body)?;

            let response = self
                .0
                .client
                .post(url)
                .header(header::CONTENT_TYPE, "application/jose+json")
                .body(body)
                .send()
                .await?;

            self.0.nonces.extract_from_response(&response)?;

            if response.status().is_success() {
                return Ok(response);
            }

            let err = response.json::<responses::Error>().await?;
            if err.type_ == ErrorType::BadNonce && attempt <= 3 {
                continue;
            }

            return Err(Error::Server(err));
        }
    }

    /// Perform the [newAccount](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3) operation.
    /// Returns the account's ID and creation response.
    pub async fn new_account(
        &self,
        contacts: Option<Vec<String>>,
        terms_of_service_agreed: bool,
        only_return_existing: bool,
        private_key: &PKey<Private>,
    ) -> Result<(String, responses::Account)> {
        let payload = responses::NewAccount {
            contacts,
            terms_of_service_agreed,
            only_return_existing,
        };
        let response = self
            .request(&self.0.urls.new_account, &payload, private_key, None)
            .await?;

        let id = response
            .headers()
            .get(header::LOCATION)
            .ok_or(Error::MissingHeader("location"))?
            .to_str()
            .map_err(|e| Error::InvalidHeader("location", e))?
            .to_owned();

        let account = response.json::<responses::Account>().await?;
        Ok((id, account))
    }
}

impl Clone for Api {
    fn clone(&self) -> Self {
        Api(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::Api;
    use crate::{LETS_ENCRYPT_STAGING_URL, TEST_URL};
    use reqwest::Client;

    async fn create_api(url: String) -> Api {
        let client = Client::builder()
            .danger_accept_invalid_hostnames(true)
            .user_agent("lers/testing")
            .build()
            .unwrap();
        Api::from_url(url, client, 10).await.unwrap()
    }

    #[tokio::test]
    async fn new_api_lets_encrypt() {
        let api = create_api(LETS_ENCRYPT_STAGING_URL.to_string()).await;

        assert_eq!(
            api.0.urls.new_nonce,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce"
        );
        assert_eq!(
            api.0.urls.new_account,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct"
        );
        assert_eq!(
            api.0.urls.new_order,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"
        );
        assert_eq!(
            api.0.urls.revoke_cert,
            "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
        );
        assert_eq!(
            api.0.urls.key_change,
            "https://acme-staging-v02.api.letsencrypt.org/acme/key-change"
        );
        assert_eq!(api.0.urls.new_authz, None);
    }

    #[tokio::test]
    async fn new_api_pebble() {
        let api = create_api(TEST_URL.to_string()).await;

        assert_eq!(api.0.urls.new_nonce, "https://10.30.50.2:14000/nonce-plz");
        assert_eq!(
            api.0.urls.new_account,
            "https://10.30.50.2:14000/sign-me-up"
        );
        assert_eq!(api.0.urls.new_order, "https://10.30.50.2:14000/order-plz");
        assert_eq!(
            api.0.urls.revoke_cert,
            "https://10.30.50.2:14000/revoke-cert"
        );
        assert_eq!(
            api.0.urls.key_change,
            "https://10.30.50.2:14000/rollover-account-key"
        );
        assert_eq!(api.0.urls.new_authz, None);
    }
}
