use crate::{
    error::{Error, Result},
    solver::SolverManager,
    Solver,
};
use chrono::{DateTime, Utc};
use openssl::pkey::{PKey, Private};
use reqwest::{header, Client, Response};
use serde::Serialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time;

mod jws;
mod nonce;
pub mod responses;

pub(crate) use jws::key_authorization;
use responses::ErrorType;

#[derive(Debug)]
pub(crate) struct ExternalAccountOptions<'o> {
    pub kid: &'o str,
    pub hmac: &'o str,
}

#[derive(Debug)]
pub(crate) struct Api(Arc<ApiInner>);

#[derive(Debug)]
struct ApiInner {
    client: Client,
    urls: responses::Directory,
    nonces: nonce::Pool,
    solvers: SolverManager,
}

impl Api {
    /// Construct the API for a directory from a URL
    pub(crate) async fn from_url(
        url: String,
        client: Client,
        max_nonces: usize,
        solvers: SolverManager,
    ) -> Result<Api> {
        let urls = client.get(url).send().await?.json().await?;

        let inner = ApiInner {
            client,
            urls,
            nonces: nonce::Pool::new(max_nonces),
            solvers,
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

    /// Perform an authenticated request to the API with a JSON body
    async fn request_json<S: Serialize>(
        &self,
        url: &str,
        body: S,
        private_key: &PKey<Private>,
        account_id: Option<&str>,
    ) -> Result<Response> {
        let body = serde_json::to_string(&body)?;
        self.request(url, &body, private_key, account_id).await
    }

    /// Perform an authenticated request to the API
    async fn request(
        &self,
        url: &str,
        body: &str,
        private_key: &PKey<Private>,
        account_id: Option<&str>,
    ) -> Result<Response> {
        let mut attempt = 0;

        loop {
            attempt += 1;

            let nonce = self.next_nonce().await?;
            let body = jws::sign(url, nonce, body, private_key, account_id)?;
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
        external_account_options: Option<ExternalAccountOptions<'_>>,
        private_key: &PKey<Private>,
    ) -> Result<(String, responses::Account)> {
        let external_account_binding = external_account_options
            .map(|opts| {
                jws::sign_with_eab(&self.0.urls.new_account, private_key, opts.kid, opts.hmac)
            })
            .transpose()?;

        let payload = responses::NewAccount {
            contacts,
            terms_of_service_agreed,
            only_return_existing,
            external_account_binding,
        };
        let response = self
            .request_json(&self.0.urls.new_account, &payload, private_key, None)
            .await?;

        let id = location_header(&response)?;
        let account = response.json::<responses::Account>().await?;
        Ok((id, account))
    }

    /// Perform the [newOrder](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4) operation.
    /// Returns the order's URL and creation response.
    pub async fn new_order(
        &self,
        identifiers: Vec<responses::Identifier>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<(String, responses::Order)> {
        let payload = responses::NewOrder {
            identifiers,
            not_before,
            not_after,
        };
        let response = self
            .request_json(
                &self.0.urls.new_order,
                &payload,
                private_key,
                Some(account_id),
            )
            .await?;

        let url = location_header(&response)?;
        let order = response.json().await?;
        Ok((url, order))
    }

    /// Fetch an order
    pub async fn fetch_order(
        &self,
        url: &str,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<responses::Order> {
        let response = self.request(url, "", private_key, Some(account_id)).await?;
        let order = response.json().await?;
        Ok(order)
    }

    /// Fetch an authorization
    pub async fn fetch_authorization(
        &self,
        url: &str,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<responses::Authorization> {
        let response = self.request(url, "", private_key, Some(account_id)).await?;
        let authorization = response.json().await?;
        Ok(authorization)
    }

    /// Fetch a challenge
    pub async fn fetch_challenge(
        &self,
        url: &str,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<responses::Challenge> {
        let response = self.request(url, "", private_key, Some(account_id)).await?;
        let challenge = response.json().await?;
        Ok(challenge)
    }

    /// Enqueue a challenge for validation
    pub async fn validate_challenge(
        &self,
        url: &str,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<responses::Challenge> {
        let response = self
            .request(url, "{}", private_key, Some(account_id))
            .await?;
        let challenge = response.json().await?;
        Ok(challenge)
    }

    /// Finalize an order using the provided CSR
    pub async fn finalize_order(
        &self,
        url: &str,
        csr: String,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<responses::Order> {
        let payload = responses::FinalizeOrder { csr };
        let response = self
            .request_json(url, &payload, private_key, Some(account_id))
            .await?;
        let order = response.json().await?;
        Ok(order)
    }

    /// Download the certificate from the order
    pub async fn download_certificate(
        &self,
        url: &str,
        private_key: &PKey<Private>,
        account_id: &str,
    ) -> Result<String> {
        let response = self.request(url, "", private_key, Some(account_id)).await?;
        let certificate = response.text().await?;
        Ok(certificate)
    }

    /// Revoke a certificate
    ///
    /// If the `account_key` is not `None`, the `private_key` must be that of the account. Otherwise,
    /// it must be the certificate's private key.
    pub async fn revoke_certificate(
        &self,
        certificate: String,
        reason: Option<responses::RevocationReason>,
        private_key: &PKey<Private>,
        account_id: Option<&str>,
    ) -> Result<()> {
        self.request_json(
            &self.0.urls.revoke_cert,
            &responses::RevocationRequest {
                certificate,
                reason,
            },
            private_key,
            account_id,
        )
        .await?;
        Ok(())
    }

    /// Wait until the fetched resource meets a condition or the maximum attempts are exceeded.
    #[allow(clippy::too_many_arguments)]
    pub async fn wait_until<'a, F, P, T, Fut>(
        &self,
        fetcher: F,
        predicate: P,
        url: &'a str,
        private_key: &'a PKey<Private>,
        account_id: &'a str,
        interval: Duration,
        max_attempts: usize,
    ) -> Result<T>
    where
        F: Fn(&'a str, &'a PKey<Private>, &'a str) -> Fut,
        Fut: Future<Output = Result<T>>,
        P: Fn(&T) -> bool,
    {
        let mut resource = fetcher(url, private_key, account_id).await?;
        let mut attempts: usize = 0;

        while !predicate(&resource) {
            if attempts >= max_attempts {
                return Err(Error::MaxAttemptsExceeded);
            }

            time::sleep(interval).await;

            resource = fetcher(url, private_key, account_id).await?;
            attempts += 1;
        }

        Ok(resource)
    }

    /// Get the solver for the challenge, if it exists.
    pub fn solver_for(&self, challenge: &responses::Challenge) -> Option<&dyn Solver> {
        self.0.solvers.get(challenge.type_)
    }
}

impl Clone for Api {
    fn clone(&self) -> Self {
        Api(Arc::clone(&self.0))
    }
}

fn location_header(response: &Response) -> Result<String> {
    Ok(response
        .headers()
        .get(header::LOCATION)
        .ok_or(Error::MissingHeader("location"))?
        .to_str()
        .map_err(|e| Error::InvalidHeader("location", e))?
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::Api;
    use crate::{
        solver::SolverManager,
        test::{client, TEST_URL},
        LETS_ENCRYPT_STAGING_URL,
    };

    async fn create_api(url: String) -> Api {
        Api::from_url(url, client(), 10, SolverManager::default())
            .await
            .unwrap()
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
