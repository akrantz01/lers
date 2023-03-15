use reqwest::Client;
use std::sync::Arc;

mod nonce;
pub(crate) mod responses;

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
    pub(crate) async fn from_url(
        url: String,
        client: Client,
        max_nonces: usize,
    ) -> Result<Api, reqwest::Error> {
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
}

impl Clone for Api {
    fn clone(&self) -> Self {
        Api(Arc::clone(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::Api;
    use crate::LETS_ENCRYPT_STAGING_URL;
    use reqwest::Client;

    async fn create_api() -> Api {
        Api::from_url(LETS_ENCRYPT_STAGING_URL.to_owned(), Client::new(), 10)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn new_api() {
        let api = create_api().await;

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
}
