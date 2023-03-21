use crate::responses::AuthorizationStatus;
use crate::{
    api::Api,
    error::Result,
    responses::{self, Identifier},
    Account,
};
use chrono::{DateTime, Utc};
use futures::future;

/// A convenience wrapper around an order resource
#[derive(Debug)]
pub(crate) struct Order<'a> {
    api: Api,
    account: &'a Account,
    url: String,
    inner: responses::Order,
}

impl<'a> Order<'a> {
    /// Create a new order for a certificate
    pub async fn create(
        api: Api,
        identifiers: Vec<Identifier>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
        account: &'a Account,
    ) -> Result<Order<'a>> {
        let (url, inner) = api
            .new_order(
                identifiers,
                not_before,
                not_after,
                &account.private_key,
                &account.id,
            )
            .await?;

        Ok(Order {
            api,
            account,
            url,
            inner,
        })
    }

    /// Get all the authorizations for the order
    pub async fn authorizations(&self) -> Result<Vec<Authorization>> {
        future::try_join_all(
            self.inner
                .authorizations
                .iter()
                .map(|url| Authorization::fetch(self.api.clone(), &self.account, &url)),
        )
        .await
    }
}

/// A convenience wrapper around an authorization
#[derive(Debug)]
pub(crate) struct Authorization<'a> {
    api: Api,
    account: &'a Account,
    url: String,
    inner: responses::Authorization,
}

impl<'a> Authorization<'a> {
    /// Fetch an authorization from it's URL
    async fn fetch(api: Api, account: &'a Account, url: &str) -> Result<Authorization<'a>> {
        let authorization = api
            .fetch_authorization(url, &account.private_key, &account.id)
            .await?;

        Ok(Authorization {
            api,
            account,
            url: url.to_owned(),
            inner: authorization,
        })
    }
}
