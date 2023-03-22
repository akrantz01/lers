use crate::{
    error::Result,
    responses::{self, Identifier},
    Account,
};
use chrono::{DateTime, Utc};
use futures::future;
use std::cmp::Ordering;

/// A convenience wrapper around an order resource
#[derive(Debug)]
pub(crate) struct Order<'a> {
    account: &'a Account,
    url: String,
    inner: responses::Order,
}

impl<'a> Order<'a> {
    /// Create a new order for a certificate
    pub async fn create(
        account: &'a Account,
        identifiers: Vec<Identifier>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
    ) -> Result<Order<'a>> {
        let (url, inner) = account
            .api
            .new_order(
                identifiers,
                not_before,
                not_after,
                &account.private_key,
                &account.id,
            )
            .await?;

        Ok(Order {
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
                .map(|url| Authorization::fetch(self.account, url)),
        )
        .await
    }
}

/// A convenience wrapper around an authorization
#[derive(Debug)]
pub(crate) struct Authorization<'a> {
    account: &'a Account,
    url: String,
    inner: responses::Authorization,
}

impl<'a> Authorization<'a> {
    /// Fetch an authorization from it's URL
    async fn fetch(account: &'a Account, url: &str) -> Result<Authorization<'a>> {
        let mut authorization = account
            .api
            .fetch_authorization(url, &account.private_key, &account.id)
            .await?;

        authorization.challenges.sort_by(challenge_type);

        Ok(Authorization {
            account,
            url: url.to_owned(),
            inner: authorization,
        })
    }
}

fn challenge_type(a: &responses::Challenge, b: &responses::Challenge) -> Ordering {
    use responses::ChallengeType::*;

    match (a.type_, b.type_) {
        (Dns01, Dns01) | (Http01, Http01) | (TlsAlpn01, TlsAlpn01) | (Unknown, Unknown) => {
            Ordering::Equal
        }
        // prefer DNS-01 over everything
        (Dns01, _) => Ordering::Greater,
        // prefer HTTP-01 over everything except for DNS
        (Http01, TlsAlpn01) | (Http01, Unknown) => Ordering::Greater,
        (Http01, Dns01) => Ordering::Less,
        // prefer TLS-ALPN-01 last
        (TlsAlpn01, Unknown) => Ordering::Greater,
        (TlsAlpn01, Http01) | (TlsAlpn01, Dns01) => Ordering::Less,
        // never prefer unknown, we can't handle it
        (Unknown, _) => Ordering::Less,
    }
}
