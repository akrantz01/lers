use crate::order::Order;
use crate::{
    account::Account,
    api::Api,
    error::{Error, Result},
    responses::Identifier,
};
use chrono::{DateTime, Utc};

/// Used to configure the ordering of a certificate
pub struct CertificateBuilder<'a> {
    api: Api,
    account: &'a Account,

    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl<'a> CertificateBuilder<'a> {
    pub(crate) fn new(api: Api, account: &'a Account) -> CertificateBuilder<'a> {
        CertificateBuilder {
            api,
            account,
            // We know there'll be at least 1 identifier in the order
            identifiers: Vec::with_capacity(1),
            not_before: None,
            not_after: None,
        }
    }

    /// Add a domain (DNS identifier) to the certificate.
    ///
    /// All certificates must have at least one domain associated with them.
    pub fn add_domain<S: Into<String>>(mut self, domain: S) -> Self {
        self.identifiers.push(Identifier::Dns(domain.into()));
        self
    }

    /// When the certificate should expire.
    ///
    /// This may not be supported by all ACME servers, namely
    /// [Let's Encrypt](https://github.com/letsencrypt/boulder/blob/main/docs/acme-divergences.md#section-74).
    pub fn expiration(mut self, at: DateTime<Utc>) -> Self {
        self.not_after = Some(at);
        self
    }

    /// When the certificate should start being valid.
    ///
    /// This may not be supported by all ACME servers, namely
    /// [Let's Encrypt](https://github.com/letsencrypt/boulder/blob/main/docs/acme-divergences.md#section-74).
    pub fn not_before(mut self, at: DateTime<Utc>) -> Self {
        self.not_before = Some(at);
        self
    }

    /// Obtain the certificate
    pub async fn obtain(self) -> Result<()> {
        if self.identifiers.is_empty() {
            return Err(Error::MissingIdentifiers);
        }

        let order = Order::create(
            self.api,
            self.identifiers,
            self.not_before,
            self.not_after,
            self.account,
        )
        .await?;

        /// TODO: complete authorizations
        let _authorizations = order.authorizations().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{test::account, Error};

    #[tokio::test]
    async fn obtain_no_identifiers() {
        let account = account().await;
        let error = account.certificate().obtain().await.unwrap_err();
        assert!(matches!(error, Error::MissingIdentifiers));
    }

    #[tokio::test]
    async fn obtain_single_domain() {
        let account = account().await;
        let _certificate = account
            .certificate()
            .add_domain("example.com")
            .obtain()
            .await
            .unwrap();
    }
}
