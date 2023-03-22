use crate::{
    account::Account,
    error::{Error, Result},
    order::Order,
    responses::Identifier,
};
use chrono::{DateTime, Utc};
use futures::future;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// Used to configure the ordering of a certificate
pub struct CertificateBuilder<'a> {
    account: &'a Account,
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    private_key: Option<PKey<Private>>,
}

impl<'a> CertificateBuilder<'a> {
    pub(crate) fn new(account: &'a Account) -> CertificateBuilder<'a> {
        CertificateBuilder {
            account,
            // We know there'll be at least 1 identifier in the order
            identifiers: Vec::with_capacity(1),
            not_before: None,
            not_after: None,
            private_key: None,
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

    /// Set the private key for certificate.
    pub fn private_key(mut self, private_key: PKey<Private>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Obtain the certificate
    pub async fn obtain(self) -> Result<Certificate> {
        if self.identifiers.is_empty() {
            return Err(Error::MissingIdentifiers);
        }

        let mut order = Order::create(
            self.account,
            self.identifiers,
            self.not_before,
            self.not_after,
        )
        .await?;

        let authorizations = order.authorizations().await?;
        future::try_join_all(authorizations.iter().map(|a| a.solve())).await?;

        order.wait_ready().await?;

        let private_key = match self.private_key {
            Some(key) => key,
            None => PKey::ec_gen("prime256v1")?,
        };
        order.finalize(&private_key).await?;

        order.wait_done().await?;

        let chain = order.download().await?;
        Ok(Certificate { chain })
    }
}

/// An issued certificate by the ACME server
#[derive(Debug)]
pub struct Certificate {
    chain: Vec<X509>,
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
