use crate::{
    account::Account,
    error::{Error, Result},
    order::Order,
    responses::Identifier,
};
use chrono::{DateTime, Utc};
use futures::future;
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

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
        Ok(Certificate { chain, private_key })
    }
}

/// An issued certificate by the ACME server
#[derive(Debug)]
pub struct Certificate {
    chain: Vec<X509>,
    private_key: PKey<Private>,
}

impl Certificate {
    /// Export the private key in PEM PKCS#8 format
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.private_key_to_pem_pkcs8()?)
    }

    /// Export the private key in DER format
    pub fn private_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.private_key_to_der()?)
    }

    /// Export the issued certificate in PEM format
    ///
    /// **NOTE**: this does NOT export the full certificate chain, use
    /// [`Certificate::fullchain_to_pem`] for that.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.chain.first().unwrap().to_pem()?)
    }

    /// Export the full certificate chain in PEM format
    pub fn fullchain_to_pem(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for certificate in &self.chain {
            result.extend(certificate.to_pem()?);
        }
        Ok(result)
    }

    /// Export the issued certificate in DER format
    ///
    /// **NOTE**: this does NOT export the full certificate chain, use
    /// [`Certificate::fullchain_to_der`] for that.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.chain.first().unwrap().to_pem()?)
    }

    /// Export the full certificate chain in DER format
    pub fn fullchain_to_der(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for certificate in &self.chain {
            result.extend(certificate.to_der()?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        responses::ErrorType,
        test::{account, directory, directory_with_dns01_solver, directory_with_http01_solver},
        Error,
    };
    use openssl::{
        pkey::{PKey, Private},
        x509::X509,
    };

    macro_rules! check_subjects {
        ($cert:expr => $($name:expr),+ $(,)?) => {
            {
                let expected = {
                    let mut set = std::collections::HashSet::new();
                    $( set.insert($name.to_owned()); )+
                    set
                };
                let names = $cert
                    .subject_alt_names()
                    .unwrap()
                    .iter()
                    .map(|n| n.dnsname().unwrap().to_owned())
                    .collect::<std::collections::HashSet<_>>();
                assert_eq!(names, expected);
            }
        };
    }

    fn check_key(cert: &X509, key: &PKey<Private>) {
        let cert_key = cert.public_key().unwrap();
        assert!(key.public_eq(&cert_key));
    }

    /// Check that the issuer for a certificate matches the provided issuer
    fn check_issuer(cert: &X509, issuer: &X509) {
        assert_eq!(
            cert.issuer_name()
                .entries()
                .next()
                .unwrap()
                .data()
                .as_utf8()
                .unwrap()
                .to_string(),
            issuer
                .subject_name()
                .entries()
                .next()
                .unwrap()
                .data()
                .as_utf8()
                .unwrap()
                .to_string()
        );
    }

    #[tokio::test]
    async fn obtain_no_identifiers() {
        let directory = directory().await;
        let account = account(directory).await;

        let error = account.certificate().obtain().await.unwrap_err();
        assert!(matches!(error, Error::MissingIdentifiers));
    }

    #[tokio::test]
    async fn obtain_missing_solvers() {
        let directory = directory().await;
        let account = account(directory).await;

        let error = account
            .certificate()
            .add_domain("domain.com")
            .obtain()
            .await
            .unwrap_err();
        assert!(matches!(error, Error::MissingSolver));
    }

    #[tokio::test]
    async fn obtain_blocked_domain() {
        let directory = directory().await;
        let account = account(directory).await;

        let error = account
            .certificate()
            .add_domain("blocked-domain.example")
            .obtain()
            .await
            .unwrap_err();

        let Error::Server(error) = error else { panic!("expected Error::Server") };
        assert_eq!(error.type_, ErrorType::RejectedIdentifier);
        assert_eq!(error.status.unwrap(), 400);
        assert!(error.detail.unwrap().contains("blocked-domain.example"));
    }

    #[tokio::test]
    async fn obtain_single_domain() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("single.com")
            .obtain()
            .await
            .unwrap();

        assert_eq!(certificate.chain.len(), 2);
        let issued = certificate.chain.first().unwrap();
        let issuer = certificate.chain.last().unwrap();

        check_subjects!(issued => "single.com");
        check_issuer(issued, issuer);
        check_key(issued, &certificate.private_key);
    }

    #[tokio::test]
    async fn obtain_multiple_domains() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("one.multiple.com")
            .add_domain("two.multiple.com")
            .add_domain("three.multiple.com")
            .obtain()
            .await
            .unwrap();

        assert_eq!(certificate.chain.len(), 2);
        let issued = certificate.chain.first().unwrap();
        let issuer = certificate.chain.last().unwrap();

        check_subjects!(issued => "one.multiple.com", "two.multiple.com", "three.multiple.com");
        check_issuer(issued, issuer);
        check_key(issued, &certificate.private_key);
    }

    #[tokio::test]
    async fn obtain_wildcard() {
        let directory = directory_with_dns01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("*.wildcard.com")
            .obtain()
            .await
            .unwrap();

        assert_eq!(certificate.chain.len(), 2);
        let issued = certificate.chain.first().unwrap();
        let issuer = certificate.chain.last().unwrap();

        check_subjects!(issued => "*.wildcard.com");
        check_issuer(issued, issuer);
        check_key(issued, &certificate.private_key);
    }

    #[tokio::test]
    async fn obtain_wildcard_without_dns01() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let error = account
            .certificate()
            .add_domain("*.failure.wildcard.com")
            .obtain()
            .await
            .unwrap_err();
        assert!(matches!(error, Error::MissingSolver));
    }
}
