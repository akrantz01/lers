use crate::{
    account::Account,
    error::{Error, Result},
    order::Order,
    responses::{Identifier, RevocationReason},
    Directory,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use chrono::{DateTime, Utc};
use futures::future;
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::X509,
};
use tracing::{info, instrument, Level, Span};

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
    #[instrument(
        level = Level::INFO,
        name = "CertificateBuilder::obtain",
        err,
        skip_all,
        fields(
            order.id,
            self.account.id,
            ?self.identifiers,
            ?self.not_before,
            ?self.not_after,
        ),
    )]
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
        Span::current().record("order.id", order.id());

        info!("solving order authorization(s)");
        let authorizations = order.authorizations().await?;
        future::try_join_all(authorizations.iter().map(|a| a.solve())).await?;

        info!("waiting for order to be ready...");
        order.wait_ready().await?;

        let private_key = match self.private_key {
            Some(key) => key,
            None => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                let ec = EcKey::generate(&group)?;
                PKey::from_ec_key(ec)?
            }
        };

        info!("finalizing order...");
        order.finalize(&private_key).await?;

        order.wait_done().await?;

        info!("order completed, downloading certificate...");
        let chain = order.download().await?;

        Ok(Certificate { chain, private_key })
    }
}

/// An issued certificate by the ACME server
#[derive(Debug)]
pub struct Certificate {
    chain: Vec<X509>,
    pub(crate) private_key: PKey<Private>,
}

impl Certificate {
    /// Load a certificate from an exported chain and private key
    pub fn from_chain_and_private_key(chain: Format<'_>, private_key: Format<'_>) -> Result<Self> {
        Ok(Certificate {
            chain: chain.try_into()?,
            private_key: private_key.try_into()?,
        })
    }

    /// Create a certificate from an already parsed chain and private key
    pub fn from_raw_chain_and_private_key(chain: Vec<X509>, private_key: PKey<Private>) -> Self {
        Certificate { chain, private_key }
    }

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
        Ok(self.chain.first().unwrap().to_der()?)
    }

    /// Export the full certificate chain in DER format
    pub fn fullchain_to_der(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        for certificate in &self.chain {
            result.extend(certificate.to_der()?);
        }
        Ok(result)
    }

    /// Get a reference to the underlying [`openssl::x509::X509`] instance for the certificate.
    pub fn x509(&self) -> &X509 {
        self.chain.first().unwrap()
    }

    /// Get a reference to the full [`openssl::x509::X509`] chain for the certificate.
    pub fn x509_chain(&self) -> &[X509] {
        self.chain.as_slice()
    }

    /// Calculate the SHA256 digest of the leaf certificate in hex format
    pub fn digest(&self) -> String {
        let digest = self
            .x509()
            .digest(MessageDigest::sha256())
            .expect("digest should always succeed");
        hex::encode(digest)
    }

    /// Revoke this certificate.
    #[instrument(
        level = Level::INFO,
        name = "Certificate::revoke",
        err,
        skip_all,
        fields(self = %self.digest())
    )]
    pub async fn revoke(&self, directory: &Directory) -> Result<()> {
        let der = BASE64.encode(self.to_der()?);
        directory
            .api()
            .revoke_certificate(der, None, &self.private_key, None)
            .await
    }

    /// Revoke this certificate with a reason.
    #[instrument(
        level = Level::INFO,
        name = "Certificate::revoke_with_reason",
        err,
        skip_all,
        fields(self = %self.digest())
    )]
    pub async fn revoke_with_reason(
        &self,
        directory: &Directory,
        reason: RevocationReason,
    ) -> Result<()> {
        let der = BASE64.encode(self.to_der()?);
        directory
            .api()
            .revoke_certificate(der, Some(reason), &self.private_key, None)
            .await
    }
}

/// The possible formats a certificate/private key can be loaded from.
///
/// When loading a certificate, full certificate chains can only be loaded from [`Format::Pem`].
#[derive(Debug)]
pub enum Format<'d> {
    /// Bytes of a PEM encoded x509 certificate or private key
    Pem(&'d [u8]),
    /// Bytes of a DER encoded x509 certificate or private key
    Der(&'d [u8]),
}

impl<'d> TryInto<Vec<X509>> for Format<'d> {
    type Error = openssl::error::ErrorStack;

    fn try_into(self) -> std::result::Result<Vec<X509>, Self::Error> {
        match self {
            Self::Pem(pem) => X509::stack_from_pem(pem),
            Self::Der(der) => Ok(vec![X509::from_der(der)?]),
        }
    }
}

impl<'d> TryInto<PKey<Private>> for Format<'d> {
    type Error = openssl::error::ErrorStack;

    fn try_into(self) -> std::result::Result<PKey<Private>, Self::Error> {
        match self {
            Self::Pem(pem) => PKey::private_key_from_pem(pem),
            Self::Der(der) => PKey::private_key_from_der(der),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        responses::{ErrorType, RevocationReason},
        test::{account, directory, directory_with_dns01_solver, directory_with_http01_solver},
        Error,
    };
    use openssl::{
        pkey::{PKey, Private},
        x509::X509,
    };
    use test_log::test;

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

    #[test(tokio::test)]
    async fn obtain_no_identifiers() {
        let directory = directory().await;
        let account = account(directory).await;

        let error = account.certificate().obtain().await.unwrap_err();
        assert!(matches!(error, Error::MissingIdentifiers));
    }

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test(tokio::test)]
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

    #[test(tokio::test)]
    async fn obtain_and_revoke_from_account() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("revoke.com")
            .obtain()
            .await
            .unwrap();

        account
            .revoke_certificate(certificate.x509())
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_revoke_with_reason_from_account() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("reason.revoke.com")
            .obtain()
            .await
            .unwrap();

        account
            .revoke_certificate_with_reason(certificate.x509(), RevocationReason::Superseded)
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_revoke_from_certificate() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory.clone()).await;

        let certificate = account
            .certificate()
            .add_domain("reason.revoke.com")
            .obtain()
            .await
            .unwrap();

        certificate.revoke(&directory).await.unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_revoke_with_reason_from_certificate() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory.clone()).await;

        let certificate = account
            .certificate()
            .add_domain("reason.revoke.com")
            .obtain()
            .await
            .unwrap();

        certificate
            .revoke_with_reason(&directory, RevocationReason::Superseded)
            .await
            .unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_renew_single_domain() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("renew.me")
            .obtain()
            .await
            .unwrap();

        account.renew_certificate(certificate).await.unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_renew_multiple_domains() {
        let directory = directory_with_http01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("one.renew.me")
            .add_domain("two.renew.me")
            .add_domain("three.renew.me")
            .obtain()
            .await
            .unwrap();

        account.renew_certificate(certificate).await.unwrap();
    }

    #[test(tokio::test)]
    async fn obtain_and_renew_wildcard_domain() {
        let directory = directory_with_dns01_solver().await;
        let account = account(directory).await;

        let certificate = account
            .certificate()
            .add_domain("*.renew.me")
            .obtain()
            .await
            .unwrap();

        account.renew_certificate(certificate).await.unwrap();
    }
}
