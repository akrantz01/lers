use crate::{
    api::Api,
    certificate::CertificateBuilder,
    error::Result,
    responses::{self, AccountStatus, RevocationReason},
    Certificate, Error,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private},
};

pub struct NoPrivateKey;
pub struct WithPrivateKey(PKey<Private>);

/// Used to configure a the creation/lookup of an account
pub struct AccountBuilder<T> {
    api: Api,

    contacts: Option<Vec<String>>,
    terms_of_service_agreed: bool,
    private_key: T,
}

impl<T> AccountBuilder<T> {
    pub(crate) fn new(api: Api) -> AccountBuilder<NoPrivateKey> {
        AccountBuilder {
            api,
            contacts: None,
            terms_of_service_agreed: false,
            private_key: NoPrivateKey,
        }
    }

    /// Specify whether the ToS for the CA are agreed to
    pub fn terms_of_service_agreed(mut self, agreed: bool) -> Self {
        self.terms_of_service_agreed = agreed;
        self
    }

    /// Set the account contacts
    pub fn contacts(mut self, contacts: Vec<String>) -> Self {
        self.contacts = Some(contacts);
        self
    }
}

impl AccountBuilder<NoPrivateKey> {
    /// Set the account's private key
    pub fn private_key(self, key: PKey<Private>) -> AccountBuilder<WithPrivateKey> {
        AccountBuilder {
            api: self.api,
            contacts: self.contacts,
            terms_of_service_agreed: self.terms_of_service_agreed,
            private_key: WithPrivateKey(key),
        }
    }

    /// Create the account if it doesn't already exists, returning the existing account if it does.
    /// Will generate a private key for the account.
    pub async fn create_if_not_exists(self) -> Result<Account> {
        let key = {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec = EcKey::generate(&group)?;
            PKey::from_ec_key(ec)?
        };

        let (id, account) = self
            .api
            .new_account(self.contacts, self.terms_of_service_agreed, false, &key)
            .await?;

        into_account(self.api, key, id, account)
    }
}

impl AccountBuilder<WithPrivateKey> {
    /// Lookup the account by private key, fails if it doesn't exist or a private key was
    /// not specified.
    pub async fn lookup(self) -> Result<Account> {
        let (id, account) = self
            .api
            .new_account(
                self.contacts,
                self.terms_of_service_agreed,
                true,
                &self.private_key.0,
            )
            .await?;

        into_account(self.api, self.private_key.0, id, account)
    }

    /// Create the account if it doesn't already exists, returning the existing account if it does.
    pub async fn create_if_not_exists(self) -> Result<Account> {
        let (id, account) = self
            .api
            .new_account(
                self.contacts,
                self.terms_of_service_agreed,
                false,
                &self.private_key.0,
            )
            .await?;

        into_account(self.api, self.private_key.0, id, account)
    }
}

/// Finalize the creation of the account
fn into_account(
    api: Api,
    private_key: PKey<Private>,
    id: String,
    account: responses::Account,
) -> Result<Account> {
    if account.status != AccountStatus::Valid {
        return Err(Error::InvalidAccount(account.status));
    }

    Ok(Account {
        api,
        private_key,
        id,
    })
}

/// An ACME account. This is used to identify a subscriber to an ACME server.
#[derive(Debug)]
pub struct Account {
    pub(crate) api: Api,
    pub(crate) private_key: PKey<Private>,
    pub(crate) id: String,
}

impl Account {
    /// Get the private key for the account
    pub fn private_key(&self) -> &PKey<Private> {
        &self.private_key
    }

    /// Access the builder to issue a new certificate.
    pub fn certificate(&self) -> CertificateBuilder {
        CertificateBuilder::new(self)
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(&self, certificate: &Certificate) -> Result<()> {
        let der = BASE64.encode(certificate.to_der()?);
        self.api
            .revoke_certificate(der, None, &self.private_key, Some(&self.id))
            .await
    }

    /// Revoke a certificate with a reason.
    pub async fn revoke_certificate_with_reason(
        &self,
        certificate: &Certificate,
        reason: RevocationReason,
    ) -> Result<()> {
        let der = BASE64.encode(certificate.to_der()?);
        self.api
            .revoke_certificate(der, Some(reason), &self.private_key, Some(&self.id))
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{responses::ErrorType, test::directory, Error};
    use once_cell::sync::Lazy;
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::{PKey, Private},
    };
    use parking_lot::Mutex;
    use std::{collections::HashSet, fs};

    static ACCOUNT_IDS: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| {
        let raw = fs::read("testdata/account-ids.json").unwrap();
        let ids = serde_json::from_slice(&raw).unwrap();
        Mutex::new(ids)
    });

    fn private_key(account: u8) -> PKey<Private> {
        let pem = fs::read(format!("testdata/accounts/{account}.pem")).unwrap();
        PKey::private_key_from_pem(&pem).unwrap()
    }

    #[tokio::test]
    async fn lookup_when_exists() {
        let directory = directory().await;
        let account = directory
            .account()
            .contacts(vec!["mailto:exists@lookup.test".into()])
            .private_key(private_key(1))
            .lookup()
            .await
            .unwrap();

        let mut ids = ACCOUNT_IDS.lock();
        assert!(!ids.insert(account.id));
    }

    #[tokio::test]
    async fn lookup_when_does_not_exists() {
        let directory = directory().await;

        let key = {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec = EcKey::generate(&group).unwrap();
            PKey::from_ec_key(ec).unwrap()
        };
        let result = directory
            .account()
            .contacts(vec!["mailto:does-not-exist@lookup.test".into()])
            .private_key(key)
            .lookup()
            .await;

        let Error::Server(error) = result.unwrap_err() else { panic!("must be server error") };
        assert_eq!(error.type_, ErrorType::AccountDoesNotExist);
        assert_eq!(error.title, None);
        assert_eq!(
            error.detail,
            Some("unable to find existing account for only-return-existing request".into())
        );
        assert_eq!(error.status, Some(400));
        assert!(error.subproblems.is_none());
    }

    #[tokio::test]
    async fn create_if_not_exists_when_does_not_exist() {
        let directory = directory().await;
        let account = directory
            .account()
            .terms_of_service_agreed(true)
            .contacts(vec!["mailto:does-not-exist@create.test".into()])
            .create_if_not_exists()
            .await
            .unwrap();

        let mut ids = ACCOUNT_IDS.lock();
        assert!(ids.insert(account.id));
    }

    #[tokio::test]
    async fn create_if_not_exists_when_exists() {
        let directory = directory().await;
        let account = directory
            .account()
            .terms_of_service_agreed(true)
            .contacts(vec!["mailto:exists@create.test".into()])
            .private_key(private_key(2))
            .create_if_not_exists()
            .await
            .unwrap();

        let mut ids = ACCOUNT_IDS.lock();
        assert!(!ids.insert(account.id));
    }
}
