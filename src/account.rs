use crate::{
    api::Api,
    error::Result,
    responses::{self, AccountStatus},
    Error,
};
use openssl::pkey::{PKey, Private};

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
        let key = PKey::ec_gen("prime256v1").unwrap();
        let (id, account) = self
            .api
            .new_account(self.contacts, self.terms_of_service_agreed, false, &key)
            .await
            .unwrap();

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
            .await
            .unwrap();

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
            .await
            .unwrap();

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

#[derive(Debug)]
pub struct Account {
    api: Api,
    private_key: PKey<Private>,
    id: String,
}

#[cfg(test)]
mod tests {
    use crate::{Directory, TEST_URL};
    use openssl::pkey::{PKey, Private};
    use std::fs;

    fn private_key() -> PKey<Private> {
        let pem = fs::read("testdata/rsa_2048.pem").unwrap();
        PKey::private_key_from_pem(&pem).unwrap()
    }

    async fn directory() -> Directory {
        Directory::builder(TEST_URL).build().await.unwrap()
    }

    #[tokio::test]
    async fn lookup_when_exists() {
        let directory = directory().await;
        let _account = directory
            .account()
            .contacts(vec!["mailto:test@user.com".into()])
            .private_key(private_key())
            .lookup()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lookup_when_does_not_exists() {
        let directory = directory().await;
        let _account = directory
            .account()
            .contacts(vec!["mailto:test@user.com".into()])
            .private_key(private_key())
            .lookup()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_if_not_exists_when_does_not_exist() {
        let directory = directory().await;
        let _account = directory
            .account()
            .terms_of_service_agreed(true)
            .contacts(vec!["mailto:test@user.com".into()])
            .create_if_not_exists()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_if_not_exists_when_exists() {
        let directory = directory().await;
        let _account = directory
            .account()
            .terms_of_service_agreed(true)
            .contacts(vec!["mailto:test@user.com".into()])
            .private_key(private_key())
            .create_if_not_exists()
            .await
            .unwrap();
    }
}
