use crate::{Account, Directory, Solver};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use reqwest::Client;
use serde::Serialize;
use std::{collections::HashMap, error::Error, sync::Arc};

/// The pebble test server URL
pub const TEST_URL: &str = "https://10.30.50.2:14000/dir";

/// Create a client allowing self-signed certificates
pub fn client() -> Client {
    Client::builder()
        .danger_accept_invalid_hostnames(true)
        .danger_accept_invalid_certs(true)
        .user_agent("lers/testing")
        .build()
        .unwrap()
}

/// Create a new directory for the local Pebble instance
pub async fn directory() -> Directory {
    Directory::builder(TEST_URL)
        .client(client())
        .build()
        .await
        .unwrap()
}

pub async fn directory_with_http01_solver() -> Directory {
    Directory::builder(TEST_URL)
        .client(client())
        .set_http01_solver(Box::new(EXTERNAL_HTTP01_SOLVER.clone()))
        .build()
        .await
        .unwrap()
}

pub async fn directory_with_dns01_solver() -> Directory {
    Directory::builder(TEST_URL)
        .client(client())
        .set_dns01_solver(Box::new(EXTERNAL_DNS01_SOLVER.clone()))
        .build()
        .await
        .unwrap()
}

/// Create a new account on the server
pub async fn account(directory: Directory) -> Account {
    directory
        .account()
        .contacts(vec!["mailto:test@user.com".into()])
        .terms_of_service_agreed(true)
        .create_if_not_exists()
        .await
        .unwrap()
}

static EXTERNAL_HTTP01_SOLVER: Lazy<ExternalHttp01Solver> = Lazy::new(|| ExternalHttp01Solver {
    domains: Arc::default(),
    client: Client::new(),
});

static EXTERNAL_DNS01_SOLVER: Lazy<ExternalDns01Solver> = Lazy::new(|| ExternalDns01Solver {
    domains: Arc::default(),
    client: Client::new(),
});

const ADD_A_RECORD_URL: &str = "http://10.30.50.3:8055/add-a";
const CLEAR_A_RECORD_URL: &str = "http://10.30.50.3:8055/clear-a";
const ADD_HTTP_01_URL: &str = "http://10.30.50.3:8055/add-http01";
const DELETE_HTTP_01_URL: &str = "http://10.30.50.3:8055/del-http-01";
const ADD_DNS_01_URL: &str = "http://10.30.50.3:8055/set-txt";
const CLEAR_DNS_01_URL: &str = "http://10.30.50.3:8055/clear-txt";

/// The external HTTP-01 solver delegates responsibility to the
/// [Pebble Challenge Test Server](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv).
#[derive(Debug, Clone)]
struct ExternalHttp01Solver {
    // Maps from tokens to domains
    domains: Arc<Mutex<HashMap<String, String>>>,
    client: Client,
}

#[async_trait::async_trait]
impl Solver for ExternalHttp01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn Error + Send + 'static>> {
        request(
            &self.client,
            ADD_A_RECORD_URL,
            DnsRequest {
                host: &domain,
                addresses: Some(&["10.30.50.3"]),
            },
            true,
        )
        .await?;

        request(
            &self.client,
            ADD_HTTP_01_URL,
            Http01Request {
                token: &token,
                content: Some(&key_authorization),
            },
            true,
        )
        .await?;

        {
            let mut domains = self.domains.lock();
            domains.insert(token, domain);
        }

        Ok(())
    }

    async fn cleanup(&self, token: &str) -> Result<(), Box<dyn Error + Send + 'static>> {
        let domain = {
            let mut domains = self.domains.lock();
            domains.remove(token)
        };
        let Some(domain) = domain else { panic!("domain for token {token:?} does not exist") };

        request(
            &self.client,
            CLEAR_A_RECORD_URL,
            DnsRequest {
                host: &domain,
                addresses: None,
            },
            false,
        )
        .await?;

        request(
            &self.client,
            DELETE_HTTP_01_URL,
            Http01Request {
                token,
                content: None,
            },
            false,
        )
        .await?;

        Ok(())
    }
}

/// The external DNS-01 solver delegates responsibility to the
/// [Pebble Challenge Test Server](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv).
#[derive(Debug, Clone)]
struct ExternalDns01Solver {
    // Maps from tokens to domains
    domains: Arc<Mutex<HashMap<String, String>>>,
    client: Client,
}

#[async_trait::async_trait]
impl Solver for ExternalDns01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn Error + Send + 'static>> {
        request(
            &self.client,
            ADD_DNS_01_URL,
            Dns01Request {
                host: format!("_acme-challenge.{domain}."),
                value: Some(&key_authorization),
            },
            true,
        )
        .await?;

        {
            let mut domains = self.domains.lock();
            domains.insert(token, domain);
        }

        Ok(())
    }

    async fn cleanup(&self, token: &str) -> Result<(), Box<dyn Error + Send + 'static>> {
        let domain = {
            let mut domains = self.domains.lock();
            domains.remove(token)
        };
        let Some(domain) = domain else { panic!("domain for token {token:?} does not exist") };

        request(
            &self.client,
            CLEAR_DNS_01_URL,
            Dns01Request {
                host: format!("_acme-challenge.{domain}."),
                value: None,
            },
            false,
        )
        .await?;

        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct DnsRequest<'s> {
    host: &'s str,
    #[serde(skip_serializing_if = "Option::is_none")]
    addresses: Option<&'s [&'s str]>,
}

#[derive(Debug, Serialize)]
struct Http01Request<'s> {
    token: &'s str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<&'s str>,
}

#[derive(Debug, Serialize)]
struct Dns01Request<'s> {
    host: String,
    value: Option<&'s str>,
}

async fn request<S>(
    client: &Client,
    url: &str,
    body: S,
    raise_for_status: bool,
) -> Result<(), Box<dyn Error + Send + 'static>>
where
    S: Serialize,
{
    let response = client.post(url).json(&body).send().await.map_err(boxed)?;

    if raise_for_status {
        response.error_for_status().map_err(boxed)?;
    }

    Ok(())
}

fn boxed<E>(err: E) -> Box<dyn Error + Send + 'static>
where
    E: Error + Send + 'static,
{
    Box::new(err)
}
