use crate::{
    error::{Error, Result},
    solver::{boxed_err, Solver},
};
use parking_lot::Mutex;
use reqwest::{
    header::{self, HeaderMap, HeaderValue, IntoHeaderName},
    Client, StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    fmt::{Display, Formatter},
    sync::Arc,
    time::Duration,
};
use tracing::{instrument, Level};

/// Errors that could be generated by the [`CloudflareDns01Solver`]
#[derive(Debug)]
pub enum CloudflareError {
    /// Could not find one of the required environment variables
    /// (see [`CloudflareDns01Solver::from_env`])
    MissingEnvironmentVariables,
    /// Failed to find the zone ID for the provided zone
    UnknownZone(String),
}

impl std::error::Error for CloudflareError {}
impl Display for CloudflareError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEnvironmentVariables => write!(
                f,
                "could not find one of the required environment variables"
            ),
            Self::UnknownZone(zone) => write!(f, "unknown zone {zone:?}"),
        }
    }
}

/// Uses the Cloudflare API to solve DNS-01 challenges.
#[derive(Clone, Debug)]
pub struct CloudflareDns01Solver {
    client: Client,
    // mapping from token to a zone id and record id pair
    tokens_to_records: Arc<Mutex<HashMap<String, (String, String)>>>,
}

impl CloudflareDns01Solver {
    /// Creates a new [`CloudflareDns01Builder`] by pulling credentials from the environment.
    ///
    /// Credentials are pulled from the following environment variables, listed in order of
    /// precedence if multiple are defined:
    ///   1. `CLOUDFLARE_API_TOKEN`
    ///   2. `CLOUDFLARE_EMAIL` and `CLOUDFLARE_API_KEY`
    pub fn from_env() -> Result<CloudflareDns01Builder> {
        if let Ok(token) = env::var("CLOUDFLARE_API_TOKEN") {
            Ok(Self::new_with_token(token))
        } else if let (Ok(email), Ok(key)) =
            (env::var("CLOUDFLARE_EMAIL"), env::var("CLOUDFLARE_API_KEY"))
        {
            Ok(Self::new_with_auth_key(email, key))
        } else {
            Err(Error::InvalidSolverConfiguration {
                name: "cloudflare dns-01",
                error: Box::new(CloudflareError::MissingEnvironmentVariables),
            })
        }
    }

    /// Creates a new [`CloudflareDns01Builder`] using an authentication token. The token must have
    /// `Zone:Read` and `DNS:Edit` permissions.
    pub fn new_with_token<S: AsRef<str>>(token: S) -> CloudflareDns01Builder {
        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {}", token.as_ref())).unwrap(),
        );

        CloudflareDns01Builder { headers }
    }

    /// Creates a new [`CloudflareDns01Builder`] using the Cloudflare global credentials.
    ///
    /// This should be avoided if at all possible, use [`CloudflareDns01Solver::new_with_token`]
    /// instead.
    pub fn new_with_auth_key<E, K>(email: E, key: K) -> CloudflareDns01Builder
    where
        E: AsRef<str>,
        K: AsRef<str>,
    {
        let mut headers = HeaderMap::with_capacity(2);
        headers.insert(
            "X-Auth-Email",
            HeaderValue::from_str(email.as_ref()).unwrap(),
        );
        headers.insert("X-Auth-Key", HeaderValue::from_str(key.as_ref()).unwrap());

        CloudflareDns01Builder { headers }
    }

    /// Find a zone's ID by its name
    #[instrument(
        level = Level::DEBUG,
        name = "CloudflareDns01Solver::zone_id_by_name",
        err,
        skip(self),
    )]
    async fn zone_id_by_name(&self, name: &str) -> reqwest::Result<Option<String>> {
        let response: Response<Vec<Zone>> = self
            .client
            .get("https://api.cloudflare.com/client/v4/zones")
            .query(&ListZoneOptions { name })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        debug_assert!(response.success);

        Ok(response.result.into_iter().next().map(|r| r.id))
    }

    /// Set the TXT record with the provided content, returns the record's ID
    #[instrument(
        level = Level::DEBUG,
        name = "CloudflareDns01Solver::set_txt_record",
        err,
        skip(self, content),
    )]
    async fn set_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
    ) -> reqwest::Result<String> {
        let response: Response<Record> = self
            .client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .json(&CreateRecordBody {
                type_: "TXT",
                ttl: 1,
                content,
                name,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.result.id)
    }

    /// Remove a TXT record by ID
    #[instrument(
        level = Level::DEBUG,
        name = "CloudflareDns01Solver::remove_record",
        err,
        skip(self),
    )]
    async fn remove_record(&self, zone_id: &str, record_id: &str) -> reqwest::Result<()> {
        let response = self
            .client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            ))
            .send()
            .await?;

        if response.status() != StatusCode::NOT_FOUND {
            response.error_for_status()?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Solver for CloudflareDns01Solver {
    #[instrument(
        level = Level::INFO,
        name = "Solver::present",
        err,
        skip_all,
        fields(token, domain, solver = std::any::type_name::<Self>()),
    )]
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let zone = super::find_zone_by_fqdn(&domain).await.map_err(boxed_err)?;
        let zone_id = self
            .zone_id_by_name(&zone)
            .await
            .map_err(boxed_err)?
            .ok_or_else(|| boxed_err(CloudflareError::UnknownZone(zone)))?;

        let id = self
            .set_txt_record(
                &zone_id,
                &format!("_acme-challenge.{domain}"),
                &key_authorization,
            )
            .await
            .map_err(boxed_err)?;

        let mut tokens_to_records = self.tokens_to_records.lock();
        tokens_to_records.insert(token, (zone_id, id));

        Ok(())
    }

    #[instrument(
        level = Level::INFO,
        name = "Solver::cleanup",
        err,
        skip_all,
        fields(token, solver = std::any::type_name::<Self>()),
    )]
    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let (zone_id, record_id) = match {
            let mut tokens_to_records = self.tokens_to_records.lock();
            tokens_to_records.remove(token)
        } {
            Some(v) => v,
            // already cleaned up, nothing to do
            None => return Ok(()),
        };

        self.remove_record(&zone_id, &record_id)
            .await
            .map_err(boxed_err)?;

        Ok(())
    }

    fn attempts(&self) -> usize {
        60
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(2)
    }
}

/// Used to configured a [`CloudflareDns01Solver`]
#[derive(Debug)]
pub struct CloudflareDns01Builder {
    headers: HeaderMap,
}

impl CloudflareDns01Builder {
    /// Adds a default header to the client
    pub fn add_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: IntoHeaderName,
        V: Into<HeaderValue>,
    {
        self.headers.insert(key, value.into());
        self
    }

    /// Build the DNS-01 solver
    pub fn build(self) -> Result<CloudflareDns01Solver> {
        let client = Client::builder()
            .user_agent(crate::USER_AGENT)
            .default_headers(self.headers)
            .build()?;

        Ok(CloudflareDns01Solver {
            client,
            tokens_to_records: Arc::default(),
        })
    }
}

#[derive(Debug, Serialize)]
struct ListZoneOptions<'n> {
    name: &'n str,
}

#[derive(Debug, Serialize)]
struct CreateRecordBody<'n> {
    content: &'n str,
    name: &'n str,
    #[serde(rename = "type")]
    type_: &'static str,
    ttl: usize,
}

#[derive(Debug, Deserialize)]
struct Response<T> {
    success: bool,
    result: T,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::CloudflareDns01Solver;
    use crate::Solver;
    use std::{env, time::Duration};
    use test_log::test;
    use tokio::time;

    const ZONE_NAME_ENV: &str = "DNS01_CF_ZONE";
    const ZONE_ID_ENV: &str = "DNS01_CF_ZONE_ID";

    fn solver() -> CloudflareDns01Solver {
        CloudflareDns01Solver::from_env().unwrap().build().unwrap()
    }

    #[test(tokio::test)]
    async fn zone_id_by_name_valid() -> reqwest::Result<()> {
        let test_zone = env::var(ZONE_NAME_ENV).unwrap();
        let expected_id = env::var(ZONE_ID_ENV).ok();

        let solver = solver();
        let id = solver.zone_id_by_name(&test_zone).await?;
        assert_eq!(id, expected_id);

        Ok(())
    }

    #[test(tokio::test)]
    async fn zone_id_by_name_invalid() -> reqwest::Result<()> {
        let solver = solver();
        let id = solver.zone_id_by_name("lego.zz").await?;
        assert_eq!(id, None);

        Ok(())
    }

    #[test(tokio::test)]
    async fn txt_record() -> reqwest::Result<()> {
        let zone = env::var(ZONE_NAME_ENV).unwrap();
        let zone_id = env::var(ZONE_ID_ENV).unwrap();

        let solver = solver();

        let id = solver
            .set_txt_record(&zone_id, &format!("cf.lers.{zone}"), "lers-testing")
            .await?;

        time::sleep(Duration::from_secs(1)).await;

        solver.remove_record(&zone_id, &id).await?;

        Ok(())
    }

    #[test(tokio::test)]
    async fn remove_non_existent_txt_record() {
        let zone_id = env::var(ZONE_ID_ENV).unwrap();

        let solver = solver();
        let result = solver
            .remove_record(&zone_id, "2ca364bf488e500ab98aa943f2d8973a")
            .await;
        assert!(result.is_ok());
    }

    #[test(tokio::test)]
    async fn present_and_cleanup() {
        let zone = env::var(ZONE_NAME_ENV).unwrap();
        let solver = solver();

        solver
            .present(
                format!("cf.lers.{zone}"),
                String::from("present-and-cleanup-test"),
                String::from("present-and-cleanup-challenge"),
            )
            .await
            .unwrap();

        {
            let mapping = solver.tokens_to_records.lock();
            assert_eq!(mapping.len(), 1);
        }

        time::sleep(Duration::from_secs(1)).await;

        solver.cleanup("present-and-cleanup-test").await.unwrap();

        {
            let mapping = solver.tokens_to_records.lock();
            assert_eq!(mapping.len(), 0);
        }
    }

    #[test(tokio::test)]
    async fn cleanup_empty() {
        let solver = solver();
        solver.cleanup("this-does-not-exist").await.unwrap();
    }

    #[test(tokio::test)]
    async fn cleanup_out_of_sync() {
        let solver = solver();
        {
            let mut mapping = solver.tokens_to_records.lock();
            mapping.insert(
                String::from("out-of-sync-test"),
                (
                    env::var(ZONE_ID_ENV).unwrap(),
                    String::from("2ca364bf488e500ab98aa943f2d8973a"),
                ),
            );
        }

        solver.cleanup("out-of-sync-test").await.unwrap();
    }
}
