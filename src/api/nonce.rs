use crate::error::{Error, Result};
use reqwest::{Client, Response};
use std::{collections::VecDeque, sync::Mutex};

#[derive(Debug)]
pub(crate) struct Pool {
    pool: Mutex<VecDeque<String>>,
    max: usize,
}

impl Pool {
    pub fn new(max: usize) -> Self {
        Pool {
            pool: Mutex::default(),
            max,
        }
    }

    /// Get a nonce used to sign the request
    pub async fn get(&self, url: &str, client: &Client) -> Result<String> {
        {
            let mut pool = self.pool.lock().unwrap();
            if let Some(nonce) = pool.pop_front() {
                return Ok(nonce);
            }
        }

        let response = client.head(url).send().await?;

        let nonce = response
            .headers()
            .get("replay-nonce")
            .ok_or(Error::MissingHeader("replay-nonce"))?
            .to_str()
            .map_err(|e| Error::InvalidHeader("replay-nonce", e))?
            .to_owned();
        Ok(nonce)
    }

    /// Extract a nonce from the `Replay-Nonce` header if it exists
    pub fn extract_from_response(&self, response: &Response) -> Result<()> {
        if let Some(nonce) = response.headers().get("replay-nonce") {
            let nonce = nonce
                .to_str()
                .map_err(|e| Error::InvalidHeader("replay-nonce", e))?
                .to_owned();

            let mut pool = self.pool.lock().unwrap();
            pool.push_back(nonce);

            // Prevent the nonce pool from growing unnecessarily large
            if pool.len() > self.max {
                pool.pop_front();
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Pool;
    use reqwest::Client;

    const NEW_NONCE_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce";

    #[tokio::test]
    async fn get_nonce_with_empty_cache() {
        let client = Client::new();
        let pool = Pool::new(10);

        let nonce = pool.get(NEW_NONCE_URL, &client).await.unwrap();
        assert_ne!(nonce.len(), 0);

        assert_pool_size(&pool, 0);
    }

    #[tokio::test]
    async fn get_nonce_with_cache() {
        let client = Client::new();

        let pool = Pool::new(10);
        {
            let mut pool = pool.pool.lock().unwrap();
            pool.push_back(String::from("nonce-asdf"));
        }

        let nonce = pool.get("http://this.should/fail", &client).await.unwrap();
        assert_eq!(nonce, "nonce-asdf");

        assert_pool_size(&pool, 0);
    }

    #[tokio::test]
    async fn cache_size_is_not_exceeded() {
        let client = Client::new();
        let pool = Pool::new(2);

        assert_pool_size(&pool, 0);

        let response = client.head(NEW_NONCE_URL).send().await.unwrap();
        pool.extract_from_response(&response).unwrap();
        assert_pool_size(&pool, 1);

        let response = client.head(NEW_NONCE_URL).send().await.unwrap();
        pool.extract_from_response(&response).unwrap();
        assert_pool_size(&pool, 2);

        let response = client.head(NEW_NONCE_URL).send().await.unwrap();
        pool.extract_from_response(&response).unwrap();
        assert_pool_size(&pool, 2);
    }

    fn assert_pool_size(pool: &Pool, expected: usize) {
        let pool = pool.pool.lock().unwrap();
        assert_eq!(pool.len(), expected);
    }
}
