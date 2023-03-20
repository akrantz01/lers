use crate::Directory;
use reqwest::Client;

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
