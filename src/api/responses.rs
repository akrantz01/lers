use serde::Deserialize;

/// Directory URLs and optional metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    pub new_authz: Option<String>,
    #[serde(default)]
    pub meta: DirectoryMeta,
}

/// Metadata about a directory.
///
/// Directories are not required to provide this information.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    pub caa_identities: Option<Vec<String>>,
    pub external_account_required: Option<bool>,
}
