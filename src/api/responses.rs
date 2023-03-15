use serde::Deserialize;

/// Directory URLs and optional metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    /// URL for the [newNonce](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.2) operation
    pub new_nonce: String,
    /// URL for the [newAccount](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3) operation
    pub new_account: String,
    /// URL for the [newOrder](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4) operation
    pub new_order: String,
    /// URL for the [revokeCert](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.6) operation
    pub revoke_cert: String,
    /// URL for the [keyChange](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.5) operation
    pub key_change: String,
    /// URL for the [newAuthz](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.1) operation
    pub new_authz: Option<String>,
    /// Metadata relating to the service provided by the ACME server
    #[serde(default)]
    pub meta: DirectoryMeta,
}

/// Metadata about a directory.
///
/// Directories are not required to provide this information.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryMeta {
    /// A URL identifying the current terms of service.
    pub terms_of_service: Option<String>,
    /// An HTTP or HTTPS URL locating a website providing more information about the ACME server.
    pub website: Option<String>,
    /// The hostnames that the ACME server recognizes as referring to itself for the purposes of
    /// CAA record validation as defined in [RFC6844](https://www.rfc-editor.org/rfc/rfc6844.html).
    pub caa_identities: Option<Vec<String>>,
    /// If this field is present and set to "true", then the CA requires that all newAccount
    /// requests include an "externalAccountBinding" field associating the new account with
    /// an external account.
    pub external_account_required: Option<bool>,
}

macro_rules! error_type {
    (
        $(
            #[doc=$doc:expr]
            $type:ident => $urn:expr
        ),+ $(,)?
    ) => {
        /// Standard error types as defined by [RFC 8555 Section 6.7](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.7)
        #[derive(Debug, serde::Deserialize)]
        pub enum ErrorType {
            $(
                #[doc=$doc]
                #[serde(rename = $urn)]
                $type,
            )*
            /// A non-standard error occurred
            Other(String),
        }

        impl ErrorType {
            /// Get a description of the error type
            pub fn description(&self) -> &'static str {
                match self {
                    $(
                        Self::$type => $doc,
                    )*
                    Self::Other(_) => "A non-standard error",
                }
            }

            /// Get the full error code
            pub fn code(&self) -> &str {
                match self {
                    $(
                        Self::$type => $urn,
                    )*
                    Self::Other(e) => e.as_str(),
                }
            }
        }
    };
}

error_type! {
    /// The request specified an account that does not exist
    AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
    /// The request specified a certificate that has already been revoked
    AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
    /// The CSR is unacceptable (e.g. due toa short key)
    BadCsr => "urn:ietf:params:acme:error:badCSR",
    /// The client sent an unacceptable anti-replay nonce
    BadNonce => "urn:ietf:params:acme:error:badNonce",
    /// The JWS was signed by a public key the server does not support
    BadPublicKey => "urn:ietf:params:acme:error:badPublicKey",
    /// The revocation reason provided is not allowed by the server
    BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
    /// The JWS was signed by an algorithm the server does not support
    BadSignatureAlgorithm => "urn:ietf:params:acme:error:badSignatureAlgorithm",
    /// Certificate Authority Authorization (CAA) records forbid the CA from issuing a certificate
    Caa => "urn:ietf:params:acme:error:caa",
    /// Specific error conditions are indicated in the `subproblems` array
    Compound => "urn:ietf:params:acme:error:compound",
    /// The server could not connect to the validation target
    Connection => "urn:ietf:params:acme:error:connection",
    /// There was a problem with a DNS query during identifier validation
    Dns => "urn:ietf:params:acme:error:dns",
    /// The request must include a value for the `externalAccountBinding` field
    ExternalAccountRequired => "urn:ietf:params:acme:error:externalAccountRequired",
    /// Response received didn't match the challenge's requirements
    IncorrectResponse => "urn:ietf:params:acme:error:incorrectResponse",
    /// A contact URL for an account was invalid
    InvalidContact => "urn:ietf:params:acme:error:invalidContact",
    /// The request message was invalid
    Malformed => "urn:ietf:params:acme:error:malformed",
    /// The request attempted to finalize an order that is not ready to be finalized
    OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
    /// The request exceeds a rate limit
    RateLimited => "urn:ietf:params:acme:error:rateLimited",
    /// The server will not issue certificates for the identifier
    RejectedIdentifier => "urn:ietf:params:acme:error:rejectedIdentifier",
    /// The server experienced an internal error
    ServerInternal => "urn:ietf:params:acme:error:serverInternal",
    /// The server received a TLS error during validation
    Tls => "urn:ietf:params:acme:error:tls",
    /// The client lacks sufficient authorization
    Unauthorized => "urn:ietf:params:acme:error:unauthorized",
    /// A contact URL for an account used an unsupported protocol scheme
    UnsupportedContact => "urn:ietf:params:acme:error:unsupportedContact",
    /// An identifier is of an unsupported type
    UnsupportedIdentifier => "urn:ietf:params:acme:error:unsupportedIdentifier",
    /// Visit the `instance` URL and take actions specified there
    UserActionRequired => "urn:ietf:params:acme:error:userActionRequired",
}

/// An error returned by the server
#[derive(Debug, Deserialize)]
pub struct Error {
    /// The type of error
    #[serde(rename = "type")]
    type_: ErrorType,
    /// A short, human-readable summary of the problem type, should not change between occurrences
    title: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    detail: Option<String>,
    /// The HTTP status code generated by the origin server for this occurrence of the problem.
    status: Option<u16>,
    /// Used when the CA needs to return multiple errors
    subproblems: Option<Vec<SubProblem>>,
}

/// Sub-errors that can occur when the CA needs to return multiple errors.
///
/// Typically used in combination with the [`ErrorType::Compound`] type.
#[derive(Debug, Deserialize)]
pub struct SubProblem {
    /// The type of error
    #[serde(rename = "type")]
    type_: ErrorType,
    /// A short, human-readable summary of the problem type, should not change between occurrences
    title: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    detail: Option<String>,
    /// Where the problem occurred in the document
    identifier: Option<Identifier>,
}

/// Identifiers that can be present in an authorization object
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum Identifier {
    /// A DNS identifier
    Dns(String),
}
