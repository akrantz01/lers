use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};

/// A flattened JWS Serialization ([RFC 7515 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2))
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Jws {
    /// The Base64 URL-encoded JWS Protected Header
    pub protected: String,
    /// The Base64 URL-encoded payload of the request
    pub payload: String,
    /// The Base64 URL-encoded protected header and payload signature
    pub signature: String,
}

/// Represents a set of metadata associated with an account.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// The status of this account.
    pub status: AccountStatus,
    /// An array of URLs that the server can use to contact the client for issues related to
    /// this account.
    #[serde(rename = "contact")]
    pub contacts: Option<Vec<String>>,
    /// Indicates the client's agreement with the terms of service. This field cannot be updated
    /// by the client.
    pub terms_of_service_agreed: Option<bool>,
    /// A URL from which a list of orders submitted by this account can be fetched
    pub orders: Option<String>,
}

/// The status of an account
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account is valid and can be used
    Valid,
    /// Account was deactivated by a client
    Deactivated,
    /// Account was revoked by the server
    Revoked,
}

/// Request payload for the [newAccount](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3)
/// operation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount {
    /// An array of URLs that the server can use to contact the client for issues related to
    /// this account.
    #[serde(rename = "contact")]
    pub contacts: Option<Vec<String>>,
    /// Indicates the client's agreement with the terms of service. This field cannot be updated
    /// by the client.
    pub terms_of_service_agreed: bool,
    /// If `true`, the server will not create a new account if one does not exist. This allows a
    /// client to look up an account URL based on an account key
    pub only_return_existing: bool,
    // TODO: support externalAccountBinding (https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.4)
}

/// Represents a client's request for a certificate that is used to track the progress of that order
/// through to issuance.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The status of the order
    pub status: OrderStatus,
    /// The timestamp after which the server will consider this order invalid
    pub expires: Option<DateTime<Utc>>,
    /// The identifiers this order pertains to
    pub identifiers: Vec<Identifier>,
    /// The requested value of the `notBefore` field in the certificate
    pub not_before: Option<DateTime<Utc>>,
    /// The requested value of the `notAfter` field in the certificate
    pub not_after: Option<DateTime<Utc>>,
    /// The error that occurred while processing the order, if any.
    pub error: Option<Error>,
    /// The authorizations that the client needs to complete before the requested certificate can be
    /// issued, including unexpired authorizations that the client has completed in the past for
    /// identifiers specified in the order. The authorizations required are dictated by server
    /// policy; there may not be a 1:1 relationship between the order identifiers and the
    /// authorizations required.
    pub authorizations: Vec<String>,
    /// A URL that a CSR must be sent to once all of the order's authorizations are satisfied to
    /// finalize the order. The result of a successful finalization will be the population of the
    /// certificate URL for the order.
    pub finalize: String,
    /// A URL for the certificate that has been issued in response to this order.
    pub certificate: Option<String>,
}

/// The status of an order
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// The order was created
    Pending,
    /// The order's authorizations are all valid
    Ready,
    /// The order is waiting to be finalized by the server
    Processing,
    /// A certificate was issued
    Valid,
    /// An error occurred in the order during one of the previous stages or one of the
    /// authorizations failed.
    Invalid,
}

/// Request payload for the [newOrder](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
/// operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder {
    /// The identifiers this order pertains to
    pub identifiers: Vec<Identifier>,
    /// The requested value of the `notBefore` field in the certificate
    pub not_before: Option<DateTime<Utc>>,
    /// The requested value of the `notAfter` field in the certificate
    pub not_after: Option<DateTime<Utc>>,
}

/// An ACME authorization object represents a server's authorization for an account to represent
/// an identifier.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    /// The identifier that the account is authorized to represent.
    pub identifier: Identifier,
    /// The status of this authorization.
    pub status: AuthorizationStatus,
    /// The timestamp after which the server will consider this authorization invalid. Guaranteed
    /// to be present once the authorization is `Valid`.
    pub expires: Option<DateTime<Utc>>,
    /// For pending authorizations, the challenges that the client can fulfill in order to prove
    /// possession of the identifier. For valid authorizations, the challenge that was validated.
    /// For invalid authorizations, the challenge that was attempted and failed.
    pub challenges: Vec<Challenge>,
    /// Indicates the order contained a DNS identifier that was a wildcard domain name.
    pub wildcard: Option<bool>,
}

/// The status of an authorization
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    /// The authorization is waiting for a challenge to be successful
    Pending,
    /// The authorization has been completed successfully
    Valid,
    /// One of the challenges failed or an error occurred while waiting for a challenge to complete
    Invalid,
    /// The authorization was deactivated by the client
    Deactivated,
    /// The authorization expired due to inaction
    Expired,
    /// The authorization was revoked by the server
    Revoked,
}

/// An ACME challenge object represents a server's offer to validate a client's possession of an
/// identifier in a specific way.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// The URL to which a response can be posted.
    pub url: String,
    /// The status of this challenge.
    pub status: ChallengeStatus,
    /// he time at which the server validated this challenge.
    pub validated: Option<DateTime<Utc>>,
    #[serde(rename = "type")]
    pub type_: ChallengeType,
    /// A random value that uniquely identifies the challenge. We are making the assumption that all
    /// challenge types will only use a token, just as HTTP-01, DNS-01, and TLS-ALPN-01 do.
    pub token: String,
    /// Error that occurred while the server was validating the challenge
    pub error: Option<Error>,
}

/// The type of challenge that can be proposed by the server.
///
/// The challenges are ordered by preference if multiple solver exist for an authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChallengeType {
    /// When the identifier being validated is a domain name, the client can prove control of that
    /// domain by provisioning a TXT resource record containing a designated value for a specific
    /// validation domain name.
    #[serde(rename = "dns-01")]
    Dns01,
    /// With HTTP validation, the client in an ACME transaction proves its control over a domain
    /// name by proving that it can provision HTTP resources on a server accessible under that
    /// domain name.  The ACME server challenges the client to provision a file at a specific path,
    /// with a specific string as its content.
    #[serde(rename = "http-01")]
    Http01,
    /// The TLS with Application-Layer Protocol Negotiation (TLS ALPN) validation method proves
    /// control over a domain name by requiring the ACME client to configure a TLS server to respond
    /// to specific connection attempts using the ALPN extension with identifying information. The
    /// ACME server validates control of the domain name by connecting to a TLS server at one of the
    /// addresses resolved for the domain name and verifying that a certificate with specific
    /// content is presented.
    TlsAlpn01,
    /// The server responded with an unknown challenge type
    #[serde(other)]
    Unknown,
}

/// The status of an authorization challenge
#[derive(Clone, Copy, Debug, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// The challenge was created and is waiting for user action
    Pending,
    /// The server is processing the challenge
    Processing,
    /// The challenge was validated successfully
    Valid,
    /// The challenge failed validation
    Invalid,
}

/// Used for finalizing the certificate order
#[derive(Debug, Serialize)]
pub struct FinalizeOrder {
    /// A CSR encoding the parameters for the certificate being requested. The CSR is sent in the
    /// base64 URL-encoded version of the DER format.
    pub csr: String,
}

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

/// Request for the [revokeCertificate](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.6) operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRequest {
    /// The certificate to be revoked, in the base64url-encoded version of the DER format.
    pub certificate: String,
    /// One of the revocation reasonCodes defined in [RFC 5280 Section 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1)
    /// to be used when generating OCSP responses and CRLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
}

/// Reasons a certificate could be revoked for, from [RFC 5280 Section 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1).
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanges = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

impl Serialize for RevocationReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

macro_rules! error_type {
    (
        $(
            #[doc=$doc:expr]
            $type:ident => $urn:expr
        ),+ $(,)?
    ) => {
        /// Standard error types as defined by [RFC 8555 Section 6.7](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.7)
        #[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
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
    pub type_: ErrorType,
    /// A short, human-readable summary of the problem type, should not change between occurrences
    pub title: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: Option<String>,
    /// The HTTP status code generated by the origin server for this occurrence of the problem.
    pub status: Option<u16>,
    /// Used when the CA needs to return multiple errors
    pub subproblems: Option<Vec<SubProblem>>,
}

/// Sub-errors that can occur when the CA needs to return multiple errors.
///
/// Typically used in combination with the [`ErrorType::Compound`] type.
#[derive(Debug, Deserialize)]
pub struct SubProblem {
    /// The type of error
    #[serde(rename = "type")]
    pub type_: ErrorType,
    /// A short, human-readable summary of the problem type, should not change between occurrences
    pub title: Option<String>,
    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: Option<String>,
    /// Where the problem occurred in the document
    pub identifier: Option<Identifier>,
}

/// Identifiers that can be present in an authorization object
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "value")]
pub enum Identifier {
    /// A DNS identifier
    Dns(String),
}
