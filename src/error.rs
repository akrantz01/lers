use crate::api::responses;
use reqwest::header::ToStrError;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

/// Possible errors that could occur
#[derive(Debug)]
pub enum Error {
    /// Error occurred in the server
    Server(responses::Error),
    /// Error occurred while processing the request
    Reqwest(reqwest::Error),
    /// Failed serializing the request
    Serialization(serde_json::Error),
    /// The `Location` header was missing from the response
    MissingHeader(&'static str),
    /// The header contained invalid data
    InvalidHeader(&'static str, ToStrError),
    /// The account's status is not set to `Valid`
    InvalidAccount(responses::AccountStatus),
    /// The certificate must have at least one identifier associated with it
    MissingIdentifiers,
    /// No solver could be found for any of the proposed challenge types
    MissingSolver,
    /// The solver encountered an error while presenting or cleaning up the challenge.
    SolverFailure(Box<dyn StdError + Send + 'static>),
    /// The maximum attempts while polling a resource was exceeded
    MaxAttemptsExceeded,
    /// The challenge for the identifier could not be validated
    ChallengeFailed(responses::Identifier, responses::ChallengeType),
    /// An error occurred within OpenSSL
    OpenSSL(openssl::error::ErrorStack),
    /// The order is invalid due to an error or authorization failure
    OrderFailed(responses::Error),
    /// The certificate cannot be downloaded due to the order state
    CannotDownloadCertificate,
    /// The provided key type is not supported
    UnsupportedKeyType,
    /// The provided ECDSA curve is not supported
    UnsupportedECDSACurve,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server(_) => write!(f, "an error occurred in the server"),
            Self::Reqwest(_) => write!(f, "an error occurred while processing the request"),
            Self::Serialization(_) => write!(f, "an error occurred while serializing the request"),
            Self::MissingHeader(name) => write!(f, "the `{name}` header was missing"),
            Self::InvalidHeader(name, _) => {
                write!(f, "the value of the `{name}` header was invalid")
            }
            Self::InvalidAccount(status) => {
                write!(f, "expected Valid account, got {status:?} account")
            }
            Self::MissingIdentifiers => write!(
                f,
                "the certificate must have at least one identifier associated with it"
            ),
            Self::MissingSolver => write!(
                f,
                "no solver could be found for the proposed challenge types"
            ),
            Self::SolverFailure(e) => write!(
                f,
                "the solver failed while presenting or cleaning up the challenge: {e}"
            ),
            Self::MaxAttemptsExceeded => write!(
                f,
                "the maximum attempts while polling a resource was exceeded"
            ),
            Self::ChallengeFailed(identifier, type_) => write!(
                f,
                "the {type_:?} challenge could not be validated for {identifier:?}"
            ),
            Self::OpenSSL(e) => write!(f, "openssl error: {e}"),
            Self::OrderFailed(e) => write!(
                f,
                "the order is invalid due to an error or authorization failure: {} ({})",
                e.type_.description(),
                e.type_.code()
            ),
            Self::CannotDownloadCertificate => {
                write!(f, "cannot download the certificate due to the order status")
            }
            Self::UnsupportedKeyType => write!(f, "the provided key type is unsupported"),
            Self::UnsupportedECDSACurve => write!(f, "the provided ecdsa curve is unsupported"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Server(_) => None,
            Self::Reqwest(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::MissingHeader(_) => None,
            Self::InvalidHeader(_, e) => Some(e),
            Self::InvalidAccount(_) => None,
            Self::MissingIdentifiers => None,
            Self::MissingSolver => None,
            Self::SolverFailure(e) => Some(e.as_ref()),
            Self::MaxAttemptsExceeded => None,
            Self::ChallengeFailed(_, _) => None,
            Self::OpenSSL(e) => Some(e),
            Self::OrderFailed(_) => None,
            Self::CannotDownloadCertificate => None,
            Self::UnsupportedKeyType => None,
            Self::UnsupportedECDSACurve => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(err)
    }
}
