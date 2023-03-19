use crate::api::{responses, JWSError};
use reqwest::header::ToStrError;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// Error occurred in the server
    Server(responses::Error),
    /// Error occurred while processing the request
    Reqwest(reqwest::Error),
    /// Failed serializing the request
    Serialization(serde_json::Error),
    /// Failed to generate JSON Web Signature for the request
    JWS(JWSError),
    /// The `Location` header was missing from the response
    MissingHeader(&'static str),
    /// The header contained invalid data
    InvalidHeader(&'static str, ToStrError),
    InvalidAccount(responses::AccountStatus),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server(_) => write!(f, "an error occurred in the server"),
            Self::Reqwest(_) => write!(f, "an error occurred while processing the request"),
            Self::Serialization(_) => write!(f, "an error occurred while serializing the request"),
            Self::JWS(_) => write!(f, "failed to generate json web signature for request"),
            Self::MissingHeader(name) => write!(f, "the `{name}` header was missing"),
            Self::InvalidHeader(name, _) => {
                write!(f, "the value of the `{name}` header was invalid")
            }
            Self::InvalidAccount(status) => {
                write!(f, "expected Valid account, got {status:?} account")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Server(_) => None,
            Self::Reqwest(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::JWS(e) => Some(e),
            Self::MissingHeader(_) => None,
            Self::InvalidHeader(_, e) => Some(e),
            Self::InvalidAccount(_) => None,
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

impl From<JWSError> for Error {
    fn from(err: JWSError) -> Self {
        Self::JWS(err)
    }
}
