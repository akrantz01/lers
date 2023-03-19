use super::{jws, responses};
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
    /// The `Replay-Nonce` header was missing from the response
    MissingReplayNonce,
    /// The value of the `Replay-Nonce` header was invalid
    InvalidReplayNonce(ToStrError),
    /// Failed serializing the request
    Serialization(serde_json::Error),
    /// Failed to generate JSON Web Signature for the request
    JWS(jws::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server(_) => write!(f, "an error occurred in the server"),
            Self::Reqwest(_) => write!(f, "an error occurred while processing the request"),
            Self::MissingReplayNonce => write!(f, "the `replay-nonce` header was missing"),
            Self::InvalidReplayNonce(_) => {
                write!(f, "the value of the `replay-nonce` header was invalid")
            }
            Self::Serialization(_) => write!(f, "an error occurred while serializing the request"),
            Self::JWS(_) => write!(f, "failed to generate json web signature for request"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Server(_) => None,
            Self::Reqwest(e) => Some(e),
            Self::MissingReplayNonce => None,
            Self::InvalidReplayNonce(e) => Some(e),
            Self::Serialization(e) => Some(e),
            Self::JWS(e) => Some(e),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err)
    }
}

impl From<ToStrError> for Error {
    fn from(err: ToStrError) -> Self {
        Self::InvalidReplayNonce(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

impl From<jws::Error> for Error {
    fn from(err: jws::Error) -> Self {
        Self::JWS(err)
    }
}
