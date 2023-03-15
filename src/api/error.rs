use super::responses::Error as ServerError;
use reqwest::header::ToStrError;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

pub(crate) type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// Error occurred in the server
    Server(ServerError),
    /// Error occurred while processing the request
    Reqwest(reqwest::Error),
    /// The `Replay-Nonce` header was missing from the response
    MissingReplayNonce,
    /// The value of the `Replay-Nonce` header was invalid
    InvalidReplayNonce(ToStrError),
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
