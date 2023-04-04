use openssl::{error::ErrorStack, ssl, x509::X509VerifyResult};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{self, ErrorKind},
};

/// From https://github.com/sfackler/rust-native-tls/blob/8fa929d6c3fb7c7adfca9e0fdd6446f5dfb34f92/src/imp/openssl.rs#L112-L150
#[derive(Debug)]
pub enum Error {
    Normal(ErrorStack),
    Ssl(ssl::Error, X509VerifyResult),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Normal(ref e) => std::error::Error::source(e),
            Error::Ssl(ref e, _) => std::error::Error::source(e),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::Normal(ref e) => Display::fmt(e, f),
            Error::Ssl(ref e, X509VerifyResult::OK) => Display::fmt(e, f),
            Error::Ssl(ref e, v) => write!(f, "{} ({})", e, v),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::Normal(err)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(ErrorKind::Other, err)
    }
}
