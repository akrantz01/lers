#![cfg_attr(docsrs, feature(doc_cfg))]

mod account;
mod api;
mod certificate;
mod directory;
mod error;
mod order;
pub mod solver;
#[cfg(test)]
mod test;

pub(crate) const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub use account::{Account, AccountBuilder};
pub use api::responses;
pub use certificate::{Certificate, CertificateBuilder, Format};
pub use directory::{
    Directory, DirectoryBuilder, LETS_ENCRYPT_PRODUCTION_URL, LETS_ENCRYPT_STAGING_URL,
};
pub use error::Error;
pub use solver::Solver;
