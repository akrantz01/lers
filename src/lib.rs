#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

//! # lers
//!
//! An async, user-friendly Let's Encrypt/ACMEv2 library. Inspired by
//! [acme2](https://github.com/lucacasonato/acme2), [acme-micro](https://github.com/kpcyrd/acme-micro),
//! and [lego](https://github.com/go-acme/lego).
//!
//! Features:
//!
//! - ACME v2 support (according to [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html))
//! - Account creation, certificate issuance, certificate renewal, and certificate revocation
//! - Robust implementation of [HTTP-01](solver::Http01Solver) and [DNS-01](solver::dns) challenges
//! - Custom challenge solvers via [`Solver`]
//! - [External account bindings](https://www.rfc-editor.org/rfc/rfc8555.html#page-38) support
//!
//! ## Example
//!
//! How to obtain a certificate for `example.com` from Let's Encrypt Staging using the
//! [`solver::Http01Solver`].
//!
//! ```no_run
#![doc = include_str!("../examples/http-01.rs")]
//! ```
//!
//! See the [examples/](https://github.com/akrantz01/lers/tree/main/examples) folder for more examples.
//!

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
