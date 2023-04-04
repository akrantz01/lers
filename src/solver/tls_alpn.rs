use super::{
    boxed_err,
    common::{Challenges, SolverHandle},
    Solver,
};
use futures::future::FutureExt;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    select_next_proto, AlpnError, NameType, SniError, SslAcceptor, SslContext, SslMethod,
};
use openssl::x509::X509;
use rcgen::{Certificate, CertificateParams, CustomExtension, RcgenError, SanType};
use std::{io, net::SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

mod error;
#[cfg(test)]
mod smoke;
mod stream;

use stream::TlsAcceptor;

static ALPN: &[u8; 11] = b"\x0aacme-tls/1";

/// A bare-bones implementation of a solver for the TLS-ALPN-01 challenge.
#[derive(Clone, Debug, Default)]
pub struct TlsAlpn01Solver {
    challenges: Challenges<Authorization>,
}

impl TlsAlpn01Solver {
    /// Create a new solver
    pub fn new() -> Self {
        Self::default()
    }

    /// Start the solver in a separate task listening on the given address
    pub async fn start(&self, address: SocketAddr) -> io::Result<SolverHandle<io::Error>> {
        let listener = TcpListener::bind(address).await?;
        self.start_with_listener(listener)
    }

    /// Start the solver in a separate task using the given listener.
    pub fn start_with_listener(
        &self,
        listener: TcpListener,
    ) -> io::Result<SolverHandle<io::Error>> {
        let acceptor = new_acceptor(self.challenges.clone())?;

        let (tx, rx) = oneshot::channel();
        let handle = tokio::spawn(server(acceptor, listener.into(), rx));

        Ok(SolverHandle { tx, handle })
    }
}

#[async_trait::async_trait]
impl Solver for TlsAlpn01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let (certificate, private_key) =
            generate_certificate(&domain, &key_authorization).map_err(boxed_err)?;
        let (certificate, private_key) =
            load_openssl_tls_certificate(certificate, private_key).map_err(boxed_err)?;

        let mut context = SslContext::builder(SslMethod::tls()).map_err(boxed_err)?;
        context.set_private_key(&private_key).map_err(boxed_err)?;
        context.set_certificate(&certificate).map_err(boxed_err)?;

        context.set_alpn_protos(ALPN).map_err(boxed_err)?;
        context.set_alpn_select_callback(|_ssl, client| {
            select_next_proto(ALPN, client).ok_or(AlpnError::ALERT_FATAL)
        });

        if cfg!(debug_assertions) {
            context.check_private_key().map_err(boxed_err)?;
        }

        let mut challenges = self.challenges.write();
        challenges.insert(
            token,
            Authorization {
                domain,
                context: context.build(),
            },
        );

        Ok(())
    }

    async fn cleanup(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut challenges = self.challenges.write();
        challenges.remove(token);

        Ok(())
    }
}

#[derive(Debug)]
struct Authorization {
    domain: String,
    context: SslContext,
}

fn new_acceptor(challenges: Challenges<Authorization>) -> io::Result<TlsAcceptor> {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    acceptor.set_alpn_protos(ALPN)?;
    acceptor.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ALPN, client).ok_or(AlpnError::ALERT_FATAL)
    });

    acceptor.set_servername_callback(move |ssl, _alert| {
        let servername = ssl.servername(NameType::HOST_NAME).ok_or(SniError::NOACK)?;

        let challenges = challenges.read();
        let authorization = challenges
            .values()
            .find(|a| a.domain == servername)
            .ok_or(SniError::NOACK)?;

        ssl.set_ssl_context(&authorization.context)
            .map_err(|_| SniError::ALERT_FATAL)?;

        Ok(())
    });

    Ok(acceptor.build().into())
}

async fn server(
    acceptor: TlsAcceptor,
    listener: TcpListener,
    stop: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut stop = stop.fuse();

    loop {
        futures::select_biased! {
            _ = stop => break,
            result = listener.accept().fuse() => {
                let (socket, _addr) = result?;
                if let Ok(mut socket) = acceptor.accept(socket).await {
                    debug_assert!(socket.get_ref().ssl().selected_alpn_protocol().is_some());

                    // Nothing to do once the handshake finishes
                    let _ = socket.shutdown().await;
                }
            }
        }
    }

    Ok(())
}

// Currently depends on rcgen pending support for custom x509 extensions in openssl
// Relevant issues
//   - https://github.com/sfackler/rust-openssl/issues/1411
//   - https://github.com/sfackler/rust-openssl/issues/1601
fn generate_certificate(
    domain: &str,
    key_authorization: &str,
) -> Result<(Vec<u8>, Vec<u8>), RcgenError> {
    debug_assert_eq!(key_authorization.as_bytes().len(), 32);

    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(SanType::DnsName(domain.to_owned()));
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(
            key_authorization.as_bytes(),
        ));

    let certificate = Certificate::from_params(params)?;
    let certificate_der = certificate.serialize_der()?;
    let private_key_der = certificate.serialize_private_key_der();

    Ok((certificate_der, private_key_der))
}

fn load_openssl_tls_certificate(
    certificate: Vec<u8>,
    private_key: Vec<u8>,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    let certificate = X509::from_der(&certificate)?;
    let private_key = PKey::private_key_from_der(&private_key)?;

    Ok((certificate, private_key))
}

#[cfg(test)]
mod tests {
    use super::{Solver, SolverHandle, TlsAlpn01Solver, ALPN};

    use openssl::{
        ssl::{HandshakeError, NameType, SslConnector, SslMethod, SslVerifyMode},
        x509::{X509VerifyResult, X509},
    };
    use std::{
        io,
        net::{SocketAddr, TcpStream},
    };
    use tokio::net::TcpListener;
    use x509_parser::{
        der_parser::parse_der,
        oid_registry::asn1_rs::{oid, Oid},
        parse_x509_certificate,
    };

    macro_rules! assert_challenges_size {
        ($solver:expr, $expected:expr) => {{
            let challenges = $solver.challenges.read();
            assert_eq!(challenges.len(), $expected);
        }};
    }

    const ACME_IDENTIFIER_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .31);

    const DOMAIN: &str = "domain.com";
    const TOKEN: &str = "testing-token";
    const KEY_AUTHZ: &str = "testing-key-authorization-abcdef";

    async fn solver() -> (TlsAlpn01Solver, SolverHandle<io::Error>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let solver = TlsAlpn01Solver::new();
        let handle = solver.start_with_listener(listener).unwrap();

        (solver, handle, addr)
    }

    fn check(
        address: SocketAddr,
        domain: &str,
        use_alpn: bool,
        use_sni: bool,
    ) -> Result<(Option<String>, Option<X509>), HandshakeError<TcpStream>> {
        let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
        builder
            .set_alpn_protos(if use_alpn { ALPN } else { b"\x08http/1.1" })
            .unwrap();
        let connector = builder.build();

        let mut ssl = connector
            .configure()
            .unwrap()
            .use_server_name_indication(use_sni)
            .verify_hostname(false);
        ssl.set_verify(SslVerifyMode::NONE);

        let socket = TcpStream::connect(&address).unwrap();
        let mut stream = ssl.connect(domain, socket)?;

        let servername = stream
            .ssl()
            .servername(NameType::HOST_NAME)
            .map(ToOwned::to_owned);
        let certificate = stream.ssl().peer_certificate();

        stream.shutdown().unwrap();

        Ok((servername, certificate))
    }

    // Need to use x509-parser since openssl doesn't support reading custom extensions
    // See: https://github.com/sfackler/rust-openssl/issues/373
    fn verify_key_authorization(certificate: &X509, expected: &str) {
        let der = certificate.to_der().unwrap();
        let (_, certificate) = parse_x509_certificate(&der).unwrap();

        let extension = certificate
            .get_extension_unique(&ACME_IDENTIFIER_OID)
            .unwrap()
            .unwrap();
        assert!(extension.critical);

        let (_, parsed) = parse_der(extension.value).unwrap();
        let bytes = parsed.as_slice().unwrap();
        assert_eq!(String::from_utf8_lossy(bytes), expected);
    }

    #[tokio::test]
    async fn valid() {
        let (solver, handle, addr) = solver().await;

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let (servername, certificate) =
            tokio::task::spawn_blocking(move || check(addr, DOMAIN, true, true))
                .await
                .unwrap()
                .unwrap();

        assert_eq!(servername.unwrap(), "domain.com");

        let certificate = certificate.unwrap();
        assert_eq!(
            certificate
                .subject_alt_names()
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .dnsname()
                .unwrap(),
            "domain.com"
        );
        verify_key_authorization(&certificate, KEY_AUTHZ);

        solver.cleanup(TOKEN).await.unwrap();
        assert_challenges_size!(solver, 0);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn wrong_domain() {
        let (solver, handle, addr) = solver().await;

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let error = tokio::task::spawn_blocking(move || check(addr, "wrong.domain", true, true))
            .await
            .unwrap()
            .unwrap_err();
        let HandshakeError::Failure(error) = error else { panic!("expected handshake failure") };
        assert_eq!(error.ssl().verify_result(), X509VerifyResult::OK);
        assert_eq!(error.ssl().state_string(), "SSLERR");

        solver.cleanup(TOKEN).await.unwrap();
        assert_challenges_size!(solver, 0);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn without_sni() {
        let (solver, handle, addr) = solver().await;

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let error = tokio::task::spawn_blocking(move || check(addr, DOMAIN, true, false))
            .await
            .unwrap()
            .unwrap_err();
        let HandshakeError::Failure(error) = error else { panic!("expected handshake failure") };
        assert_eq!(error.ssl().verify_result(), X509VerifyResult::OK);
        assert_eq!(error.ssl().state_string(), "SSLERR");

        solver.cleanup(TOKEN).await.unwrap();
        assert_challenges_size!(solver, 0);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn without_alpn() {
        let (solver, handle, addr) = solver().await;

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let error = tokio::task::spawn_blocking(move || check(addr, DOMAIN, false, true))
            .await
            .unwrap()
            .unwrap_err();
        let HandshakeError::Failure(error) = error else { panic!("expected handshake failure") };
        assert_eq!(error.ssl().verify_result(), X509VerifyResult::OK);
        assert_eq!(error.ssl().state_string(), "SSLERR");

        solver.cleanup(TOKEN).await.unwrap();
        assert_challenges_size!(solver, 0);

        handle.stop().await.unwrap();
    }
}
