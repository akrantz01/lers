use super::stream::{AllowStd, TlsAcceptor};
use futures::join;
use lazy_static::lazy_static;
use native_tls::Certificate;
use openssl::{
    pkcs12::Pkcs12,
    ssl::{SslAcceptor, SslMethod, SslStream},
    stack::Stack,
    x509::X509VerifyResult,
};
use std::{
    fs,
    io::{Error, ErrorKind},
    iter,
    path::PathBuf,
    process::Command,
};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsConnector;

lazy_static! {
    static ref CERT_DIR: PathBuf = {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();

        Command::new("sh")
            .arg("-c")
            .arg(format!(
                "./hack/generate-certificates.sh {}",
                path.display()
            ))
            .output()
            .expect("failed to execute process");

        dir.into_path()
    };
}

#[tokio::test]
async fn client_to_server() {
    let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = srv.local_addr().unwrap();

    let (server_tls, client_tls) = context();

    let server = async move {
        let (socket, _) = srv.accept().await.unwrap();
        let mut socket = server_tls.accept(socket).await.unwrap();

        let openssl_stream: &SslStream<_> = socket.get_ref();
        assert_eq!(openssl_stream.ssl().verify_result(), X509VerifyResult::OK);
        let allow_std_stream: &AllowStd<_> = openssl_stream.get_ref();
        let _tokio_tcp_stream: &TcpStream = allow_std_stream.get_ref();

        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        data
    };

    let client = async move {
        let socket = TcpStream::connect(&addr).await.unwrap();
        let socket = client_tls.connect("foobar.com", socket).await.unwrap();
        copy(socket).await
    };

    let (data, _) = join!(server, client);
    assert_eq!(data, vec![9; AMOUNT]);
}

#[tokio::test]
async fn server_to_client() {
    let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = srv.local_addr().unwrap();

    let (server_tls, client_tls) = context();

    let server = async move {
        let (socket, _) = srv.accept().await.unwrap();
        let socket = server_tls.accept(socket).await.unwrap();
        copy(socket).await
    };

    let client = async move {
        let socket = TcpStream::connect(&addr).await.unwrap();
        let mut socket = client_tls.connect("foobar.com", socket).await.unwrap();

        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        data
    };

    let (_, data) = join!(server, client);
    assert_eq!(data, vec![9; AMOUNT]);
}

#[tokio::test]
async fn one_byte_at_a_time() {
    const AMOUNT: usize = 1024;

    let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = srv.local_addr().unwrap();

    let (server_tls, client_tls) = context();

    let server = async move {
        let (socket, _) = srv.accept().await.unwrap();
        let mut socket = server_tls.accept(socket).await.unwrap();

        let mut sent = 0;
        for b in iter::repeat(9).take(AMOUNT) {
            let data = [b as u8];
            socket.write_all(&data).await.unwrap();
            sent += 1;
        }
        sent
    };

    let client = async move {
        let socket = TcpStream::connect(&addr).await.unwrap();
        let mut socket = client_tls.connect("foobar.com", socket).await.unwrap();

        let mut data = Vec::new();
        loop {
            let mut buf = [0; 1];
            match socket.read_exact(&mut buf).await {
                Ok(_) => data.extend_from_slice(&buf),
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => break,
                Err(err) => panic!("{}", err),
            }
        }
        data
    };

    let (amount, data) = join!(server, client);
    assert_eq!(amount, AMOUNT);
    assert_eq!(data, vec![9; AMOUNT]);
}

fn context() -> (TlsAcceptor, TlsConnector) {
    let pkcs12 = fs::read(CERT_DIR.join("identity.p12")).unwrap();
    let pkcs12 = Pkcs12::from_der(&pkcs12).unwrap();
    let parsed = pkcs12.parse2("mypass").unwrap();

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&parsed.pkey.unwrap()).unwrap();
    acceptor.set_certificate(&parsed.cert.unwrap()).unwrap();
    parsed
        .ca
        .unwrap_or_else(|| Stack::new().unwrap())
        .into_iter()
        .rev()
        .for_each(|c| acceptor.add_extra_chain_cert(c).unwrap());
    acceptor.set_min_proto_version(None).unwrap();
    acceptor.set_max_proto_version(None).unwrap();
    let acceptor = acceptor.build();

    let der = fs::read(CERT_DIR.join("root-ca.der")).unwrap();
    let cert = Certificate::from_der(&der).unwrap();
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(cert)
        .build()
        .unwrap();

    (acceptor.into(), connector.into())
}

const AMOUNT: usize = 128 * 1024;

async fn copy<W: AsyncWrite + Unpin>(mut w: W) -> Result<usize, Error> {
    let mut data = vec![9; AMOUNT];
    let mut copied = 0;

    while !data.is_empty() {
        let written = w.write(&data).await?;
        if written <= data.len() {
            copied += written;
            data.resize(data.len() - written, 0);
        } else {
            w.write_all(&data).await?;
            copied += data.len();
            break;
        }

        println!("remaining: {}", data.len());
    }

    Ok(copied)
}
