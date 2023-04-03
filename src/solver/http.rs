use super::{
    common::{ChallengeAuthorization, Challenges, SolverHandle},
    Solver,
};
use hyper::{
    header,
    server::{conn::AddrIncoming, Builder, Server},
    service::Service,
    Body, Method, Request, Response, StatusCode,
};
use std::{
    future::Future,
    net::{SocketAddr, TcpListener},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

/// A bare-bones implementation of a solver for the HTTP-01 challenge.
#[derive(Clone, Debug, Default)]
pub struct Http01Solver {
    challenges: Challenges,
}

impl Http01Solver {
    /// Create a new solver
    pub fn new() -> Self {
        Self::default()
    }

    /// Start the solver in a separate task listening on the given address
    pub fn start(&self, address: &SocketAddr) -> hyper::Result<SolverHandle<hyper::Error>> {
        let builder = Server::try_bind(address)?;
        Ok(self.launch(builder))
    }

    /// Start the solver in a separate task using the given listener
    pub fn start_with_listener(
        &self,
        listener: TcpListener,
    ) -> hyper::Result<SolverHandle<hyper::Error>> {
        let builder = Server::from_tcp(listener)?;
        Ok(self.launch(builder))
    }

    fn launch(&self, builder: Builder<AddrIncoming>) -> SolverHandle<hyper::Error> {
        let (tx, rx) = oneshot::channel();

        let server = builder
            .serve(MakeSvc(self.challenges.clone()))
            .with_graceful_shutdown(async { rx.await.unwrap() });

        SolverHandle {
            handle: tokio::spawn(server),
            tx,
        }
    }
}

#[async_trait::async_trait]
impl Solver for Http01Solver {
    async fn present(
        &self,
        domain: String,
        token: String,
        key_authorization: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let mut challenges = self.challenges.write();
        challenges.insert(
            token,
            ChallengeAuthorization {
                domain,
                key_authorization,
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

struct SolverService(Challenges);

impl Service<Request<Body>> for SolverService {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        fn response(body: &'static str, status: StatusCode) -> Response<Body> {
            Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap()
        }

        if req.method() != Method::GET {
            return Box::pin(async {
                Ok(response(
                    "method not allowed",
                    StatusCode::METHOD_NOT_ALLOWED,
                ))
            });
        }

        let host = req
            .headers()
            .get(header::HOST)
            .map(|v| v.to_str().unwrap_or(""));

        let token = req
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/");

        if let (Some(token), Some(host)) = (token, host) {
            let challenges = self.0.read();

            if let Some(challenge) = challenges.get(token) {
                if challenge.domain == host {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .body(challenge.key_authorization.clone().into())
                        .unwrap();

                    return Box::pin(async { Ok(response) });
                }
            }
        }

        Box::pin(async { Ok(response("not found", StatusCode::NOT_FOUND)) })
    }
}

struct MakeSvc(Challenges);

impl<T> Service<T> for MakeSvc {
    type Response = SolverService;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: T) -> Self::Future {
        let challenges = self.0.clone();
        Box::pin(async move { Ok(SolverService(challenges)) })
    }
}

#[cfg(test)]
mod tests {
    use super::{Http01Solver, Solver, SolverHandle};
    use reqwest::{header, Client, StatusCode};
    use std::net::{SocketAddr, TcpListener};

    macro_rules! assert_challenges_size {
        ($solver:expr, $expected:expr) => {{
            let challenges = $solver.challenges.read();
            assert_eq!(challenges.len(), $expected);
        }};
    }

    const DOMAIN: &str = "domain.com";
    const TOKEN: &str = "testing-token";
    const KEY_AUTHZ: &str = "testing-key-authorization";

    fn solver() -> (Http01Solver, SolverHandle<hyper::Error>, SocketAddr) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();

        let solver = Http01Solver::new();
        let handle = solver.start_with_listener(listener).unwrap();

        (solver, handle, addr)
    }

    fn request_url(addr: &SocketAddr, token: &str) -> String {
        format!("http://{addr}/.well-known/acme-challenge/{token}")
    }

    #[tokio::test]
    async fn valid() {
        let (solver, handle, addr) = solver();

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let client = Client::new();
        let response = client
            .get(request_url(&addr, TOKEN))
            .header(header::HOST, DOMAIN)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let key_authorization = response.text().await.unwrap();
        assert_eq!(key_authorization, KEY_AUTHZ);

        solver.cleanup(TOKEN).await.unwrap();
        assert_challenges_size!(solver, 0);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn post() {
        let (_solver, handle, addr) = solver();

        let client = Client::new();
        let response = client.post(request_url(&addr, TOKEN)).send().await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn missing_token() {
        let (solver, handle, addr) = solver();

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let client = Client::new();
        let response = client
            .get(format!("http://{addr}/no/token"))
            .header(header::HOST, DOMAIN)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn wrong_token() {
        let (solver, handle, addr) = solver();

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let client = Client::new();
        let response = client
            .get(request_url(&addr, "wrong-token"))
            .header(header::HOST, DOMAIN)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn missing_host_header() {
        let (solver, handle, addr) = solver();

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let client = Client::new();
        let response = client.get(request_url(&addr, TOKEN)).send().await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        handle.stop().await.unwrap();
    }

    #[tokio::test]
    async fn wrong_host_header() {
        let (solver, handle, addr) = solver();

        solver
            .present(DOMAIN.into(), TOKEN.into(), KEY_AUTHZ.into())
            .await
            .unwrap();
        assert_challenges_size!(solver, 1);

        let client = Client::new();
        let response = client
            .get(request_url(&addr, TOKEN))
            .header(header::HOST, "wrong.domain")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        handle.stop().await.unwrap();
    }
}
