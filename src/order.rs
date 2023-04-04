use crate::{
    api::key_authorization,
    error::Result,
    responses::{self, AuthorizationStatus, ChallengeStatus, Identifier, OrderStatus},
    Account, Error,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use chrono::{DateTime, Utc};
use futures::future;
use openssl::{
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Name, X509Req, X509},
};
use std::{cmp::Ordering, time::Duration};
use tracing::{debug, field, instrument, Level, Span};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_ATTEMPTS: usize = 10;

/// A convenience wrapper around an order resource
#[derive(Debug)]
pub(crate) struct Order<'a> {
    account: &'a Account,
    url: String,
    inner: responses::Order,
}

impl<'a> Order<'a> {
    /// Create a new order for a certificate
    #[instrument(
        level = Level::DEBUG,
        name = "Order::create",
        err,
        skip_all,
        fields(order.id, order.status),
    )]
    pub async fn create(
        account: &'a Account,
        identifiers: Vec<Identifier>,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
    ) -> Result<Order<'a>> {
        let (url, inner) = account
            .api
            .new_order(
                identifiers,
                not_before,
                not_after,
                &account.private_key,
                &account.id,
            )
            .await?;

        Span::current().record("order.id", &url);
        Span::current().record("order.status", field::debug(&inner.status));

        Ok(Order {
            account,
            url,
            inner,
        })
    }

    /// Get all the authorizations for the order
    #[instrument(
        level = Level::DEBUG,
        name = "Order::authorizations",
        err,
        skip_all,
        fields(self.id = self.url, self.status = ?self.inner.status),
    )]
    pub async fn authorizations(&self) -> Result<Vec<Authorization>> {
        future::try_join_all(
            self.inner
                .authorizations
                .iter()
                .map(|url| Authorization::fetch(self.account, url)),
        )
        .await
    }

    /// Get the ID of the order
    pub fn id(&self) -> &str {
        &self.url
    }

    /// Generate a base64 URL-encoded CSR for the certificate private key and identifiers
    fn generate_csr(&self, key: &PKey<Private>) -> Result<String> {
        let domains = self
            .inner
            .identifiers
            .iter()
            .map(|Identifier::Dns(domain)| domain.to_owned())
            .collect::<Vec<_>>();

        let name = {
            let mut name = X509Name::builder()?;
            name.append_entry_by_nid(Nid::COMMONNAME, &domains[0])?;
            name.build()
        };

        let mut builder = X509Req::builder()?;
        builder.set_subject_name(&name)?;

        let mut extensions = Stack::new()?;
        extensions.push({
            let mut san = SubjectAlternativeName::new();
            for domain in &domains {
                san.dns(domain);
            }
            san.build(&builder.x509v3_context(None))?
        })?;
        builder.add_extensions(&extensions)?;

        builder.set_pubkey(key)?;
        builder.sign(key, MessageDigest::sha256())?;

        let csr = builder.build();
        let der = csr.to_der()?;

        Ok(BASE64.encode(der))
    }

    /// Finalize an order with the provided CSR
    #[instrument(
        level = Level::DEBUG,
        name = "Order::finalize",
        err,
        skip_all,
        fields(self.id = self.url, self.status = ?self.inner.status, updated.status),
    )]
    pub async fn finalize(&mut self, private_key: &PKey<Private>) -> Result<()> {
        let csr = self.generate_csr(private_key)?;

        let order = self
            .account
            .api
            .finalize_order(
                &self.inner.finalize,
                csr,
                &self.account.private_key,
                &self.account.id,
            )
            .await?;

        Span::current().record("updated.status", field::debug(&order.status));

        self.inner = order;
        Ok(())
    }

    /// Download the certificate from the order
    #[instrument(
        level = Level::DEBUG,
        name = "Order::download",
        err,
        skip_all,
        fields(
            self.id = self.url,
            self.status = ?self.inner.status,
            self.has_certificate = ?self.inner.certificate.is_some(),
        ),
    )]
    pub async fn download(self) -> Result<Vec<X509>> {
        if self.inner.status != OrderStatus::Valid {
            return Err(match self.inner.error {
                Some(error) => Error::OrderFailed(error),
                None => Error::CannotDownloadCertificate,
            });
        }

        let certificate_url = self
            .inner
            .certificate
            .ok_or(Error::CannotDownloadCertificate)?;

        let certificate = self
            .account
            .api
            .download_certificate(
                &certificate_url,
                &self.account.private_key,
                &self.account.id,
            )
            .await?;

        let stack = X509::stack_from_pem(&certificate.into_bytes())?;
        Ok(stack)
    }

    /// Wait for the order to transition into [`OrderStatus::Ready`]
    #[instrument(
        level = Level::DEBUG,
        name = "Order::wait_ready",
        err,
        skip_all,
        fields(self.id = self.url, self.status = ?self.inner.status, updated.status)
    )]
    pub async fn wait_ready(&mut self) -> Result<()> {
        let order = self
            .account
            .api
            .wait_until(
                |url, private_key, account_id| async {
                    self.account
                        .api
                        .fetch_order(url, private_key, account_id)
                        .await
                },
                |o| o.status == OrderStatus::Ready,
                &self.url,
                &self.account.private_key,
                &self.account.id,
                DEFAULT_INTERVAL,
                DEFAULT_ATTEMPTS,
            )
            .await?;

        Span::current().record("updated.status", field::debug(&order.status));
        self.inner = order;

        Ok(())
    }

    /// Wait for the order to transition into [`OrderStatus::Valid`] or [`OrderStatus::Invalid`]
    #[instrument(
        level = Level::DEBUG,
        name = "Order::wait_done",
        err,
        skip_all,
        fields(self.id = self.url, self.status = ?self.inner.status, updated.status)
    )]
    pub async fn wait_done(&mut self) -> Result<()> {
        let order = self
            .account
            .api
            .wait_until(
                |url, private_key, account_id| async {
                    self.account
                        .api
                        .fetch_order(url, private_key, account_id)
                        .await
                },
                |o| o.status == OrderStatus::Valid || o.status == OrderStatus::Invalid,
                &self.url,
                &self.account.private_key,
                &self.account.id,
                DEFAULT_INTERVAL,
                DEFAULT_ATTEMPTS,
            )
            .await?;

        Span::current().record("updated.status", field::debug(&order.status));
        self.inner = order;

        Ok(())
    }
}

/// A convenience wrapper around an authorization
#[derive(Debug)]
pub(crate) struct Authorization<'a> {
    account: &'a Account,
    url: String,
    inner: responses::Authorization,
}

impl<'a> Authorization<'a> {
    /// Fetch an authorization from it's URL
    #[instrument(
        level = Level::DEBUG,
        name = "Authorization::fetch",
        err, skip(account),
        fields(
            %account.id,
            authorization.status,
            authorization.challenges.len,
            authorization.identifier,
            authorization.wildcard,
        ),
    )]
    async fn fetch(account: &'a Account, url: &str) -> Result<Authorization<'a>> {
        let mut authorization = account
            .api
            .fetch_authorization(url, &account.private_key, &account.id)
            .await?;

        authorization.challenges.sort_by(challenge_type);

        let span = Span::current();
        span.record("authorization.status", field::debug(&authorization.status));
        span.record(
            "authorization.challenges.len",
            authorization.challenges.len(),
        );
        span.record(
            "authorization.identifier",
            field::debug(&authorization.identifier),
        );
        span.record(
            "authorization.wildcard",
            authorization.wildcard.unwrap_or_default(),
        );

        Ok(Authorization {
            account,
            url: url.to_owned(),
            inner: authorization,
        })
    }

    /// Attempt to solve one of the authorization's challenges
    #[instrument(
        level = Level::DEBUG,
        name = "Authorization::solve",
        err,
        skip_all,
        fields(
            self.id = %self.url,
            self.status = ?self.inner.status,
            self.identifier = ?self.inner.identifier,
            self.wildcard = ?self.inner.wildcard.unwrap_or_default(),
        ),
    )]
    pub async fn solve(&self) -> Result<()> {
        let api = &self.account.api;
        let private_key = &self.account.private_key;
        let account_id = &self.account.id;

        let Identifier::Dns(domain) = &self.inner.identifier;

        for challenge in &self.inner.challenges {
            debug!("finding solver for {:?}", challenge.type_);
            let Some(solver) = api.solver_for(challenge) else { continue };
            debug!("attempting to solve {:?} challenge", challenge.type_);

            let authorization = format_key_authorization(challenge, private_key)?;
            solver
                .present(domain.to_owned(), challenge.token.to_owned(), authorization)
                .await
                .map_err(|e| Error::SolverFailure(e))?;

            api.validate_challenge(&challenge.url, private_key, account_id)
                .await?;

            self.wait_for_challenge(&challenge.url, solver.interval(), solver.attempts())
                .await?;

            solver
                .cleanup(&challenge.token)
                .await
                .map_err(|e| Error::SolverFailure(e))?;

            // Wait for the authorization to complete
            let status = self.wait_done().await?;
            if status != AuthorizationStatus::Valid {
                return Err(Error::ChallengeFailed(
                    self.inner.identifier.clone(),
                    challenge.type_,
                ));
            }

            return Ok(());
        }

        Err(Error::MissingSolver)
    }

    /// Wait for the challenge to transition into either [`ChallengeStatus::Valid`]
    /// or [`ChallengeStatus::Invalid`].
    #[instrument(
        level = Level::DEBUG,
        name = "Authorization::wait_for_challenge",
        err,
        skip(self),
        fields(
            self.id = %self.url,
            self.status = ?self.inner.status,
            self.identifier = ?self.inner.identifier,
            self.wildcard = ?self.inner.wildcard.unwrap_or_default(),
            challenge.status, challenge.r#type,
        )
    )]
    async fn wait_for_challenge(
        &self,
        url: &str,
        interval: Duration,
        max_attempts: usize,
    ) -> Result<ChallengeStatus> {
        let challenge = self
            .account
            .api
            .wait_until(
                |url, private_key, account_id| async {
                    self.account
                        .api
                        .fetch_challenge(url, private_key, account_id)
                        .await
                },
                |c| c.status == ChallengeStatus::Valid || c.status == ChallengeStatus::Invalid,
                url,
                &self.account.private_key,
                &self.account.id,
                interval,
                max_attempts,
            )
            .await?;

        Span::current().record("challenge.status", field::debug(&challenge.status));
        Span::current().record("challenge.type", field::debug(&challenge.type_));

        Ok(challenge.status)
    }

    /// Wait for the authorization to transition into either [`AuthorizationStatus::Valid`] or
    /// [`AuthorizationStatus::Invalid`]
    #[instrument(
        level = Level::DEBUG,
        name = "Authorization::wait_done",
        err,
        skip_all,
        fields(
            self.id = %self.url,
            self.status = ?self.inner.status,
            self.identifier = ?self.inner.identifier,
            self.wildcard = ?self.inner.wildcard.unwrap_or_default(),
            updated.status,
        ),
    )]
    async fn wait_done(&self) -> Result<AuthorizationStatus> {
        let authorization = self
            .account
            .api
            .wait_until(
                |url, private_key, account_id| async {
                    self.account
                        .api
                        .fetch_authorization(url, private_key, account_id)
                        .await
                },
                |a| {
                    a.status == AuthorizationStatus::Valid
                        || a.status == AuthorizationStatus::Invalid
                },
                &self.url,
                &self.account.private_key,
                &self.account.id,
                DEFAULT_INTERVAL,
                DEFAULT_ATTEMPTS,
            )
            .await?;

        Span::current().record("updated.status", field::debug(&authorization.status));

        Ok(authorization.status)
    }
}

/// Generate the key authorization and ensure it is in the correct format for the challenge.
fn format_key_authorization(
    challenge: &responses::Challenge,
    private_key: &PKey<Private>,
) -> Result<String> {
    use responses::ChallengeType;

    let authorization = key_authorization(&challenge.token, private_key)?;

    Ok(match challenge.type_ {
        ChallengeType::Dns01 => {
            let digest = hash(MessageDigest::sha256(), authorization.as_bytes())?;
            BASE64.encode(digest)
        }
        _ => authorization,
    })
}

fn challenge_type(a: &responses::Challenge, b: &responses::Challenge) -> Ordering {
    use responses::ChallengeType::*;

    match (a.type_, b.type_) {
        (Dns01, Dns01) | (Http01, Http01) | (TlsAlpn01, TlsAlpn01) | (Unknown, Unknown) => {
            Ordering::Equal
        }
        // prefer DNS-01 over everything
        (Dns01, _) => Ordering::Greater,
        // prefer HTTP-01 over everything except for DNS
        (Http01, TlsAlpn01) | (Http01, Unknown) => Ordering::Greater,
        (Http01, Dns01) => Ordering::Less,
        // prefer TLS-ALPN-01 last
        (TlsAlpn01, Unknown) => Ordering::Greater,
        (TlsAlpn01, Http01) | (TlsAlpn01, Dns01) => Ordering::Less,
        // never prefer unknown, we can't handle it
        (Unknown, _) => Ordering::Less,
    }
}
