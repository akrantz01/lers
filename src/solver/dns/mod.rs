//! DNS-01 solvers for various providers
//!
//! Currently, the following providers are supported:
//! - [Cloudflare](https://www.cloudflare.com): [`CloudflareDns01Solver`]
//!
//! If you would like a provider to be supported,
//! [file an issue](https://github.com/akrantz01/lers/issues/new?assignees=&labels=dns-01+provider&template=dns-1-provider-request.md&title=)
//! or [make a contribution](https://github.com/akrantz01/lers/compare).

use once_cell::sync::OnceCell;
use trust_dns_resolver::{
    error::{ResolveError, ResolveErrorKind},
    AsyncResolver, IntoName, TokioAsyncResolver,
};

#[cfg(any(feature = "dns-01-cloudflare", feature = "integration"))]
mod cloudflare;

#[cfg(feature = "dns-01-cloudflare")]
#[cfg_attr(docsrs, doc(cfg(feature = "dns-01-cloudflare")))]
pub use cloudflare::{CloudflareDns01Builder, CloudflareDns01Solver, CloudflareError};

// TODO: don't use global resolver to allow for better configuration
static RESOLVER: OnceCell<TokioAsyncResolver> = OnceCell::new();

/// Find the zone for a FQDN.
///
/// This is intended for use by DNS-01 solvers to get the root zone for a FQDN.
pub async fn find_zone_by_fqdn(fqdn: &str) -> Result<String, ResolveError> {
    let resolver = RESOLVER.get_or_try_init(|| AsyncResolver::tokio_from_system_conf())?;

    let mut name = fqdn.into_name()?;
    loop {
        let lookup = resolver.soa_lookup(name.clone()).await;
        match lookup {
            Ok(lookup) => {
                let records = lookup.as_lookup().records();
                debug_assert_ne!(records.len(), 0);
                let record = records.first().unwrap();

                break Ok(record.name().to_utf8());
            }
            Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => {
                if name.num_labels() > 1 {
                    name = name.base_name();
                    continue;
                } else {
                    break Err(e);
                }
            }
            Err(e) => break Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::find_zone_by_fqdn;
    use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};

    #[tokio::test]
    async fn find_zone_by_fqdn_simple() -> Result<(), ResolveError> {
        let zone = find_zone_by_fqdn("gist.github.com").await?;
        assert_eq!(zone, "github.com.");

        Ok(())
    }

    #[tokio::test]
    async fn find_zone_by_fqdn_cname() -> Result<(), ResolveError> {
        let zone = find_zone_by_fqdn("mail.google.com").await?;
        assert_eq!(zone, "google.com.");

        Ok(())
    }

    #[tokio::test]
    async fn find_zone_by_fqdn_non_existent_subdomain() -> Result<(), ResolveError> {
        let zone = find_zone_by_fqdn("foo.google.com").await?;
        assert_eq!(zone, "google.com.");

        Ok(())
    }

    #[tokio::test]
    async fn find_zone_by_fqdn_etld() -> Result<(), ResolveError> {
        let zone = find_zone_by_fqdn("example.com.ac").await?;
        assert_eq!(zone, "ac.");

        Ok(())
    }

    #[tokio::test]
    async fn find_zone_by_fqdn_cross_zone_cname() -> Result<(), ResolveError> {
        let zone = find_zone_by_fqdn("cross-zone-example.assets.sh").await?;
        assert_eq!(zone, "assets.sh.");

        Ok(())
    }

    #[tokio::test]
    async fn find_zone_by_fqdn_non_existent() {
        let error = find_zone_by_fqdn("test.lego.zz").await.unwrap_err();
        assert!(matches!(
            error.kind(),
            ResolveErrorKind::NoRecordsFound { .. }
        ));
    }
}
