use once_cell::sync::OnceCell;
use trust_dns_resolver::{
    error::{ResolveError, ResolveErrorKind},
    AsyncResolver, IntoName, TokioAsyncResolver,
};

/// TODO: don't use global resolver to allow for better configuration
static RESOLVER: OnceCell<TokioAsyncResolver> = OnceCell::new();

/// Find the zone for a FQDN.
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
        let error = dbg!(find_zone_by_fqdn("test.lego.zz").await).unwrap_err();
        assert!(matches!(
            error.kind(),
            ResolveErrorKind::NoRecordsFound { .. }
        ));
    }
}
