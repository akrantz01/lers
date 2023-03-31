// You'll need the dns-01 and dns-01-cloudflare features enabled
use lers::{solver::dns::CloudflareDns01Solver, Directory, LETS_ENCRYPT_STAGING_URL};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a Cloudflare DNS-01 solver. You'll need to have the CLOUDFLARE_API_TOKEN environment
    // set for this to work.
    let solver = CloudflareDns01Solver::from_env()?.build()?;

    // Create a new directory for Let's Encrypt Staging
    let directory = Directory::builder(LETS_ENCRYPT_STAGING_URL)
        .dns01_solver(Box::new(solver))
        .build()
        .await?;

    // Create an ACME account to order your certificate. In production, you should store
    // the private key, so you can renew your certificate.
    let account = directory
        .account()
        .terms_of_service_agreed(true)
        .contacts(vec!["mailto:hello@example.com".into()])
        .create_if_not_exists()
        .await?;

    // Obtain your wildcard certificate
    let certificate = account
        .certificate()
        .add_domain("*.example.com")
        .obtain()
        .await?;

    // You now have your certificate to export to a webserver or store somewhere.
    assert!(certificate.x509_chain().len() > 1);

    Ok(())
}
