use lers::{solver::Http01Solver, Directory, LETS_ENCRYPT_STAGING_URL};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create and start a new HTTP-01 solver.
    let address = "127.0.0.1:8080".parse()?;
    let solver = Http01Solver::new();
    let handle = solver.start(&address)?;

    // Create a new directory for Let's Encrypt Staging
    let directory = Directory::builder(LETS_ENCRYPT_STAGING_URL)
        .http01_solver(Box::new(solver))
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

    // Obtain your certificate
    let certificate = account
        .certificate()
        .add_domain("example.com")
        .obtain()
        .await?;

    // You now have your certificate to export to a webserver or store somewhere.
    assert!(certificate.x509_chain().len() > 1);

    // Stop the HTTP-01 solver since we've issued the certificate.
    handle.stop().await?;

    Ok(())
}
