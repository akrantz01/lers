# lers

[![Crates.io](https://img.shields.io/crates/v/lers)](https://crates.io/crates/lers)
[![docs.rs](https://img.shields.io/docsrs/lers/latest)](https://docs.rs/lers/latest/lers)

An async, user-friendly Let's Encrypt/ACMEv2 library written in Rust.

The API and implementation were inspired by [acme2][], [acme-micro][], and [lego][].

## Features
- ACME v2 ([RFC 8555][])
- Register with CA
- Obtain certificates
- Robust implementation of ACME challenges
  - [HTTP][] (http-01)
  - [DNS][] (dns-01)
- SAN certificate support
- Custom challenge solvers ([`Solver` trait][])

### Missing features

- [ ] Certificate renewal
- [x] Certificate revocation (akrantz01/lers#3)
- [ ] [TLS-ALPN-01][] challenge implementation
- [ ] Certificate bundling
- [x] [External account binding][] (akrantz01/lers#4)

Contributions are welcome for any of the above features.

### Supported DNS-01 Providers

Currently, the following providers are supported:
- [Cloudflare](https://www.cloudflare.com): [`CloudflareDns01Solver`][]

[acme2]: https://github.com/lucacasonato/acme2
[acme-micro]: https://github.com/kpcyrd/acme-micro
[lego]: https://github.com/go-acme/lego
[RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555.html
[HTTP]: https://docs.rs/lers/latest/lers/solver/struct.Http01Solver.html
[DNS]: https://docs.rs/lers/latest/lers/solver/dns/index.html
[`Solver` trait]: https://docs.rs/lers/latest/lers/solver/trait.Solver.html
[TLS-ALPN-01]: https://www.rfc-editor.org/rfc/rfc8737.html
[External account binding]: https://www.rfc-editor.org/rfc/rfc8555.html#page-38

[`CloudflareDns01Solver`]: https://docs.rs/lers/latest/lers/solver/dns/struct.CloudflareDns01Solver.html
