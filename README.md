# lers

An async, user-friendly Let's Encrypt/ACMEv2 library written in Rust.

The API and implementation were inspired by [acme2][], [acme-micro][], and [lego][].

## Features
- ACME v2 ([RFC 8555][])
- Register with CA
- Obtain certificates
- Robust implementation of ACME challenges
  - [HTTP][] (http-01)
- SAN certificate support
- Custom challenge solvers ([`Solver` trait][])

### Missing features

- [ ] Certificate renewal
- [ ] Certificate revocation
- [ ] [TLS-ALPN-01][] challenge implementation
- [ ] Certificate bundling
- [ ] [External account binding][]

Contributions are welcome for any of the above features.

[acme2]: https://github.com/lucacasonato/acme2
[acme-micro]: https://github.com/kpcyrd/acme-micro
[lego]: https://github.com/go-acme/lego
[RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555.html
[HTTP]: https://docs.rs/lers/latest/lers/solver/struct.Http01Solver.html
[`Solver` trait]: https://docs.rs/lers/latest/lers/solver/trait.Solver.html
[TLS-ALPN-01]: https://www.rfc-editor.org/rfc/rfc8737.html
[External account binding]: https://www.rfc-editor.org/rfc/rfc8555.html#page-38
