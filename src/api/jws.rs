use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use openssl::bn::{BigNum, BigNumContext};
use openssl::sign::Signer;
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
};
use serde::Serialize;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

#[derive(Clone, Debug)]
pub enum Error {
    UnsupportedKeyType,
    UnsupportedECDSACurve,
    OpenSSL(openssl::error::ErrorStack),
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::OpenSSL(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenSSL(e) => write!(f, "openssl error: {e}"),
            Self::UnsupportedKeyType => write!(f, "unsupported key type"),
            Self::UnsupportedECDSACurve => write!(f, "unsupported ecdsa curve"),
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        Error::OpenSSL(error)
    }
}

/// Possible algorithms a JWS can be signed with. Ignores algorithms explicitly denied by
/// [RFC 8555 Section 6.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2), namely:
/// `none` and MAC-based algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum Algorithm {
    RS256,
    // TODO: eventually support RS384 and RS512
    ES256,
    ES384,
    ES512,
    // TODO: eventually support PS256, PS384, and PS512
}

/// Determine the algorithm and digest method to use from the private key.
fn algorithm_and_digest(key: &PKey<Private>) -> Result<(Algorithm, MessageDigest), Error> {
    match key.id() {
        Id::RSA => Ok((Algorithm::RS256, MessageDigest::sha256())),
        Id::EC => {
            let ec_key = key.ec_key()?;
            match ec_key.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Ok((Algorithm::ES256, MessageDigest::sha256())),
                Some(Nid::SECP384R1) => Ok((Algorithm::ES384, MessageDigest::sha384())),
                Some(Nid::SECP521R1) => Ok((Algorithm::ES512, MessageDigest::sha512())),
                _ => Err(Error::UnsupportedECDSACurve),
            }
        }
        _ => Err(Error::UnsupportedKeyType),
    }
}

/// The header of a JSON Web Signature according to
/// [RFC 8555 Section 6.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2)
#[derive(Debug, Serialize)]
struct Header<'h> {
    nonce: String,
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    url: &'h str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'h str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kty")]
enum Jwk {
    RSA {
        e: String,
        n: String,
    },
    EC {
        crv: &'static str,
        x: String,
        y: String,
    },
}

impl TryFrom<&PKey<Private>> for Jwk {
    type Error = Error;

    fn try_from(key: &PKey<Private>) -> Result<Self, Self::Error> {
        match key.id() {
            Id::RSA => {
                let rsa = key.rsa()?;
                Ok(Jwk::RSA {
                    e: BASE64.encode(&rsa.e().to_vec()),
                    n: BASE64.encode(&rsa.n().to_vec()),
                })
            }
            Id::EC => {
                let ec = key.ec_key()?;
                let ec_public = ec.public_key();

                let mut ctx = BigNumContext::new()?;
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                ec_public.affine_coordinates(ec.group(), &mut x, &mut y, &mut ctx)?;

                let curve = match ec.group().curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => "P-256",
                    Some(Nid::SECP384R1) => "P-384",
                    Some(Nid::SECP521R1) => "P-521",
                    _ => unreachable!(),
                };

                Ok(Jwk::EC {
                    x: BASE64.encode(&x.to_vec()),
                    y: BASE64.encode(&y.to_vec()),
                    crv: curve,
                })
            }
            _ => unreachable!(),
        }
    }
}

/// A flattened JWS Serialization ([RFC 7515 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2))
#[derive(Debug, Serialize)]
pub(crate) struct JWS {
    protected: String,
    payload: String,
    signature: String,
}

/// Create a JWS for the request
pub(crate) fn sign(
    url: &str,
    nonce: String,
    payload: &str,
    private_key: &PKey<Private>,
    account_id: Option<&str>,
) -> Result<JWS, Error> {
    let payload = BASE64.encode(payload.as_bytes());

    let (algorithm, digest) = algorithm_and_digest(private_key)?;
    let header = match account_id {
        Some(kid) => Header {
            nonce,
            algorithm,
            url,
            kid: Some(kid),
            jwk: None,
        },
        None => Header {
            nonce,
            algorithm,
            url,
            kid: None,
            jwk: Some(Jwk::try_from(private_key)?),
        },
    };

    let protected = serde_json::to_vec(&header).unwrap();
    let protected = BASE64.encode(&protected);

    let signature = {
        let mut signer = Signer::new(digest, private_key)?;
        signer.update(&format!("{protected}.{payload}").into_bytes())?;
        signer.sign_to_vec()?
    };
    let signature = BASE64.encode(&signature);

    Ok(JWS {
        protected,
        payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::{algorithm_and_digest, sign, Algorithm, Jwk};
    use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa};
    use std::fs;

    #[test]
    fn validate_algorithm_and_digest() {
        macro_rules! ec {
            ($curve:expr => ($algo:ident, $digest:ident)) => {
                let ec = PKey::ec_gen($curve).unwrap();
                let (algorithm, digest) = algorithm_and_digest(&ec).unwrap();
                assert_eq!(algorithm, Algorithm::$algo);
                assert!(digest == MessageDigest::$digest());
            };
        }

        macro_rules! rs {
            ($bits:expr => ($algo:ident, $digest:ident)) => {
                let rs = Rsa::generate($bits).unwrap();
                let rs = PKey::from_rsa(rs).unwrap();
                let (algorithm, digest) = algorithm_and_digest(&rs).unwrap();
                assert_eq!(algorithm, Algorithm::$algo);
                assert!(digest == MessageDigest::$digest());
            };
        }

        ec!("prime256v1" => (ES256, sha256));
        ec!("secp384r1" => (ES384, sha384));
        ec!("secp521r1" => (ES512, sha512));

        rs!(2048 => (RS256, sha256));
        rs!(3072 => (RS256, sha256));
        rs!(4096 => (RS256, sha256));
    }

    #[test]
    fn jwk_rsa() {
        let pem = fs::read("testdata/rsa_2048.pem").unwrap();
        let key = PKey::private_key_from_pem(&pem).unwrap();

        let jwk = Jwk::try_from(&key).unwrap();

        let Jwk::RSA { n: n_b64, e: e_b64 } = jwk else { panic!("not rsa jwk") };
        assert_eq!(n_b64, "y2McwrH7NMy4y-0iMBTNLWIBcvLi-_i8_sTJVaIRbsAp3rYhFFx2v_79ETp3hqquU23brJjPgYV-hdcB7lwq4ssZPD2zzvzEnLfuh0Ldsnuy_oQIKGtOvb48lqZ4c094k-TFLVhApBjkdBaJ-rhb7iM1xk3SXLWb2xBrz1iXV-okfXao9N5kV0azOZ3Spfr2HPLSEDUQrg4RW01BZe3zZtKu7TJUnlICeLJd_rexMizWx8iIzYX-NayhXSSp1yeXPRfk5ZnlhrGCu6ywmhmu7QA3dou77WxN2EzAUJAoiIuxLpCSeQV4XxnDEe4o88U9_PI1f6xBKdcfR0_HeBut3w");
        assert_eq!(e_b64, "AQAB");
    }

    macro_rules! jwk_ecdsa {
        (
            $(
                $name:ident ($file:expr) => {
                    crv: $crv:expr,
                    x: $x:expr,
                    y: $y:expr,
                }
            );+ $(;)?
        ) => {
            $(
                #[test]
                fn $name() {
                    let pem = fs::read($file).unwrap();
                    let key = PKey::private_key_from_pem(&pem).unwrap();

                    let jwk = Jwk::try_from(&key).unwrap();

                    let Jwk::EC {crv, x: x_b64, y: y_b64 } = jwk else { panic!("not ec jwk") };
                    assert_eq!(crv, $crv);
                    assert_eq!(x_b64, $x);
                    assert_eq!(y_b64, $y);
                }
            )*
        };
    }

    jwk_ecdsa! {
        jwk_ecdsa_p_256("testdata/ecdsa_p-256.pem") => {
            crv: "P-256",
            x: "bFFJEKk0HrAyTVz69iCiV8KsX1bNwSx60o6Xlat9hPo",
            y: "fsxkWwspm4NA2lUWIf9DwlrOQgf2Y610ynAwJP_Gx0E",
        };
        jwk_ecdsa_p_384("testdata/ecdsa_p-384.pem") => {
            crv: "P-384",
            x: "MDD68TroskBcnk49wd7UI1nLI4o9q9DJH0P29ibkAb6AzLxg0mIu1U3NwUTKUf_l",
            y: "HldntIAzF67Nd-jfTDaiJxa0WMVHcZ5at_AQkxtT6aCu5jQ1zSKcPvVnj1Sv3JT2",
        };
        jwk_ecdsa_p_521("testdata/ecdsa_p-521.pem") => {
            crv: "P-521",
            x: "Ad27MiJgOobBKFO_YyAy6mQ_Dz2uGLF0UD3-MkF4hLa5Z__RCrNmtidjQ5FW64wahfzLeQamEA_KATh2zFBNhSM0",
            y: "AUyg4XumobEqaPCjUGC9Mc8SE2saUrYVd824Is1ercPjpq5Wx3HE-I2HvbtLmm29UX3T5IkHmKRbPIa7oB8Oo6PL",
        };
    }

    const JWS_PAYLOAD: &str = "this is a test payload";
    const JWS_NONCE: &str = "A272VFpvC1e7H0YZ14_-fLlbt9Gg8bR-dGtl0PqjuGX_-o8";
    const JWS_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct";
    const JWS_ACCOUNT_ID: &str = "0123456";

    #[test]
    fn jws_rsa_without_account() {
        let pem = fs::read("testdata/rsa_2048.pem").unwrap();
        let key = PKey::private_key_from_pem(&pem).unwrap();

        let sig = sign(JWS_URL, String::from(JWS_NONCE), JWS_PAYLOAD, &key, None).unwrap();

        assert_eq!(sig.protected, "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiUlMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6InkyTWN3ckg3Tk15NHktMGlNQlROTFdJQmN2TGktX2k4X3NUSlZhSVJic0FwM3JZaEZGeDJ2Xzc5RVRwM2hxcXVVMjNickpqUGdZVi1oZGNCN2x3cTRzc1pQRDJ6enZ6RW5MZnVoMExkc251eV9vUUlLR3RPdmI0OGxxWjRjMDk0ay1URkxWaEFwQmprZEJhSi1yaGI3aU0xeGszU1hMV2IyeEJyejFpWFYtb2tmWGFvOU41a1YwYXpPWjNTcGZyMkhQTFNFRFVRcmc0UlcwMUJaZTN6WnRLdTdUSlVubElDZUxKZF9yZXhNaXpXeDhpSXpZWC1OYXloWFNTcDF5ZVhQUmZrNVpubGhyR0N1Nnl3bWhtdTdRQTNkb3U3N1d4TjJFekFVSkFvaUl1eExwQ1NlUVY0WHhuREVlNG84OFU5X1BJMWY2eEJLZGNmUjBfSGVCdXQzdyJ9fQ");
        assert_eq!(sig.payload, "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA");
        assert_eq!(sig.signature, "kHMqhmTjqsGJ2QGPHZ1oXjsjB0LVHogbXXv9KRlPACK9dNJe2jAZ9lFe_XsvG9-H-0sdd0mMgHh2j3QtiZRHr-PmGpBcf_DzHUy9V5KeiX5XOYjeo8fIi_Z8BF9XMFUyWx3pi9Kjjm5EnYx3uQD9KpNjGJo0DuATREoNoNeGVH6Eh34nQ18PIEAdMz04nkkYLYUSxAUiKlB_zRc-bfCYysUJqF3IGN4n1OVNcJdRFMDLQYDWBscC7q59uSDbPTK3iOJ36TALY7S84ObPxFEr3c8XmySDzOay71oTsuZyUmjCMC_lJx3WA9ecvHcRu9Co7Cdv37NhF1LcH_lUOjsKrA");
    }

    #[test]
    fn jws_rsa_with_account() {
        let pem = fs::read("testdata/rsa_2048.pem").unwrap();
        let key = PKey::private_key_from_pem(&pem).unwrap();

        let sig = sign(
            JWS_URL,
            String::from(JWS_NONCE),
            JWS_PAYLOAD,
            &key,
            Some(JWS_ACCOUNT_ID),
        )
        .unwrap();

        assert_eq!(sig.protected, "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiUlMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0Iiwia2lkIjoiMDEyMzQ1NiJ9");
        assert_eq!(sig.payload, "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA");
        assert_eq!(sig.signature, "jGnidAkLcm5f7AujOx_jdhBYDPwm0EVts5HREMUL9hs7xZVnj4C_iy7D8ZfjrJ15e5ZHToE0nmyV7_u8W5iX_4NA2isqJv_f3R9sjVky5D2nBsxS_CG3d_b2ANA1GZoVlrS_umEW2vIHQHOcnpqjZw1OEeH5DcHixeKy_3mKZIWWRvN-Jq2BD-DJdyOMHJL0jBPKYMVwR92-_mmhrtQsUZqefgDyezcENTePF6wbs_KdUUyLHja_N-3sqeD1_1k0z3_WhlEiKplYx1eNdd27tzXXy4CKXEtzouDN-1w6bhLBheik3Wa3rPkD9JVaFxbQy1LOa2jpTHkEK_TJLiUhfA");
    }

    macro_rules! jws_ecdsa {
        (
            $(
                $name:ident ($file:expr, $acct:expr) => {
                    protected: $protected:expr,
                    payload: $payload:expr,
                }
            );+ $(;)?
        ) => {
            $(
                #[test]
                fn $name() {
                    let pem = fs::read($file).unwrap();
                    let key = PKey::private_key_from_pem(&pem).unwrap();

                    let sig = jws(JWS_URL, String::from(JWS_NONCE), JWS_PAYLOAD, &key, $acct).unwrap();

                    assert_eq!(sig.protected, $protected);
                    assert_eq!(sig.payload, $payload);
                    assert!(!sig.signature.is_empty());
                }
            )*
        };
    }

    jws_ecdsa! {
        jws_ecdsa_p_256_without_account("testdata/ecdsa_p-256.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYkZGSkVLazBIckF5VFZ6NjlpQ2lWOEtzWDFiTndTeDYwbzZYbGF0OWhQbyIsInkiOiJmc3hrV3dzcG00TkEybFVXSWY5RHdsck9RZ2YyWTYxMHluQXdKUF9HeDBFIn19",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_384_without_account("testdata/ecdsa_p-384.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMzODQiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoiTURENjhUcm9za0Jjbms0OXdkN1VJMW5MSTRvOXE5REpIMFAyOWlia0FiNkF6THhnMG1JdTFVM053VVRLVWZfbCIsInkiOiJIbGRudElBekY2N05kLWpmVERhaUp4YTBXTVZIY1o1YXRfQVFreHRUNmFDdTVqUTF6U0tjUHZWbmoxU3YzSlQyIn19",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_521_without_account("testdata/ecdsa_p-521.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVM1MTIiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC01MjEiLCJ4IjoiQWQyN01pSmdPb2JCS0ZPX1l5QXk2bVFfRHoydUdMRjBVRDMtTWtGNGhMYTVaX19SQ3JObXRpZGpRNUZXNjR3YWhmekxlUWFtRUFfS0FUaDJ6RkJOaFNNMCIsInkiOiJBVXlnNFh1bW9iRXFhUENqVUdDOU1jOFNFMnNhVXJZVmQ4MjRJczFlcmNQanBxNVd4M0hFLUkySHZidExtbTI5VVgzVDVJa0htS1JiUElhN29COE9vNlBMIn19",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
    }

    jws_ecdsa! {
        jws_ecdsa_p_256_with_account("testdata/ecdsa_p-256.pem", Some(JWS_ACCOUNT_ID)) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0Iiwia2lkIjoiMDEyMzQ1NiJ9",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_384_with_account("testdata/ecdsa_p-384.pem", Some(JWS_ACCOUNT_ID)) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMzODQiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0Iiwia2lkIjoiMDEyMzQ1NiJ9",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_521_with_account("testdata/ecdsa_p-521.pem", Some(JWS_ACCOUNT_ID)) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVM1MTIiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0Iiwia2lkIjoiMDEyMzQ1NiJ9",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
    }
}
