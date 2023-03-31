use super::responses::Jws;
use crate::error::{Error, Result};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use openssl::{
    bn::{BigNum, BigNumContext},
    ecdsa::EcdsaSig,
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Private},
    sha::{sha256, sha384, sha512},
    sign::Signer,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};

/// Possible algorithms a JWS can be signed with. Ignores algorithms explicitly denied by
/// [RFC 8555 Section 6.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2), namely:
/// `none` and MAC-based algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum Algorithm {
    // only for use by sign_with_eab
    HS256,
    RS256,
    // TODO: eventually support RS384 and RS512
    ES256,
    ES384,
    ES512,
    // TODO: eventually support PS256, PS384, and PS512
}

impl TryFrom<&PKey<Private>> for Algorithm {
    type Error = Error;

    fn try_from(key: &PKey<Private>) -> Result<Self, Self::Error> {
        match key.id() {
            Id::RSA => Ok(Algorithm::RS256),
            Id::EC => {
                let ec = key.ec_key()?;
                match ec.group().curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => Ok(Algorithm::ES256),
                    Some(Nid::SECP384R1) => Ok(Algorithm::ES384),
                    Some(Nid::SECP521R1) => Ok(Algorithm::ES512),
                    _ => Err(Error::UnsupportedECDSACurve),
                }
            }
            _ => Err(Error::UnsupportedKeyType),
        }
    }
}

/// The header of a JSON Web Signature according to
/// [RFC 8555 Section 6.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2)
#[derive(Debug, Serialize)]
struct Header<'h> {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    url: &'h str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'h str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum Curve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

impl TryFrom<Nid> for Curve {
    type Error = Error;

    fn try_from(group: Nid) -> Result<Self, Self::Error> {
        match group {
            Nid::X9_62_PRIME256V1 => Ok(Curve::P256),
            Nid::SECP384R1 => Ok(Curve::P384),
            Nid::SECP521R1 => Ok(Curve::P521),
            _ => Err(Error::UnsupportedECDSACurve),
        }
    }
}

/// The public key of a key
#[derive(Debug)]
enum Jwk {
    Rsa { e: String, n: String },
    EC { crv: Curve, x: String, y: String },
}

impl TryFrom<&PKey<Private>> for Jwk {
    type Error = Error;

    fn try_from(key: &PKey<Private>) -> Result<Self, Self::Error> {
        match key.id() {
            Id::RSA => {
                let rsa = key.rsa()?;
                Ok(Jwk::Rsa {
                    e: BASE64.encode(rsa.e().to_vec()),
                    n: BASE64.encode(rsa.n().to_vec()),
                })
            }
            Id::EC => {
                let ec = key.ec_key()?;
                let ec_public = ec.public_key();

                let mut ctx = BigNumContext::new()?;
                let mut x = BigNum::new()?;
                let mut y = BigNum::new()?;
                ec_public.affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut ctx)?;

                let curve = ec
                    .group()
                    .curve_name()
                    .ok_or(Error::UnsupportedECDSACurve)?;

                Ok(Jwk::EC {
                    x: BASE64.encode(x.to_vec()),
                    y: BASE64.encode(y.to_vec()),
                    crv: Curve::try_from(curve)?,
                })
            }
            _ => unreachable!(),
        }
    }
}

// We manually implement serialization to ensure lexicographical ordering of the fields per
// RFC 7638 Section 3 (https://www.rfc-editor.org/rfc/rfc7638#section-3)
impl Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 1 + number of fields taking into account the `kty`
        let (fields, kty) = match self {
            Self::Rsa { .. } => (3, "RSA"),
            Self::EC { .. } => (4, "EC"),
        };

        let mut state = serializer.serialize_struct("Jwk", fields)?;
        match self {
            Self::Rsa { e, n } => {
                state.serialize_field("e", e)?;
                state.serialize_field("kty", kty)?;
                state.serialize_field("n", n)?;
            }
            Self::EC { crv, x, y } => {
                state.serialize_field("crv", crv)?;
                state.serialize_field("kty", kty)?;
                state.serialize_field("x", x)?;
                state.serialize_field("y", y)?;
            }
        }
        state.end()
    }
}

/// Create a JWS for the request
pub(crate) fn sign(
    url: &str,
    nonce: String,
    payload: &str,
    private_key: &PKey<Private>,
    account_id: Option<&str>,
) -> Result<Jws> {
    let payload = BASE64.encode(payload.as_bytes());

    let algorithm = Algorithm::try_from(private_key)?;
    let header = match account_id {
        Some(kid) => Header {
            algorithm,
            url,
            nonce: Some(nonce),
            kid: Some(kid),
            jwk: None,
        },
        None => Header {
            algorithm,
            url,
            nonce: Some(nonce),
            kid: None,
            jwk: Some(Jwk::try_from(private_key)?),
        },
    };

    let protected = serde_json::to_vec(&header).unwrap();
    let protected = BASE64.encode(protected);

    let signature = signer(private_key, &protected, &payload)?;
    let signature = BASE64.encode(signature);

    Ok(Jws {
        protected,
        payload,
        signature,
    })
}

/// Generate the signature for the protected data and message payload
fn signer(private_key: &PKey<Private>, protected: &str, payload: &str) -> Result<Vec<u8>> {
    let data = format!("{protected}.{payload}").into_bytes();

    match private_key.id() {
        Id::RSA => {
            let sig =
                Signer::new(MessageDigest::sha256(), private_key)?.sign_oneshot_to_vec(&data)?;
            Ok(sig)
        }
        Id::EC => {
            let ec = private_key.ec_key()?;
            let digest = match ec.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => sha256(&data).to_vec(),
                Some(Nid::SECP384R1) => sha384(&data).to_vec(),
                Some(Nid::SECP521R1) => sha512(&data).to_vec(),
                _ => unreachable!(),
            };

            let sig = EcdsaSig::sign(&digest, &ec)?;
            let r = sig.r().to_vec();
            let s = sig.s().to_vec();

            let mut result = Vec::with_capacity(r.len() + s.len());
            result.extend_from_slice(&r);
            result.extend_from_slice(&s);
            Ok(result)
        }
        _ => Err(Error::UnsupportedKeyType),
    }
}

/// Sign the provided private key with the provided Base64 URL-encoded HMAC and associated key ID
pub(crate) fn sign_with_eab(
    url: &str,
    private_key: &PKey<Private>,
    kid: &str,
    hmac: &str,
) -> Result<Jws> {
    let header = Header {
        url,
        algorithm: Algorithm::HS256,
        kid: Some(kid),
        nonce: None,
        jwk: None,
    };
    let protected = BASE64.encode(serde_json::to_vec(&header).unwrap());

    let jwk = Jwk::try_from(private_key)?;
    let payload = BASE64.encode(serde_json::to_vec(&jwk).unwrap());

    let data = format!("{protected}.{payload}").into_bytes();

    let hmac = BASE64.decode(hmac)?;
    let key = PKey::hmac(&hmac)?;
    let signature = Signer::new(MessageDigest::sha256(), &key)?.sign_oneshot_to_vec(&data)?;
    let signature = BASE64.encode(signature);

    Ok(Jws {
        protected,
        payload,
        signature,
    })
}

/// Generate the key authorization for the token and private key
pub(crate) fn key_authorization(token: &str, private_key: &PKey<Private>) -> Result<String> {
    let jwk = Jwk::try_from(private_key)?;
    let serialized = serde_json::to_vec(&jwk).unwrap();
    let digest = hash(MessageDigest::sha256(), &serialized)?;
    let thumbprint = BASE64.encode(digest);

    Ok(format!("{token}.{thumbprint}"))
}

#[cfg(test)]
mod tests {
    use super::{key_authorization, sign, sign_with_eab, Curve, Jwk};
    use openssl::pkey::PKey;
    use std::fs;

    #[test]
    fn jwk_rsa() {
        let pem = fs::read("testdata/rsa_2048.pem").unwrap();
        let key = PKey::private_key_from_pem(&pem).unwrap();

        let jwk = Jwk::try_from(&key).unwrap();

        let Jwk::Rsa { n: n_b64, e: e_b64 } = jwk else { panic!("not rsa jwk") };
        assert_eq!(n_b64, "y2McwrH7NMy4y-0iMBTNLWIBcvLi-_i8_sTJVaIRbsAp3rYhFFx2v_79ETp3hqquU23brJjPgYV-hdcB7lwq4ssZPD2zzvzEnLfuh0Ldsnuy_oQIKGtOvb48lqZ4c094k-TFLVhApBjkdBaJ-rhb7iM1xk3SXLWb2xBrz1iXV-okfXao9N5kV0azOZ3Spfr2HPLSEDUQrg4RW01BZe3zZtKu7TJUnlICeLJd_rexMizWx8iIzYX-NayhXSSp1yeXPRfk5ZnlhrGCu6ywmhmu7QA3dou77WxN2EzAUJAoiIuxLpCSeQV4XxnDEe4o88U9_PI1f6xBKdcfR0_HeBut3w");
        assert_eq!(e_b64, "AQAB");
    }

    macro_rules! jwk_ecdsa {
        (
            $(
                $name:ident ($file:expr) => {
                    crv: $crv:ident,
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
                    assert_eq!(crv, Curve::$crv);
                    assert_eq!(x_b64, $x);
                    assert_eq!(y_b64, $y);
                }
            )*
        };
    }

    jwk_ecdsa! {
        jwk_ecdsa_p_256("testdata/ecdsa_p-256.pem") => {
            crv: P256,
            x: "bFFJEKk0HrAyTVz69iCiV8KsX1bNwSx60o6Xlat9hPo",
            y: "fsxkWwspm4NA2lUWIf9DwlrOQgf2Y610ynAwJP_Gx0E",
        };
        jwk_ecdsa_p_384("testdata/ecdsa_p-384.pem") => {
            crv: P384,
            x: "MDD68TroskBcnk49wd7UI1nLI4o9q9DJH0P29ibkAb6AzLxg0mIu1U3NwUTKUf_l",
            y: "HldntIAzF67Nd-jfTDaiJxa0WMVHcZ5at_AQkxtT6aCu5jQ1zSKcPvVnj1Sv3JT2",
        };
        jwk_ecdsa_p_521("testdata/ecdsa_p-521.pem") => {
            crv: P521,
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

        assert_eq!(sig.protected, "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiUlMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7ImUiOiJBUUFCIiwia3R5IjoiUlNBIiwibiI6InkyTWN3ckg3Tk15NHktMGlNQlROTFdJQmN2TGktX2k4X3NUSlZhSVJic0FwM3JZaEZGeDJ2Xzc5RVRwM2hxcXVVMjNickpqUGdZVi1oZGNCN2x3cTRzc1pQRDJ6enZ6RW5MZnVoMExkc251eV9vUUlLR3RPdmI0OGxxWjRjMDk0ay1URkxWaEFwQmprZEJhSi1yaGI3aU0xeGszU1hMV2IyeEJyejFpWFYtb2tmWGFvOU41a1YwYXpPWjNTcGZyMkhQTFNFRFVRcmc0UlcwMUJaZTN6WnRLdTdUSlVubElDZUxKZF9yZXhNaXpXeDhpSXpZWC1OYXloWFNTcDF5ZVhQUmZrNVpubGhyR0N1Nnl3bWhtdTdRQTNkb3U3N1d4TjJFekFVSkFvaUl1eExwQ1NlUVY0WHhuREVlNG84OFU5X1BJMWY2eEJLZGNmUjBfSGVCdXQzdyJ9fQ");
        assert_eq!(sig.payload, "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA");
        assert_eq!(sig.signature, "vkUiuNTwtrHBDu69ajBQ1jhuqlIDDMnm57gwI7DQs8ljSXuSrWft8W5pUbsIe50TT6XXRmSnc3__XviADvarwhqhqJbfgr1NE66n3wUlRWc6uC7b7POaGlIs9vaWN_WfgtSzYwX6NtS5qfo4tY7hRH0wTD1R6gx3Vyb910JuA1boJNTazlD7sl6npCA5LXUQCnQQx5NHZl5vZs-xTYYQVlefgXdox-IP0qWvR1hCdTNiosFQTLIlLvF9wp13cADAplUQvynacxLQbrrn2dzSAXjCm9rPZty4lq0npvwQIQS9AaXVT7Nfbz_urIAO5Qlx89JbmFdS4VvzZdOUxk9lhA");
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

                    let sig = sign(JWS_URL, String::from(JWS_NONCE), JWS_PAYLOAD, &key, $acct).unwrap();

                    assert_eq!(sig.protected, $protected);
                    assert_eq!(sig.payload, $payload);
                    assert!(!sig.signature.is_empty());
                }
            )*
        };
    }

    jws_ecdsa! {
        jws_ecdsa_p_256_without_account("testdata/ecdsa_p-256.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMyNTYiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiYkZGSkVLazBIckF5VFZ6NjlpQ2lWOEtzWDFiTndTeDYwbzZYbGF0OWhQbyIsInkiOiJmc3hrV3dzcG00TkEybFVXSWY5RHdsck9RZ2YyWTYxMHluQXdKUF9HeDBFIn19",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_384_without_account("testdata/ecdsa_p-384.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVMzODQiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7ImNydiI6IlAtMzg0Iiwia3R5IjoiRUMiLCJ4IjoiTURENjhUcm9za0Jjbms0OXdkN1VJMW5MSTRvOXE5REpIMFAyOWlia0FiNkF6THhnMG1JdTFVM053VVRLVWZfbCIsInkiOiJIbGRudElBekY2N05kLWpmVERhaUp4YTBXTVZIY1o1YXRfQVFreHRUNmFDdTVqUTF6U0tjUHZWbmoxU3YzSlQyIn19",
            payload: "dGhpcyBpcyBhIHRlc3QgcGF5bG9hZA",
        };
        jws_ecdsa_p_521_without_account("testdata/ecdsa_p-521.pem", None) => {
            protected: "eyJub25jZSI6IkEyNzJWRnB2QzFlN0gwWVoxNF8tZkxsYnQ5R2c4YlItZEd0bDBQcWp1R1hfLW84IiwiYWxnIjoiRVM1MTIiLCJ1cmwiOiJodHRwczovL2FjbWUtc3RhZ2luZy12MDIuYXBpLmxldHNlbmNyeXB0Lm9yZy9hY21lL25ldy1hY2N0IiwiandrIjp7ImNydiI6IlAtNTIxIiwia3R5IjoiRUMiLCJ4IjoiQWQyN01pSmdPb2JCS0ZPX1l5QXk2bVFfRHoydUdMRjBVRDMtTWtGNGhMYTVaX19SQ3JObXRpZGpRNUZXNjR3YWhmekxlUWFtRUFfS0FUaDJ6RkJOaFNNMCIsInkiOiJBVXlnNFh1bW9iRXFhUENqVUdDOU1jOFNFMnNhVXJZVmQ4MjRJczFlcmNQanBxNVd4M0hFLUkySHZidExtbTI5VVgzVDVJa0htS1JiUElhN29COE9vNlBMIn19",
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

    macro_rules! test_key_authorization {
        (
            $(
                $name:ident($key:expr) => $signature:expr
            );+ $(;)?
        ) => {
            $(
                #[test]
                fn $name() {
                    let pem = fs::read($key).unwrap();
                    let key = PKey::private_key_from_pem(&pem).unwrap();

                    let authorization = key_authorization("testing-token", &key).unwrap();
                    let parts = authorization.split('.').collect::<Vec<_>>();
                    assert_eq!(*parts.first().unwrap(), "testing-token");
                    assert_eq!(*parts.last().unwrap(), $signature);
                }
            )*
        };
    }

    test_key_authorization! {
        key_authorization_rsa("testdata/rsa_2048.pem") => "1tYs-daa88-j-PKKVXr1fsygMDlxk5sIYgcWzLl7zU8";
        key_authorization_ecdsa_p_256("testdata/ecdsa_p-256.pem") => "uuIRg-39HHLblKbBUmg1XIT63ZynnLhCXvLJKY9Edew";
        key_authorization_ecdsa_p_384("testdata/ecdsa_p-384.pem") => "t4pPjjyfZL9xx_bWqd79c5ucdOLixBtukSr58OiZhjI";
        key_authorization_ecdsa_p_521("testdata/ecdsa_p-521.pem") => "c_7slHmYt2at4zV8Em-l1_yisd2s0Exvs8XDPsX11XI";
    }

    static EAB_URL: &str = "https://10.30.50.2:14000/sign-me-up";
    static EAB_KID: &str = "V6iRR0p3";
    static EAB_HMAC: &str = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W";

    macro_rules! test_sign_with_eab {
        (
            $(
                $name:ident($file:expr) => {
                    protected: $protected:expr,
                    payload: $payload:expr,
                    signature: $signature:expr,
                }
            );+ $(;)?
        ) => {
            $(
                #[test]
                fn $name() {
                    let pem = fs::read($file).unwrap();
                    let key = PKey::private_key_from_pem(&pem).unwrap();

                    let sig = sign_with_eab(EAB_URL, &key, EAB_KID, EAB_HMAC).unwrap();
                    assert_eq!(sig.protected, $protected);
                    assert_eq!(sig.payload, $payload);
                    assert_eq!(sig.signature, $signature);
                }
            )*
        };
    }

    test_sign_with_eab! {
        sign_with_eab_rsa("testdata/rsa_2048.pem") => {
            protected: "eyJhbGciOiJIUzI1NiIsInVybCI6Imh0dHBzOi8vMTAuMzAuNTAuMjoxNDAwMC9zaWduLW1lLXVwIiwia2lkIjoiVjZpUlIwcDMifQ",
            payload: "eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ5Mk1jd3JIN05NeTR5LTBpTUJUTkxXSUJjdkxpLV9pOF9zVEpWYUlSYnNBcDNyWWhGRngydl83OUVUcDNocXF1VTIzYnJKalBnWVYtaGRjQjdsd3E0c3NaUEQyenp2ekVuTGZ1aDBMZHNudXlfb1FJS0d0T3ZiNDhscVo0YzA5NGstVEZMVmhBcEJqa2RCYUotcmhiN2lNMXhrM1NYTFdiMnhCcnoxaVhWLW9rZlhhbzlONWtWMGF6T1ozU3BmcjJIUExTRURVUXJnNFJXMDFCWmUzelp0S3U3VEpVbmxJQ2VMSmRfcmV4TWl6V3g4aUl6WVgtTmF5aFhTU3AxeWVYUFJmazVabmxockdDdTZ5d21obXU3UUEzZG91NzdXeE4yRXpBVUpBb2lJdXhMcENTZVFWNFh4bkRFZTRvODhVOV9QSTFmNnhCS2RjZlIwX0hlQnV0M3cifQ",
            signature: "XXK6TYRI_-kjlMraYSXqYaIBqks2eSB9JANqt-Vv0tw",
        };
        sign_with_eab_ecdsa_p_256("testdata/ecdsa_p-256.pem") => {
            protected: "eyJhbGciOiJIUzI1NiIsInVybCI6Imh0dHBzOi8vMTAuMzAuNTAuMjoxNDAwMC9zaWduLW1lLXVwIiwia2lkIjoiVjZpUlIwcDMifQ",
            payload: "eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImJGRkpFS2swSHJBeVRWejY5aUNpVjhLc1gxYk53U3g2MG82WGxhdDloUG8iLCJ5IjoiZnN4a1d3c3BtNE5BMmxVV0lmOUR3bHJPUWdmMlk2MTB5bkF3SlBfR3gwRSJ9",
            signature: "sXYXLVwqpVIx1bZngZ0ORvFR_kvETi9kFyIdFwQXlm8",
        };
        sign_with_eab_ecdsa_p_384("testdata/ecdsa_p-384.pem") => {
            protected: "eyJhbGciOiJIUzI1NiIsInVybCI6Imh0dHBzOi8vMTAuMzAuNTAuMjoxNDAwMC9zaWduLW1lLXVwIiwia2lkIjoiVjZpUlIwcDMifQ",
            payload: "eyJjcnYiOiJQLTM4NCIsImt0eSI6IkVDIiwieCI6Ik1ERDY4VHJvc2tCY25rNDl3ZDdVSTFuTEk0bzlxOURKSDBQMjlpYmtBYjZBekx4ZzBtSXUxVTNOd1VUS1VmX2wiLCJ5IjoiSGxkbnRJQXpGNjdOZC1qZlREYWlKeGEwV01WSGNaNWF0X0FRa3h0VDZhQ3U1alExelNLY1B2Vm5qMVN2M0pUMiJ9",
            signature: "pX34eEDN2QZL0fuRi7qJnewPo5oomVCDrZ2Y-kXSdwE",
        };
        sign_with_eab_ecdsa_p_521("testdata/ecdsa_p-521.pem") => {
            protected: "eyJhbGciOiJIUzI1NiIsInVybCI6Imh0dHBzOi8vMTAuMzAuNTAuMjoxNDAwMC9zaWduLW1lLXVwIiwia2lkIjoiVjZpUlIwcDMifQ",
            payload: "eyJjcnYiOiJQLTUyMSIsImt0eSI6IkVDIiwieCI6IkFkMjdNaUpnT29iQktGT19ZeUF5Nm1RX0R6MnVHTEYwVUQzLU1rRjRoTGE1Wl9fUkNyTm10aWRqUTVGVzY0d2FoZnpMZVFhbUVBX0tBVGgyekZCTmhTTTAiLCJ5IjoiQVV5ZzRYdW1vYkVxYVBDalVHQzlNYzhTRTJzYVVyWVZkODI0SXMxZXJjUGpwcTVXeDNIRS1JMkh2YnRMbW0yOVVYM1Q1SWtIbUtSYlBJYTdvQjhPbzZQTCJ9",
            signature: "0P6pEVQ7SZJtymoLiYKELgzRHVDeZiaVEny3DobPBeM",
        };
    }
}
