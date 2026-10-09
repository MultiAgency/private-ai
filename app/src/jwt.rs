//! The GitHub App's JSON Web Token: RS256 over `{iat, exp, iss}`, signed with
//! the App's private key, which lives only in the enclave. GitHub trades it for
//! a one-hour installation token.
use anyhow::{Context, Result};
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use serde_json::json;

/// System randomness for RSA blinding.
struct SystemRng;

impl rand_core::RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(crate::random::<4>())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(crate::random::<8>())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("system randomness");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SystemRng {}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A token valid for nine minutes from a minute ago (GitHub allows ten, and
/// clocks drift). `issuer` is the App's client ID or numeric App ID.
pub fn app_token(issuer: &str, private_key_pem: &str, now: u64) -> Result<String> {
    let key = rsa::RsaPrivateKey::from_pkcs1_pem(private_key_pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem))
        .context("the App private key is not an RSA PEM key")?;
    let header = b64(json!({ "alg": "RS256", "typ": "JWT" }).to_string().as_bytes());
    let claims = b64(json!({ "iat": now - 60, "exp": now + 540, "iss": issuer }).to_string().as_bytes());
    let signing = format!("{header}.{claims}");
    let signature = SigningKey::<sha2::Sha256>::new(key).sign_with_rng(&mut SystemRng, signing.as_bytes());
    Ok(format!("{signing}.{}", b64(&signature.to_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    #[test]
    fn an_app_token_is_rs256_signed_and_names_the_app() {
        let key = rsa::RsaPrivateKey::new(&mut SystemRng, 2048).unwrap();
        let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let token = app_token("Iv23liExample", &pem, 1_791_000_000).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let decode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(claims, json!({ "iat": 1_790_999_940u64, "exp": 1_791_000_540u64, "iss": "Iv23liExample" }));
        let signature = Signature::try_from(decode(parts[2]).as_slice()).unwrap();
        VerifyingKey::<sha2::Sha256>::new(key.to_public_key()).verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature).unwrap();
        assert!(app_token("x", "not a key", 0).is_err());
    }

    fn parts(token: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let decode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
        let p: Vec<&str> = token.split('.').collect();
        assert_eq!(p.len(), 3);
        (serde_json::from_slice(&decode(p[0])).unwrap(), serde_json::from_slice(&decode(p[1])).unwrap(), decode(p[2]))
    }

    fn test_key() -> rsa::RsaPrivateKey {
        rsa::RsaPrivateKey::new(&mut SystemRng, 2048).unwrap()
    }

    #[test]
    fn the_header_names_rs256_and_the_token_is_unpadded_url_safe_base64() {
        let pem = test_key().to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let token = app_token("123456", &pem, 1_791_000_000).unwrap();
        assert_eq!(parts(&token).0, json!({ "alg": "RS256", "typ": "JWT" }));
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')), "{token}");
    }

    #[test]
    fn a_pkcs8_key_signs_the_same_way_as_a_pkcs1_key() {
        use rsa::pkcs8::EncodePrivateKey;
        let key = test_key();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let token = app_token("123456", &pem, 1_791_000_000).unwrap();
        let (_, claims, signature) = parts(&token);
        assert_eq!(claims["iss"], "123456");
        let signing = token.rsplit_once('.').unwrap().0;
        VerifyingKey::<sha2::Sha256>::new(key.to_public_key()).verify(signing.as_bytes(), &Signature::try_from(signature.as_slice()).unwrap()).unwrap();
    }

    #[test]
    fn a_token_is_backdated_a_minute_and_lasts_nine_more_so_it_spans_githubs_ten_at_most() {
        let pem = test_key().to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let (_, claims, _) = parts(&app_token("x", &pem, 5_000).unwrap());
        let (iat, exp) = (claims["iat"].as_u64().unwrap(), claims["exp"].as_u64().unwrap());
        assert_eq!((iat, exp), (4_940, 5_540));
        assert_eq!(exp - iat, 600);
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key_or_for_another_issuer() {
        let (key, other) = (test_key(), test_key());
        let pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        let token = app_token("1", &pem, 1_000).unwrap();
        let (_, _, signature) = parts(&token);
        let signature = Signature::try_from(signature.as_slice()).unwrap();
        let signing = token.rsplit_once('.').unwrap().0;
        assert!(VerifyingKey::<sha2::Sha256>::new(other.to_public_key()).verify(signing.as_bytes(), &signature).is_err());
        let forged = signing.replacen(signing.split('.').nth(1).unwrap(), &b64(json!({ "iat": 940, "exp": 1_540, "iss": "2" }).to_string().as_bytes()), 1);
        assert!(VerifyingKey::<sha2::Sha256>::new(key.to_public_key()).verify(forged.as_bytes(), &signature).is_err());
    }

    #[test]
    fn an_unusable_key_is_refused_with_a_message_that_does_not_echo_it() {
        for pem in ["", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"] {
            let error = app_token("1", pem, 1_000).unwrap_err();
            assert_eq!(error.to_string(), "the App private key is not an RSA PEM key");
        }
    }
}
