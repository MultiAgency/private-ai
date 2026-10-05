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
}
