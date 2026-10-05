//! Response signatures from NEAR AI Cloud: the model's enclave signs
//! "<model>:<sha256 of the exact request bytes>:<sha256 of the exact response
//! bytes>" with the key its attestation report bound. Port of `core/sign.mjs`.
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Hex SHA-256 of bytes.
pub fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn signed_text(model: &str, request_sha256: &str, response_sha256: &str) -> String {
    format!("{model}:{request_sha256}:{response_sha256}")
}

pub fn check_signature(signature: &Value, expected_text: &str, signer: &str) -> Result<()> {
    match signature["signature_kind"].as_str() {
        Some("provider_tee") => {}
        kind => bail!("signed by {}, not the model enclave", kind.unwrap_or("nobody")),
    }
    if signature["signing_algo"].as_str() != Some("ed25519") {
        bail!("unexpected signing algorithm {}", signature["signing_algo"]);
    }
    if signature["text"].as_str() != Some(expected_text) {
        bail!("signature does not cover the exact request and response");
    }
    if signature["signing_address"].as_str().map(str::to_lowercase) != Some(signer.to_lowercase()) {
        bail!("signed by a key other than the attested one");
    }
    let valid = (|| {
        let key = VerifyingKey::from_bytes(&crate::bytes(signer).ok()?.try_into().ok()?).ok()?;
        let signature = Signature::from_slice(&crate::bytes(signature["signature"].as_str()?).ok()?).ok()?;
        Some(key.verify(expected_text.as_bytes(), &signature).is_ok())
    })();
    if valid != Some(true) {
        bail!("invalid signature");
    }
    Ok(())
}
