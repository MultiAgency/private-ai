//! Verifies a NEAR AI Cloud attestation report before any data is sent, per
//! docs.near.ai/cloud/verification: for the gateway and every model candidate,
//! an Intel TDX quote whose report data binds the signing key and our nonce,
//! whose MRCONFIGID is the hash of the attested compose file, and whose RTMR3
//! matches the replayed event log; for the model, NVIDIA's signed verdict on
//! its GPUs for the same nonce. Port of `core/attest.mjs`.
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use dcap_qvl::configs::DefaultConfig;
use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::QuoteCollateralV3;
use p384::ecdsa::signature::Verifier;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

/// The model reads the data, so its platform must be fully patched, unless the
/// run's policy opts in to a pending update, which every review and receipt
/// then states.
pub const MODEL_TCB: &[&str] = &["UpToDate"];
/// Under E2EE the gateway relays ciphertext only. Its quote must still verify
/// and bind our nonce, but a pending platform patch there does not expose
/// data. This is also the most a model may be allowed: never Revoked or Unknown.
pub const GATEWAY_TCB: &[&str] = &[
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
];

pub const NRAS: &str = "https://nras.attestation.nvidia.com";

/// What a quote verifier reports about one TDX quote.
pub struct Verified {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report_data: [u8; 64],
    pub mr_config_id: [u8; 48],
    pub rt_mr3: [u8; 48],
    pub debug: bool,
}

/// Verifies a quote against Intel collateral at `now` (Unix seconds).
pub fn verify_quote(quote: &[u8], collateral: &QuoteCollateralV3, now: u64) -> Result<Verified> {
    let verified = QuoteVerifier::new_prod().with_config::<DefaultConfig>().verify(quote, collateral, now)?;
    let td = verified.report.as_td10().ok_or_else(|| anyhow!("expected a TDX quote"))?;
    Ok(Verified {
        status: verified.status,
        advisory_ids: verified.advisory_ids,
        report_data: td.report_data,
        mr_config_id: td.mr_config_id,
        rt_mr3: td.rt_mr3,
        debug: td.td_attributes[0] & 1 == 1,
    })
}

/// Where the NVIDIA verdict and keys come from: the attestation service for a
/// live run; for a receipt, the verdict it recorded.
pub trait Nvidia {
    fn token(&self, payload: &Value) -> Result<String>;
    fn keys(&self) -> Result<Vec<Value>>;
}

pub struct Options<'a> {
    pub verify_quote: &'a dyn Fn(&[u8]) -> Result<Verified>,
    pub nvidia: &'a dyn Nvidia,
    pub gpu_token: Option<&'a str>,
    pub allow_unpatched_model: bool,
}

/// What the receipt and the review state about one verified report.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub tcb: String,
    pub advisories: Vec<String>,
    pub signer: String,
    pub compose_hash: String,
}

#[derive(Clone, Debug)]
pub struct Model {
    pub summary: Summary,
    pub gpu_token: String,
    /// The NVIDIA key that signed the verdict, with its certificate chain.
    pub gpu_key: Value,
    pub public_key: String,
}

#[derive(Clone, Debug)]
pub struct Attestation {
    pub gateway: Summary,
    pub model: Model,
}

/// A JSON field that NEAR AI sends either as an object or as a JSON string of one.
fn parse(value: &Value) -> Result<Value> {
    match value {
        Value::String(text) => Ok(serde_json::from_str(text)?),
        other => Ok(other.clone()),
    }
}

pub fn replay_rtmr3(event_log: &Value) -> Result<[u8; 48]> {
    let mut rtmr3 = [0u8; 48];
    for event in parse(event_log)?.as_array().into_iter().flatten() {
        if event["imr"].as_u64() != Some(3) {
            continue;
        }
        let mut hasher = Sha384::new();
        hasher.update((event["event_type"].as_u64().unwrap_or(0) as u32).to_le_bytes());
        hasher.update(b":");
        hasher.update(event["event"].as_str().unwrap_or("").as_bytes());
        hasher.update(b":");
        hasher.update(crate::bytes(event["event_payload"].as_str().unwrap_or(""))?);
        let digest = hasher.finalize();
        if let Some(recorded) = event["digest"].as_str().filter(|d| !d.is_empty()) {
            if crate::bytes(recorded)? != digest.as_slice() {
                bail!("event log digest mismatch for {}", event["event"].as_str().unwrap_or(""));
            }
        }
        let mut extend = Sha384::new();
        extend.update(rtmr3);
        extend.update(digest);
        rtmr3.copy_from_slice(&extend.finalize());
    }
    Ok(rtmr3)
}

/// The TDX checks on one report; returns what the receipt records.
pub fn check_report(report: &Value, nonce: &str, accepted: &[&str], verify_quote: &dyn Fn(&[u8]) -> Result<Verified>) -> Result<Summary> {
    let quote = report["intel_quote"].as_str().ok_or_else(|| anyhow!("no Intel quote"))?;
    let verified = verify_quote(&crate::bytes(quote)?)?;
    if !accepted.contains(&verified.status.as_str()) {
        let advisories = if verified.advisory_ids.is_empty() { "no advisories".to_string() } else { verified.advisory_ids.join(", ") };
        bail!("TCB status {} not accepted ({advisories})", verified.status);
    }
    if verified.debug {
        bail!("TDX debug mode is enabled");
    }

    if report["signing_algo"].as_str() != Some("ed25519") {
        bail!("unexpected signing algorithm {}", report["signing_algo"]);
    }
    let signer = report["signing_address"].as_str().unwrap_or("");
    let identity = crate::bytes(signer).unwrap_or_default();
    if identity.len() != 32 {
        bail!("malformed signing address");
    }
    let bound = match report["tls_cert_fingerprint"].as_str().filter(|f| !f.is_empty()) {
        Some(fingerprint) => Sha256::new().chain_update(&identity).chain_update(crate::bytes(fingerprint)?).finalize().to_vec(),
        None => identity,
    };
    let expected: Vec<u8> = [bound, crate::bytes(nonce)?].concat();
    if verified.report_data.as_slice() != expected.as_slice() {
        bail!("report data does not bind the signer and nonce");
    }
    if report["request_nonce"].as_str().map(str::to_lowercase).as_deref() != Some(nonce) {
        bail!("echoed nonce does not match");
    }

    let tcb_info = parse(&report["info"]["tcb_info"])?;
    let compose = tcb_info["app_compose"].as_str().ok_or_else(|| anyhow!("no compose file attested"))?;
    let compose_hash = Sha256::digest(compose.as_bytes());
    let mut mr_config_id = [0u8; 48];
    mr_config_id[0] = 1;
    mr_config_id[1..33].copy_from_slice(&compose_hash);
    if verified.mr_config_id != mr_config_id {
        bail!("MRCONFIGID does not match the attested compose file");
    }
    if replay_rtmr3(&report["event_log"])? != verified.rt_mr3 {
        bail!("event log does not match RTMR3");
    }

    Ok(Summary {
        tcb: verified.status,
        advisories: verified.advisory_ids,
        signer: signer.to_string(),
        compose_hash: hex::encode(compose_hash),
    })
}

fn base64url(text: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim_end_matches('='))?)
}

/// Checks NVIDIA's signature on the verdict, its issuer, its result and our
/// nonce. Returns the key that signed it, for the receipt to keep.
pub fn check_nvidia_token(token: &str, nonce: &str, keys: &[Value]) -> Result<Value> {
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("NVIDIA verdict is not a JWT");
    };
    let head: Value = serde_json::from_slice(&base64url(header)?)?;
    let key = keys.iter().find(|k| k["kid"] == head["kid"]);
    let (Some("ES384"), Some(key)) = (head["alg"].as_str(), key) else {
        bail!("NVIDIA verdict is not signed by a published NVIDIA key");
    };
    // JOSE allows either of an ECDSA signature's two valid S values; NVIDIA uses both.
    let valid = (|| {
        let point = [vec![4u8], base64url(key["x"].as_str()?).ok()?, base64url(key["y"].as_str()?).ok()?].concat();
        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok()?;
        let signature = p384::ecdsa::Signature::from_slice(&base64url(signature).ok()?).ok()?;
        Some(key.verify(format!("{header}.{claims}").as_bytes(), &signature).is_ok())
    })();
    if valid != Some(true) {
        bail!("NVIDIA verdict has an invalid signature");
    }
    let verdict: Value = serde_json::from_slice(&base64url(claims)?)?;
    if verdict["iss"].as_str() != Some(NRAS) {
        bail!("NVIDIA verdict has the wrong issuer");
    }
    let verdict_nonce = match &verdict["eat_nonce"] {
        Value::String(s) => s.to_lowercase(),
        other => other.to_string(),
    };
    if verdict_nonce != nonce {
        bail!("NVIDIA verdict is for another nonce");
    }
    if verdict["x-nvidia-overall-att-result"] != Value::Bool(true) {
        bail!("NVIDIA did not attest the GPUs");
    }
    Ok(key.clone())
}

fn check_model(candidate: &Value, nonce: &str, options: &Options) -> Result<Model> {
    let accepted = if options.allow_unpatched_model { GATEWAY_TCB } else { MODEL_TCB };
    let summary = check_report(candidate, nonce, accepted, options.verify_quote)?;
    if candidate["nvidia_payload"].is_null() || candidate["nvidia_payload"] == "" {
        bail!("no GPU evidence");
    }
    let payload = parse(&candidate["nvidia_payload"])?;
    let payload_nonce = match &payload["nonce"] {
        Value::String(s) => s.to_lowercase(),
        other => other.to_string(),
    };
    if payload_nonce != nonce {
        bail!("GPU evidence does not bind the nonce");
    }
    let token = match options.gpu_token {
        Some(token) => token.to_string(),
        None => options.nvidia.token(&payload)?,
    };
    let gpu_key = check_nvidia_token(&token, nonce, &options.nvidia.keys()?)?;
    let public_key = candidate["signing_public_key"].as_str().unwrap_or("");
    if public_key.to_lowercase() != summary.signer.to_lowercase() {
        bail!("encryption key is not the attested signing key");
    }
    Ok(Model { summary, gpu_token: token, gpu_key, public_key: public_key.to_string() })
}

/// Checks the gateway and every model candidate, and returns the gateway
/// summary plus the first verified model, whose key the run encrypts to.
pub fn verify_attestation(body: &Value, nonce: &str, options: &Options) -> Result<Attestation> {
    let gateway = check_report(&body["gateway_attestation"], nonce, GATEWAY_TCB, options.verify_quote).map_err(|e| anyhow!("gateway: {e}"))?;
    let candidates = body["model_attestations"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if candidates.is_empty() {
        bail!("no model evidence returned");
    }
    let mut failures = Vec::new();
    for candidate in candidates {
        match check_model(candidate, nonce, options) {
            Ok(model) => return Ok(Attestation { gateway, model }),
            Err(e) => failures.push(e.to_string()),
        }
    }
    bail!("model: {}", failures.join("; "))
}

/// A recorded set of collateral, tried in turn: what checking a receipt offline uses.
pub fn verify_with_recorded(quote: &[u8], collateral: &[QuoteCollateralV3], now: u64) -> Result<Verified> {
    let mut last = anyhow!("no collateral recorded");
    for c in collateral {
        match verify_quote(quote, c, now) {
            Ok(verified) => return Ok(verified),
            Err(e) => last = e,
        }
    }
    Err(last).context("quote")
}
