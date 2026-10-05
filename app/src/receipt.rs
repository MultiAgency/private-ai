//! A receipt: what a private run proves, in a form anyone can re-check with
//! `core/verify.mjs` or the page. It holds the attestation evidence, the nonce
//! it binds, NVIDIA's signed verdict on the model's GPUs, and each turn's
//! request and response hashes with the model enclave's signature; no request
//! or response bytes. Port of `core/receipt.mjs`.
use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::attest::{verify_attestation, Attestation, Nvidia, Options, Verified};
use crate::sign::{check_signature, sha256, signed_text};

pub const RECEIPT_VERSION: u64 = 1;

/// What a live attestation leaves for the receipt.
pub struct Evidence {
    pub nonce: String,
    pub report: Value,
    pub gpu_token: String,
    pub allow_unpatched_model: bool,
}

/// `subject` names what the run was about, e.g. a pull request and its commits.
/// Returns the receipt text and its SHA-256.
pub fn receipt(subject: &Value, model: &str, evidence: &Evidence, turns: &[Value], created_at: &str) -> (String, String) {
    let text = serde_json::to_string_pretty(&json!({
        "version": RECEIPT_VERSION,
        "subject": subject,
        "model": model,
        "created_at": created_at,
        "nonce": evidence.nonce,
        "attestation": evidence.report,
        "gpu_token": evidence.gpu_token,
        "policy": { "allow_unpatched_model": evidence.allow_unpatched_model },
        "turns": turns,
    }))
    .expect("receipt serializes");
    let hash = sha256(text.as_bytes());
    (text, hash)
}

/// Receipt version 2, written by the hosted App. Two differences from version 1:
/// - the pull request is not named, only committed to: `subject_sha256` is the
///   SHA-256 of `salt:canonical(subject)`, and the salt reaches only the review's
///   readers (the link in the review). The receipt is public; the repository may not be.
/// - `outlayer` lists every OutLayer run of the job by call id with what it
///   returned, so a checker can fetch each run's attestation and see that our
///   build fetched the evidence, took every signed turn, and wrote this receipt.
///   The last run's output is not listed: it carries this receipt's own hash,
///   and the checker rebuilds it from the receipt.
pub fn receipt_v2(subject_sha256: &str, model: &str, evidence: &Evidence, turns: &[Value], created_at: &str, outlayer: &Value) -> (String, String) {
    let text = serde_json::to_string_pretty(&json!({
        "version": 2,
        "subject_sha256": subject_sha256,
        "model": model,
        "created_at": created_at,
        "nonce": evidence.nonce,
        "attestation": evidence.report,
        "gpu_token": evidence.gpu_token,
        "policy": { "allow_unpatched_model": evidence.allow_unpatched_model },
        "turns": turns,
        "outlayer": outlayer,
    }))
    .expect("receipt serializes");
    let hash = sha256(text.as_bytes());
    (text, hash)
}

/// What a turn record is to the steps that took it: its hash, as the step's attested output lists it.
pub fn turn_hash(record: &Value) -> String {
    sha256(crate::canonical(record).as_bytes())
}

/// The commitment a version 2 receipt makes to its pull request.
pub fn subject_commitment(salt: &str, subject: &Value) -> String {
    sha256(format!("{salt}:{}", crate::canonical(subject)).as_bytes())
}

/// The recorded verdict, checked against the keys the verifier is given.
struct Recorded<'a> {
    keys: &'a dyn Fn() -> Result<Vec<Value>>,
}

impl Nvidia for Recorded<'_> {
    fn token(&self, _: &Value) -> Result<String> {
        bail!("a receipt is checked against the verdict it recorded")
    }
    fn keys(&self) -> Result<Vec<Value>> {
        (self.keys)()
    }
}

pub struct Checked {
    pub receipt: Value,
    pub sha256: String,
    pub attestation: Attestation,
}

/// Re-runs the attestation checks on the recorded evidence and checks every
/// response signature against the attested model key. Fails on the first problem.
pub fn verify_receipt(text: &str, verify_quote: &dyn Fn(&[u8]) -> Result<Verified>, nvidia_keys: &dyn Fn() -> Result<Vec<Value>>) -> Result<Checked> {
    let receipt: Value = serde_json::from_str(text)?;
    if receipt["version"].as_u64() != Some(RECEIPT_VERSION) {
        bail!("unknown receipt version {}", receipt["version"]);
    }
    let Some(gpu_token) = receipt["gpu_token"].as_str().filter(|t| !t.is_empty()) else {
        bail!("no NVIDIA verdict recorded");
    };
    let attestation = verify_attestation(
        &receipt["attestation"],
        receipt["nonce"].as_str().unwrap_or(""),
        &Options {
            verify_quote,
            nvidia: &Recorded { keys: nvidia_keys },
            gpu_token: Some(gpu_token),
            allow_unpatched_model: receipt["policy"]["allow_unpatched_model"] == Value::Bool(true),
        },
    )?;
    let turns = receipt["turns"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if turns.is_empty() {
        bail!("no signed turns");
    }
    let model = receipt["model"].as_str().unwrap_or("");
    for turn in turns {
        let text = signed_text(model, turn["request_sha256"].as_str().unwrap_or(""), turn["response_sha256"].as_str().unwrap_or(""));
        check_signature(&turn["signature"], &text, &attestation.model.public_key)?;
    }
    Ok(Checked { sha256: sha256(text.as_bytes()), receipt, attestation })
}

/// What a verified run proves, as (label, text) pairs with code in backticks.
/// The review's proof block, the page and the CLI all state exactly these.
pub fn proven_claims(model_name: &str, model: &crate::attest::Summary, gateway: &crate::attest::Summary, turns: usize) -> Vec<(String, String)> {
    let pending = |tcb: &str, who: &str| if tcb == "UpToDate" { String::new() } else { format!(" (an Intel platform update is pending, which {who})") };
    vec![
        ("Model".into(), format!(
            "`{model_name}` in an Intel TDX enclave with NVIDIA confidential GPUs. Quote verified, TCB {}{}, debug off; it binds signing key `{}` and this run's nonce. Compose hash `{}`.",
            model.tcb, pending(&model.tcb, "this repository's policy allows for the model"), model.signer, model.compose_hash
        )),
        ("GPUs".into(), "NVIDIA's signed verdict approves them for the same nonce.".into()),
        ("Gateway".into(), format!(
            "Quote verified, TCB {}{}. It relayed only end-to-end encrypted content.",
            gateway.tcb, pending(&gateway.tcb, "the check allows for the gateway only")
        )),
        ("Signed".into(), format!("{turns} of {turns} responses signed by the model enclave's key, over the exact request and response bytes.")),
    ]
}
