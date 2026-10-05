//! The Rust core against the JS core's evidence: the page's sample receipt (a
//! real review of a public pull request, written by core/receipt.mjs) and the
//! Intel collateral and NVIDIA key recorded with it (test/fixtures). Mirrors
//! test/attest.test.mjs, test/receipt.test.mjs, test/sign.test.mjs and
//! test/e2ee.test.mjs.
use anyhow::{bail, Result};
use dcap_qvl::QuoteCollateralV3;
use private_investigator::attest::{self, check_nvidia_token, verify_attestation, Nvidia, Options, Verified};
use private_investigator::e2ee::{montgomery, seal, Session};
use private_investigator::receipt::verify_receipt;
use private_investigator::sign::{check_signature, sha256, signed_text};
use serde_json::{json, Value};
use std::sync::OnceLock;

fn read(path: &str) -> String {
    std::fs::read_to_string(format!("{}/../{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Recorded {
    now: u64,
    collateral: Vec<QuoteCollateralV3>,
    keys: Vec<Value>,
}

fn recorded() -> &'static Recorded {
    static R: OnceLock<Recorded> = OnceLock::new();
    R.get_or_init(|| {
        let r: Value = serde_json::from_str(&read("test/fixtures/sample-receipt-evidence.json")).unwrap();
        Recorded {
            now: r["now"].as_u64().unwrap(),
            collateral: r["collateral"].as_object().unwrap().values().map(collateral).collect(),
            keys: r["keys"].as_array().unwrap().clone(),
        }
    })
}

/// The recorded collateral, in @phala/dcap-qvl's JSON form (byte fields as arrays).
fn collateral(c: &Value) -> QuoteCollateralV3 {
    let text = |k: &str| c[k].as_str().unwrap().to_string();
    let bytes = |k: &str| c[k].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
    QuoteCollateralV3 {
        pck_crl_issuer_chain: text("pck_crl_issuer_chain"),
        root_ca_crl: bytes("root_ca_crl"),
        pck_crl: bytes("pck_crl"),
        tcb_info_issuer_chain: text("tcb_info_issuer_chain"),
        tcb_info: text("tcb_info"),
        tcb_info_signature: bytes("tcb_info_signature"),
        qe_identity_issuer_chain: text("qe_identity_issuer_chain"),
        qe_identity: text("qe_identity"),
        qe_identity_signature: bytes("qe_identity_signature"),
        pck_certificate_chain: c["pck_certificate_chain"].as_str().map(String::from),
    }
}

fn receipt_text() -> String {
    read("site/sample-receipt.json")
}

fn receipt() -> Value {
    serde_json::from_str(&receipt_text()).unwrap()
}

fn verify_quote(quote: &[u8]) -> Result<Verified> {
    attest::verify_with_recorded(quote, &recorded().collateral, recorded().now)
}

fn with_status(status: &'static str) -> impl Fn(&[u8]) -> Result<Verified> {
    move |quote| Ok(Verified { status: status.into(), ..verify_quote(quote)? })
}

fn keys() -> Result<Vec<Value>> {
    Ok(recorded().keys.clone())
}

struct Fixed(String);
impl Nvidia for Fixed {
    fn token(&self, _: &Value) -> Result<String> {
        Ok(self.0.clone())
    }
    fn keys(&self) -> Result<Vec<Value>> {
        keys()
    }
}

fn token() -> String {
    receipt()["gpu_token"].as_str().unwrap().to_string()
}

fn nonce() -> String {
    receipt()["nonce"].as_str().unwrap().to_string()
}

fn check(body: &Value, nonce: &str, verify: &dyn Fn(&[u8]) -> Result<Verified>, allow_unpatched_model: bool) -> Result<attest::Attestation> {
    let nvidia = Fixed(token());
    verify_attestation(body, nonce, &Options { verify_quote: verify, nvidia: &nvidia, gpu_token: None, allow_unpatched_model })
}

fn body() -> Value {
    receipt()["attestation"].clone()
}

fn err(result: Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.unwrap_err())
}

#[test]
fn a_real_report_verifies_and_the_review_encrypts_to_the_attested_model_key() {
    let result = check(&body(), &nonce(), &verify_quote, false).unwrap();
    assert_eq!(result.model.summary.tcb, "UpToDate");
    assert_eq!(result.model.gpu_token, token());
    assert_eq!(result.model.public_key, body()["model_attestations"][0]["signing_public_key"].as_str().unwrap());
    assert_eq!(result.model.summary.compose_hash.len(), 64);
    assert_eq!(result.gateway.tcb, "OutOfDate");
}

#[test]
fn a_different_nonce_fails() {
    assert!(err(check(&body(), &"00".repeat(32), &verify_quote, false)).contains("report data does not bind"));
}

#[test]
fn one_changed_byte_in_the_model_quote_fails() {
    let mut b = body();
    let mut quote = hex::decode(b["model_attestations"][0]["intel_quote"].as_str().unwrap()).unwrap();
    quote[200] ^= 1;
    b["model_attestations"][0]["intel_quote"] = json!(hex::encode(quote));
    assert!(err(check(&b, &nonce(), &verify_quote, false)).starts_with("model: "));
}

#[test]
fn a_swapped_signing_key_fails_the_report_data_binding() {
    let mut b = body();
    b["model_attestations"][0]["signing_address"] = json!("11".repeat(32));
    b["model_attestations"][0]["signing_public_key"] = json!("11".repeat(32));
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("report data does not bind"));
}

#[test]
fn an_encryption_key_other_than_the_signing_key_fails() {
    let mut b = body();
    b["model_attestations"][0]["signing_public_key"] = json!("11".repeat(32));
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("encryption key is not the attested signing key"));
}

#[test]
fn a_changed_compose_file_fails_mrconfigid() {
    let mut b = body();
    let info = &mut b["model_attestations"][0]["info"]["tcb_info"];
    let was_string = info.is_string();
    let mut tcb: Value = match &*info {
        Value::String(s) => serde_json::from_str(s).unwrap(),
        other => other.clone(),
    };
    tcb["app_compose"] = json!(format!("{} ", tcb["app_compose"].as_str().unwrap()));
    *info = if was_string { json!(tcb.to_string()) } else { tcb };
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("MRCONFIGID"));
}

#[test]
fn a_changed_event_log_fails_rtmr3() {
    let mut b = body();
    let log = &mut b["model_attestations"][0]["event_log"];
    let was_string = log.is_string();
    let mut events: Value = match &*log {
        Value::String(s) => serde_json::from_str(s).unwrap(),
        other => other.clone(),
    };
    let last = events.as_array_mut().unwrap().iter_mut().filter(|e| e["imr"] == 3).last().unwrap();
    last["event_payload"] = json!(format!("00{}", last["event_payload"].as_str().unwrap()));
    last["digest"] = json!("");
    *log = if was_string { json!(events.to_string()) } else { events };
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("RTMR3"));
}

#[test]
fn the_model_must_be_fully_patched_the_gateway_may_lag() {
    assert!(err(check(&body(), &nonce(), &with_status("OutOfDate"), false)).starts_with("model: TCB status OutOfDate"));
    assert!(err(check(&body(), &nonce(), &with_status("Revoked"), false)).starts_with("gateway: TCB status Revoked"));
}

#[test]
fn a_repository_can_allow_a_pending_update_never_a_revoked_one() {
    let result = check(&body(), &nonce(), &with_status("OutOfDate"), true).unwrap();
    assert_eq!(result.model.summary.tcb, "OutOfDate");
    assert!(err(check(&body(), &nonce(), &with_status("Revoked"), true)).contains("TCB status Revoked"));
}

#[test]
fn gpu_evidence_must_bind_the_nonce() {
    let mut b = body();
    let mut payload: Value = serde_json::from_str(b["model_attestations"][0]["nvidia_payload"].as_str().unwrap()).unwrap();
    payload["nonce"] = json!("00".repeat(32));
    b["model_attestations"][0]["nvidia_payload"] = json!(payload.to_string());
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("GPU evidence does not bind the nonce"));

    let mut missing = body();
    missing["model_attestations"][0].as_object_mut().unwrap().remove("nvidia_payload");
    assert!(err(check(&missing, &nonce(), &verify_quote, false)).contains("no GPU evidence"));
}

#[test]
fn nvidias_verdict_must_carry_its_signature_in_either_s_form_our_nonce_and_a_pass() {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let token = token();
    let keys = keys().unwrap();
    check_nvidia_token(&token, &nonce(), &keys).unwrap();
    assert!(err(check_nvidia_token(&token, &"00".repeat(32), &keys).map(|_| ())).contains("another nonce"));
    assert!(err(check_nvidia_token(&token, &nonce(), &[]).map(|_| ())).contains("not signed by a published NVIDIA key"));

    let parts: Vec<&str> = token.split('.').collect();
    let raw = b64.decode(parts[2]).unwrap();
    // n - s, big-endian, for P-384's group order.
    let n = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973").unwrap();
    let (mut high, mut borrow) = (vec![0u8; 48], 0i16);
    for i in (0..48).rev() {
        let d = n[i] as i16 - raw[48 + i] as i16 - borrow;
        high[i] = d.rem_euclid(256) as u8;
        borrow = (d < 0) as i16;
    }
    let flipped = b64.encode([&raw[..48], &high[..]].concat());
    check_nvidia_token(&format!("{}.{}.{flipped}", parts[0], parts[1]), &nonce(), &keys).unwrap();

    let mut verdict: Value = serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
    verdict["x-nvidia-overall-att-result"] = json!(false);
    let failed = b64.encode(verdict.to_string());
    assert!(err(check_nvidia_token(&format!("{}.{failed}.{}", parts[0], parts[2]), &nonce(), &keys).map(|_| ())).contains("invalid signature"));
}

#[test]
fn no_model_evidence_fails() {
    let mut b = body();
    b["model_attestations"] = json!([]);
    assert!(err(check(&b, &nonce(), &verify_quote, false)).contains("no model evidence"));
}

#[test]
fn the_sample_receipt_written_by_the_js_core_verifies() {
    let checked = verify_receipt(&receipt_text(), &verify_quote, &keys).unwrap();
    assert_eq!(checked.receipt["subject"]["pull_request"], "MultiAgency/near-agencies#78");
    assert_eq!(checked.attestation.model.summary.tcb, "UpToDate");
    assert_eq!(checked.attestation.gateway.tcb, "OutOfDate");
    assert_eq!(checked.sha256, sha256(receipt_text().as_bytes()));
}

#[test]
fn an_edited_turn_signer_verdict_or_nonce_fails_the_receipt() {
    let edit = |change: &dyn Fn(&mut Value)| {
        let mut r = receipt();
        change(&mut r);
        err(verify_receipt(&r.to_string(), &verify_quote, &keys).map(|_| ()))
    };
    assert!(edit(&|r| r["turns"][3]["request_sha256"] = json!("0".repeat(64))).contains("exact request and response"));
    assert!(edit(&|r| {
        let mut turn = r["turns"][0].clone();
        turn["signature"]["signing_address"] = json!("11".repeat(32));
        r["turns"].as_array_mut().unwrap().push(turn);
    })
    .contains("other than the attested"));
    assert!(edit(&|r| {
        let t = r["gpu_token"].as_str().unwrap();
        r["gpu_token"] = json!(format!("{}.AAAA", &t[..t.rfind('.').unwrap()]));
    })
    .contains("NVIDIA"));
    assert!(edit(&|r| r["nonce"] = json!("00".repeat(32))).contains("report data does not bind"));
    assert!(edit(&|r| r["turns"] = json!([])).contains("no signed turns"));
}

#[test]
fn a_receipt_is_checked_under_the_policy_it_states() {
    let with_policy = |allow: bool| {
        let mut r = receipt();
        r["policy"] = json!({ "allow_unpatched_model": allow });
        r.to_string()
    };
    let stale = with_status("OutOfDate");
    assert!(err(verify_receipt(&with_policy(false), &stale, &keys).map(|_| ())).contains("model: TCB status OutOfDate not accepted"));
    assert_eq!(verify_receipt(&with_policy(true), &stale, &keys).unwrap().attestation.model.summary.tcb, "OutOfDate");
}

#[test]
fn a_recorded_turn_signature_checks_and_any_edit_fails() {
    let t: Value = serde_json::from_str(&read("test/fixtures/turn.json")).unwrap();
    let model = t["model"].as_str().unwrap();
    let signer = t["signer"].as_str().unwrap();
    use base64::Engine;
    let decode = |k: &str| base64::engine::general_purpose::STANDARD.decode(t[k].as_str().unwrap()).unwrap();
    let (request, response) = (decode("request"), decode("response"));
    let text = signed_text(model, &sha256(&request), &sha256(&response));
    check_signature(&t["signature"], &text, signer).unwrap();
    let wrong = signed_text(model, &sha256(b"other"), &sha256(&response));
    assert!(err(check_signature(&t["signature"], &wrong, signer).map(|_| ())).contains("exact request and response"));
    assert!(err(check_signature(&t["signature"], &text, &"11".repeat(32)).map(|_| ())).contains("other than the attested"));
    let mut gateway = t["signature"].clone();
    gateway["signature_kind"] = json!("gateway");
    assert!(err(check_signature(&gateway, &text, signer).map(|_| ())).contains("not the model enclave"));
}

#[test]
fn a_streamed_reply_opens_fragment_by_fragment_with_tool_calls_joined_by_index() {
    let model = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let session = Session::new(&hex::encode(model.verifying_key().as_bytes())).unwrap();
    let client_key = session.headers().into_iter().find(|(k, _)| *k == "x-client-pub-key").unwrap().1;
    let to_client = montgomery(&client_key).unwrap();
    let e = |text: &str| seal(text, &to_client);
    let delta = |d: Value| json!({ "id": "chat-1", "choices": [{ "delta": d }] });
    let reply = session
        .decrypt_stream(&[
            delta(json!({ "role": "assistant", "content": "", "reasoning_content": "" })),
            delta(json!({ "reasoning_content": e("Two files") })),
            delta(json!({ "reasoning_content": e(" to read.") })),
            delta(json!({ "tool_calls": [{ "index": 0, "id": "call_a", "type": "function", "function": { "name": e("read_file") } }] })),
            delta(json!({ "tool_calls": [{ "index": 0, "function": { "arguments": e("{\"path\": ") } }] })),
            delta(json!({ "tool_calls": [{ "index": 0, "function": { "arguments": e("\"a.js\"}") } }] })),
            delta(json!({ "tool_calls": [{ "index": 1, "id": "call_b", "type": "function", "function": { "name": e("grep") } }] })),
            delta(json!({ "tool_calls": [{ "index": 1, "function": { "arguments": e("{\"pattern\": \"x\"}") } }] })),
            json!({ "id": "chat-1", "choices": [{ "delta": {}, "finish_reason": "tool_calls" }], "usage": { "total_tokens": 9 } }),
        ])
        .unwrap();
    assert_eq!(reply.id.as_deref(), Some("chat-1"));
    assert_eq!(reply.finish_reason.as_deref(), Some("tool_calls"));
    assert_eq!(reply.message["reasoning_content"], "Two files to read.");
    assert_eq!(reply.message["tool_calls"][0]["function"]["name"], "read_file");
    assert_eq!(reply.message["tool_calls"][0]["function"]["arguments"], "{\"path\": \"a.js\"}");
    assert_eq!(reply.message["tool_calls"][1]["id"], "call_b");
    assert_eq!(reply.usage.unwrap()["total_tokens"], 9);
}

#[test]
fn a_request_is_encrypted_field_by_field_to_the_model_key() -> Result<()> {
    let model = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let session = Session::new(&hex::encode(model.verifying_key().as_bytes()))?;
    let messages = [json!({ "role": "user", "content": "secret code" })];
    let tools = [json!({ "type": "function", "function": { "name": "grep", "description": "search", "parameters": { "type": "object" } } })];
    let (m, t) = session.encrypt_request(&messages, &tools);
    let secret = x25519_dalek::StaticSecret::from(model.to_scalar_bytes());
    let open = |v: &Value| private_investigator::e2ee::open(v.as_str().unwrap(), &secret);
    if open(&m[0]["content"])? != "secret code" || m[0]["role"] != "user" {
        bail!("message not encrypted to the model key");
    }
    assert_eq!(open(&t[0]["function"]["name"])?, "grep");
    assert_eq!(open(&t[0]["function"]["parameters"])?, "{\"type\":\"object\"}");
    Ok(())
}

#[test]
fn timestamps_read_like_javascripts_to_iso_string() {
    assert_eq!(private_investigator::iso_time(1_791_103_153, 7), "2026-10-04T08:39:13.007Z");
    assert_eq!(private_investigator::iso_time(951_782_400, 0), "2000-02-29T00:00:00.000Z");
}

#[test]
fn turn_hashes_and_subject_commitments_match_the_js_checker() {
    use private_investigator::receipt::{subject_commitment, turn_hash};
    // The same values test/receipt.test.mjs pins for core/receipt.mjs.
    assert_eq!(turn_hash(&receipt()["turns"][0]), "3ee9d41764acc01a67aee289edc62ecd43f16231ca972123f473b6c3eeaeebc9");
    let subject = json!({ "pull_request": "owner/secret-repo#7", "base_sha": "a".repeat(40), "head_sha": "b".repeat(40) });
    assert_eq!(subject_commitment("00112233445566778899aabbccddeeff", &subject), "1713fd61b577b8dbe92fc4de33840d7f7d1c494908b33737395fc21ec322dc28");
}
