//! The network inside the enclave, over wasi-http: NEAR AI Cloud (port of
//! `core/nearai.mjs` and `core/turn.mjs`), Intel collateral from Phala's PCCS
//! (what @phala/dcap-qvl fetches), and NVIDIA's attestation service. Requests
//! and responses are kept as exact bytes, since response signatures cover them.
use anyhow::{anyhow, bail, Context, Result};
use asn1_der::{typed::{DerDecodable, Sequence}, DerObject};
use dcap_qvl::config::{Config, PckCa, ParsedCert, X509Codec};
use dcap_qvl::configs::DefaultConfig;
use dcap_qvl::quote::Quote;
use dcap_qvl::QuoteCollateralV3;
use serde_json::{json, Value};
use wasip2::http::outgoing_handler;
use wasip2::http::types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme};
use wasip2::io::streams::StreamError;

use crate::agent::{Agent, Finish, Next, REASONING_EFFORT};
use crate::attest::{self, Attestation, Nvidia, Options, Verified, NRAS};
use crate::e2ee::Session;
use crate::receipt::Evidence;
use crate::sign::{check_signature, sha256, signed_text};

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// One HTTPS request; the body is read to the end as it streams.
pub fn request(method: Method, url: &str, headers: &[(&str, String)], body: Option<&[u8]>) -> Result<Response> {
    let rest = url.strip_prefix("https://").ok_or_else(|| anyhow!("only https is allowed: {url}"))?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let fields: Vec<(String, Vec<u8>)> = headers.iter().map(|(k, v)| (k.to_string(), v.as_bytes().to_vec())).collect();
    let req = OutgoingRequest::new(Fields::from_list(&fields).map_err(|e| anyhow!("headers: {e:?}"))?);
    req.set_method(&method).map_err(|_| anyhow!("method"))?;
    req.set_scheme(Some(&Scheme::Https)).map_err(|_| anyhow!("scheme"))?;
    req.set_authority(Some(authority)).map_err(|_| anyhow!("authority"))?;
    req.set_path_with_query(Some(if path.is_empty() { "/" } else { path })).map_err(|_| anyhow!("path"))?;
    let out = req.body().map_err(|_| anyhow!("body"))?;
    // Start the request before writing its body: a body larger than the
    // stream's buffer can only drain once the request is under way.
    let future = outgoing_handler::handle(req, None).map_err(|e| anyhow!("{method:?} {authority}: {e:?}"))?;
    if let Some(bytes) = body {
        let stream = out.write().map_err(|_| anyhow!("body stream"))?;
        for chunk in bytes.chunks(4096) {
            stream.blocking_write_and_flush(chunk).map_err(|e| anyhow!("write: {e:?}"))?;
        }
    }
    OutgoingBody::finish(out, None).map_err(|e| anyhow!("finish: {e:?}"))?;
    future.subscribe().block();
    let resp = future
        .get()
        .ok_or_else(|| anyhow!("no response"))?
        .map_err(|_| anyhow!("response taken"))?
        .map_err(|e| anyhow!("{authority}: {e:?}"))?;
    let headers = resp.headers().entries().into_iter().map(|(k, v)| (k, String::from_utf8_lossy(&v).into_owned())).collect();
    let status = resp.status();
    let incoming = resp.consume().map_err(|_| anyhow!("consume"))?;
    let stream = incoming.stream().map_err(|_| anyhow!("stream"))?;
    let mut body = Vec::new();
    loop {
        match stream.blocking_read(64 * 1024) {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => bail!("{authority}: reading the body: {e:?}"),
        }
    }
    Ok(Response { status, headers, body })
}

fn get(url: &str) -> Result<Response> {
    let response = request(Method::Get, url, &[], None)?;
    if !(200..300).contains(&response.status) {
        bail!("GET {}: {}", url.split('?').next().unwrap_or(url), response.status);
    }
    Ok(response)
}

pub fn now_seconds() -> u64 {
    wasip2::clocks::wall_clock::now().seconds
}

fn sleep_ms(ms: u64) {
    wasip2::clocks::monotonic_clock::subscribe_duration(ms * 1_000_000).block();
}

// ---- Intel collateral ----

const PCCS: &str = "https://pccs.phala.network";

/// The FMSPC in a PCK certificate's SGX extension (as dcap-qvl's private helper reads it).
fn fmspc(extension: &[u8]) -> Result<String> {
    let seq = Sequence::load(DerObject::decode(extension)?)?;
    for i in 0..seq.len() {
        let entry = Sequence::load(seq.get(i)?)?;
        if entry.get(0)?.value() == dcap_qvl::oids::FMSPC.as_bytes() {
            let value = entry.get(1)?.value();
            if value.len() != 6 {
                bail!("FMSPC length mismatch");
            }
            return Ok(hex::encode_upper(value));
        }
    }
    bail!("FMSPC missing")
}

fn issuer_chain(response: &Response, names: &[&str]) -> Result<String> {
    let raw = names.iter().find_map(|n| response.header(n)).ok_or_else(|| anyhow!("missing {}", names[0]))?;
    let mut out = Vec::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&raw[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Ok(String::from_utf8(out)?)
}

/// The collateral for a quote whose certification data embeds its PCK chain
/// (as NEAR AI's TDX quotes do), fetched as @phala/dcap-qvl fetches it.
pub fn collateral(quote: &[u8]) -> Result<QuoteCollateralV3> {
    let parsed = Quote::parse(quote).context("Failed to parse quote")?;
    if parsed.inner_cert_type() != 5 {
        bail!("unsupported certification data type {}", parsed.inner_cert_type());
    }
    let chain = String::from_utf8_lossy(parsed.inner_cert_data()).to_string();
    let leaf = pem::parse_many(chain.as_bytes()).map_err(|e| anyhow!("PCK chain: {e:?}"))?;
    let leaf = leaf.first().ok_or_else(|| anyhow!("empty PCK chain"))?;
    let cert = <DefaultConfig as Config>::X509::from_der(leaf.contents())?;
    let extension = cert.extension(dcap_qvl::oids::SGX_EXTENSION.as_bytes())?.ok_or_else(|| anyhow!("Intel extension not found"))?;
    let fmspc = fmspc(&extension)?;
    let ca = cert.pck_ca().unwrap_or(PckCa::Processor).as_id_str();
    let tee = if parsed.header.is_sgx() { "sgx" } else { "tdx" };

    let crl = get(&format!("{PCCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"))?;
    let tcb = get(&format!("{PCCS}/{tee}/certification/v4/tcb?fmspc={fmspc}&update=standard"))?;
    let qe = get(&format!("{PCCS}/{tee}/certification/v4/qe/identity?update=standard"))?;
    let root = get(&format!("{PCCS}/sgx/certification/v4/rootcacrl"))?;
    let tcb_json: Value = serde_json::from_slice(&tcb.body).context("TCB Info should be valid JSON")?;
    let qe_json: Value = serde_json::from_slice(&qe.body).context("QE Identity should be valid JSON")?;
    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain: issuer_chain(&crl, &["SGX-PCK-CRL-Issuer-Chain"])?,
        root_ca_crl: hex::decode(std::str::from_utf8(&root.body)?.trim()).context("root CA CRL is not hex")?,
        tcb_info_issuer_chain: issuer_chain(&tcb, &["SGX-TCB-Info-Issuer-Chain", "TCB-Info-Issuer-Chain"])?,
        tcb_info: tcb_json["tcbInfo"].to_string(),
        tcb_info_signature: hex::decode(tcb_json["signature"].as_str().unwrap_or("")).context("TCB Info signature")?,
        qe_identity_issuer_chain: issuer_chain(&qe, &["SGX-Enclave-Identity-Issuer-Chain"])?,
        qe_identity: qe_json["enclaveIdentity"].to_string(),
        qe_identity_signature: hex::decode(qe_json["signature"].as_str().unwrap_or("")).context("QE Identity signature")?,
        pck_crl: crl.body,
        pck_certificate_chain: Some(chain),
    })
}

/// Verifies a quote against the current collateral.
pub fn verify_quote_live(quote: &[u8]) -> Result<Verified> {
    attest::verify_quote(quote, &collateral(quote)?, now_seconds())
}

// ---- NVIDIA ----

pub struct LiveNvidia;

impl Nvidia for LiveNvidia {
    /// NVIDIA's signed verdict on a model's GPU evidence: a JWT from its attestation service.
    fn token(&self, payload: &Value) -> Result<String> {
        let body = serde_json::to_vec(payload)?;
        let headers = [("accept", "application/json".to_string()), ("content-type", "application/json".to_string())];
        let response = request(Method::Post, &format!("{NRAS}/v3/attest/gpu"), &headers, Some(&body))?;
        if !(200..300).contains(&response.status) {
            bail!("NVIDIA attestation service: {}", response.status);
        }
        let answer: Value = serde_json::from_slice(&response.body)?;
        answer[0][1].as_str().map(String::from).ok_or_else(|| anyhow!("NVIDIA attestation service returned no token"))
    }

    fn keys(&self) -> Result<Vec<Value>> {
        let response = get(&format!("{NRAS}/.well-known/jwks.json")).map_err(|e| anyhow!("NVIDIA signing keys: {e}"))?;
        let jwks: Value = serde_json::from_slice(&response.body)?;
        Ok(jwks["keys"].as_array().cloned().unwrap_or_default())
    }
}

// ---- NEAR AI Cloud ----

const BASE: &str = "https://cloud-api.near.ai/v1";

const CHAT_ATTEMPTS: u32 = 2;

/// A failure worth one more try: the connection, or a gateway in front of the model.
#[derive(Debug)]
struct Retryable(String);

impl std::fmt::Display for Retryable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Retryable {}

pub struct NearAi {
    api_key: String,
}

/// A chat completion's exact bytes both ways, and its parsed events.
pub struct Chat {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub events: Vec<Value>,
}

/// A signed turn: the decrypted reply, and what the receipt records.
pub struct Turn {
    pub reply: Value,
    pub finish_reason: Option<String>,
    pub usage: Option<Value>,
    pub record: Value,
}

/// The server-sent events of a streamed reply, without the closing [DONE].
pub fn parse_events(raw: &[u8]) -> Result<Vec<Value>> {
    String::from_utf8_lossy(raw)
        .split('\n')
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| Ok(serde_json::from_str(data)?))
        .collect()
}

impl NearAi {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self { api_key: api_key.into() }
    }

    fn send(&self, method: Method, path: &str, extra: &[(&str, String)], body: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut headers = vec![("authorization", format!("Bearer {}", self.api_key)), ("x-no-aliasing", "true".to_string())];
        headers.extend(extra.iter().cloned());
        let name = path.split('?').next().unwrap_or(path);
        let response = request(method, &format!("{BASE}{path}"), &headers, body).map_err(|e| anyhow::Error::new(Retryable(format!("NEAR AI {name}: {e}"))))?;
        if [502, 503, 504].contains(&response.status) {
            return Err(anyhow::Error::new(Retryable(format!("NEAR AI {name}: {}", response.status))));
        }
        if !(200..300).contains(&response.status) {
            // Error text names the status and the API's own message; request
            // bodies are ciphertext, so an echo of them reveals nothing.
            let message = serde_json::from_slice::<Value>(&response.body).ok().and_then(|v| v["error"]["message"].as_str().map(|m| m.chars().take(200).collect::<String>()));
            bail!("NEAR AI {}: {}{}", path.split('?').next().unwrap_or(path), response.status, message.map(|m| format!(" {m}")).unwrap_or_default());
        }
        Ok(response.body)
    }

    pub fn attestation_report(&self, model: &str, nonce: &str) -> Result<Value> {
        let path = format!("/attestation/report?model={}&provider=near&signing_algo=ed25519&include_tls_fingerprint=false&nonce={nonce}", model.replace('/', "%2F"));
        Ok(serde_json::from_slice(&self.send(Method::Get, &path, &[], None)?)?)
    }

    /// A streamed chat completion: the exact bytes both ways, and the parsed events.
    pub fn chat(&self, e2ee_headers: &[(&'static str, String)], mut body: Value) -> Result<Chat> {
        body["stream"] = json!(true);
        let request = serde_json::to_vec(&body)?;
        let mut headers = e2ee_headers.to_vec();
        headers.push(("content-type", "application/json".into()));
        headers.push(("accept-encoding", "identity".into()));
        // A dropped connection or a gateway error is retried once: nothing from
        // a reply is used until its signature checks out, so a retry costs
        // tokens, never correctness (as core/nearai.mjs does).
        let mut attempt = 1;
        let response = loop {
            match self.send(Method::Post, "/chat/completions", &headers, Some(&request)) {
                Ok(response) => break response,
                Err(e) if attempt < CHAT_ATTEMPTS && e.downcast_ref::<Retryable>().is_some() => {
                    attempt += 1;
                    sleep_ms(3000);
                }
                Err(e) => return Err(e),
            }
        };
        let events = parse_events(&response)?;
        Ok(Chat { request, response, events })
    }

    /// A signature can lag its response by a moment; retry briefly, then give up.
    pub fn signature(&self, id: &str, model: &str) -> Result<Value> {
        let path = format!("/signature/{id}?signing_algo=ed25519&model={}", model.replace('/', "%2F"));
        let mut last = anyhow!("signature unavailable");
        for attempt in 1..=5u64 {
            match self.send(Method::Get, &path, &[], None).and_then(|b| Ok(serde_json::from_slice::<Value>(&b)?)) {
                Ok(signature) if signature.get("error_code").is_none() => return Ok(signature),
                Ok(signature) => last = anyhow!("signature unavailable: {}", signature["error_code"]),
                Err(e) => last = e,
            }
            sleep_ms(attempt * 1000);
        }
        Err(last)
    }

    /// Fetches a fresh report for the model and verifies it. `Evidence` is what
    /// a receipt keeps; `Attestation` is what was verified, with the key to encrypt to.
    pub fn attest(&self, model: &str, allow_unpatched_model: bool) -> Result<(Evidence, Attestation)> {
        let nonce = hex::encode(crate::random::<32>());
        let mut report = self.attestation_report(model, &nonce)?;
        if let Some(map) = report.as_object_mut() {
            map.remove("ohttp_key_config");
            map.remove("ohttp_attestation");
        }
        let attestation = attest::verify_attestation(
            &report,
            &nonce,
            &Options { verify_quote: &verify_quote_live, nvidia: &LiveNvidia, gpu_token: None, allow_unpatched_model },
        )?;
        let evidence = Evidence { nonce, report, gpu_token: attestation.model.gpu_token.clone(), allow_unpatched_model };
        Ok((evidence, attestation))
    }

    /// One private turn: the request end-to-end encrypted to the attested model
    /// key, the reply streamed, and nothing of it used until the model
    /// enclave's signature over the exact request and response bytes checks out.
    pub fn signed_turn(&self, model: &str, public_key: &str, e2ee: &Session, messages: &[Value], tools: &[Value], effort: &str, max_tokens: u64) -> Result<Turn> {
        let (messages, tools) = e2ee.encrypt_request(messages, tools);
        let mut body = json!({ "model": model, "messages": messages, "max_tokens": max_tokens, "reasoning_effort": effort });
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools);
        }
        let chat = self.chat(&e2ee.headers(), body)?;
        let reply = e2ee.decrypt_stream(&chat.events)?;
        let id = reply.id.clone().ok_or_else(|| anyhow!("reply has no id"))?;
        let (request_sha256, response_sha256) = (sha256(&chat.request), sha256(&chat.response));
        let signature = self.signature(&id, model)?;
        check_signature(&signature, &signed_text(model, &request_sha256, &response_sha256), public_key)?;
        Ok(Turn {
            reply: reply.message,
            finish_reason: reply.finish_reason,
            usage: reply.usage,
            record: json!({ "id": id, "request_sha256": request_sha256, "response_sha256": response_sha256, "signature": signature }),
        })
    }

    /// One turn of an agent: a signed, end-to-end encrypted turn under a fresh
    /// session (so no client key outlives the run), applied to its state.
    pub fn agent_turn(&self, agent: &mut Agent, model: &str, public_key: &str, tools: &[Value], finish: &Finish, call: &mut dyn FnMut(&str, &Value) -> String) -> Result<Next> {
        let mut definitions = tools.to_vec();
        definitions.push(finish.tool.clone());
        let turn = self.signed_turn(model, public_key, &Session::new(public_key)?, &agent.messages, &definitions, REASONING_EFFORT, agent.reply_cap)?;
        agent.apply(&turn.reply, turn.finish_reason.as_deref(), turn.record, finish, call)
    }
}
