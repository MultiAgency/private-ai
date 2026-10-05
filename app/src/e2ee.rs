//! End-to-end encryption to an attested model key, NEAR AI Cloud's E2EE v2:
//! X25519 ECDH, HKDF-SHA256 and XChaCha20-Poly1305. Each encrypted field is hex
//! of [ephemeral public key (32)][nonce (24)][ciphertext + tag]. Port of
//! `core/e2ee.mjs`.
use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const INFO: &[u8] = b"ed25519_encryption";
const TEXT_FIELDS: [&str; 4] = ["content", "reasoning_content", "reasoning", "refusal"];

fn symmetric_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared).expand(INFO, &mut key).expect("32 bytes");
    key
}

pub fn seal(plaintext: &str, recipient: &PublicKey) -> String {
    let ephemeral = StaticSecret::from(crate::random::<32>());
    let nonce = crate::random::<24>();
    let cipher = XChaCha20Poly1305::new(&symmetric_key(ephemeral.diffie_hellman(recipient).as_bytes()).into());
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.as_bytes()).expect("encrypt");
    let mut out = PublicKey::from(&ephemeral).as_bytes().to_vec();
    out.extend(nonce);
    out.extend(ciphertext);
    hex::encode(out)
}

pub fn open(hex: &str, secret: &StaticSecret) -> Result<String> {
    let data = crate::bytes(hex)?;
    if data.len() < 56 {
        return Err(anyhow!("ciphertext too short"));
    }
    let ephemeral = PublicKey::from(<[u8; 32]>::try_from(&data[..32])?);
    let cipher = XChaCha20Poly1305::new(&symmetric_key(secret.diffie_hellman(&ephemeral).as_bytes()).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(&data[32..56]), &data[56..])
        .map_err(|_| anyhow!("could not decrypt a reply field"))?;
    String::from_utf8(plain).context("decrypted field is not UTF-8")
}

/// The X25519 key an Ed25519 public key encrypts to.
pub fn montgomery(ed25519_public_hex: &str) -> Result<PublicKey> {
    let key = VerifyingKey::from_bytes(&crate::bytes(ed25519_public_hex)?.try_into().map_err(|_| anyhow!("model key is not 32 bytes"))?)?;
    Ok(PublicKey::from(key.to_montgomery().to_bytes()))
}

/// What a streamed reply carries, decrypted.
pub struct StreamReply {
    pub id: Option<String>,
    pub message: Value,
    pub finish_reason: Option<String>,
    pub usage: Option<Value>,
}

/// One exchange's keys: a fresh client key pair, and the model's verified Ed25519 key.
pub struct Session {
    client: SigningKey,
    client_x25519: StaticSecret,
    model_x25519: PublicKey,
    model_public_key: String,
}

impl Session {
    pub fn new(model_public_key_hex: &str) -> Result<Self> {
        let client = SigningKey::from_bytes(&crate::random::<32>());
        Ok(Self {
            client_x25519: StaticSecret::from(client.to_scalar_bytes()),
            client,
            model_x25519: montgomery(model_public_key_hex)?,
            model_public_key: model_public_key_hex.to_string(),
        })
    }

    pub fn headers(&self) -> Vec<(&'static str, String)> {
        vec![
            ("x-signing-algo", "ed25519".into()),
            ("x-client-pub-key", hex::encode(self.client.verifying_key().as_bytes())),
            ("x-model-pub-key", self.model_public_key.clone()),
            ("x-encryption-version", "2".into()),
            ("x-encrypt-all-fields", "true".into()),
        ]
    }

    fn encrypt(&self, text: &str) -> String {
        seal(text, &self.model_x25519)
    }

    /// Encrypts every field the all-fields mode covers; the caller keeps the plaintext.
    pub fn encrypt_request(&self, messages: &[Value], tools: &[Value]) -> (Vec<Value>, Vec<Value>) {
        let messages = messages
            .iter()
            .map(|m| {
                let mut m = m.clone();
                if let Some(content) = m.get("content").and_then(Value::as_str) {
                    m["content"] = json!(self.encrypt(content));
                }
                if let Some(calls) = m.get("tool_calls").and_then(Value::as_array) {
                    m["tool_calls"] = Value::Array(calls.iter().map(|c| transform_call(c, |s| Ok(self.encrypt(s))).expect("encrypt")).collect());
                }
                m
            })
            .collect();
        let tools = tools
            .iter()
            .map(|t| {
                let f = &t["function"];
                json!({
                    "type": t["type"],
                    "function": {
                        "name": self.encrypt(f["name"].as_str().unwrap_or("")),
                        "description": self.encrypt(f["description"].as_str().unwrap_or("")),
                        "parameters": self.encrypt(&f["parameters"].to_string()),
                    },
                })
            })
            .collect();
        (messages, tools)
    }

    /// The reply a stream carries. Each fragment of each field is encrypted on
    /// its own, so fragments are opened before they are joined: text fields by
    /// concatenation, tool calls by their index.
    pub fn decrypt_stream(&self, events: &[Value]) -> Result<StreamReply> {
        let mut message = Map::new();
        message.insert("role".into(), json!("assistant"));
        message.insert("content".into(), json!(""));
        message.insert("reasoning_content".into(), json!(""));
        let mut calls: Vec<Option<Value>> = Vec::new();
        let (mut finish_reason, mut usage) = (None, None);
        for event in events {
            if !event["usage"].is_null() {
                usage = Some(event["usage"].clone());
            }
            let Some(choice) = event["choices"].get(0) else { continue };
            if let Some(reason) = choice["finish_reason"].as_str() {
                finish_reason = Some(reason.to_string());
            }
            let delta = &choice["delta"];
            for field in TEXT_FIELDS {
                if let Some(fragment) = delta[field].as_str().filter(|s| !s.is_empty()) {
                    let joined = format!("{}{}", message.get(field).and_then(Value::as_str).unwrap_or(""), open(fragment, &self.client_x25519)?);
                    message.insert(field.into(), json!(joined));
                }
            }
            for part in delta["tool_calls"].as_array().into_iter().flatten() {
                let index = part["index"].as_u64().unwrap_or(0) as usize;
                if calls.len() <= index {
                    calls.resize(index + 1, None);
                }
                let call = calls[index].get_or_insert_with(|| json!({ "id": "", "type": "function", "function": { "name": "", "arguments": "" } }));
                if let Some(id) = part["id"].as_str().filter(|s| !s.is_empty()) {
                    call["id"] = json!(id);
                }
                for key in ["name", "arguments"] {
                    if let Some(fragment) = part["function"][key].as_str().filter(|s| !s.is_empty()) {
                        let joined = format!("{}{}", call["function"][key].as_str().unwrap_or(""), open(fragment, &self.client_x25519)?);
                        call["function"][key] = json!(joined);
                    }
                }
            }
        }
        let calls: Vec<Value> = calls.into_iter().flatten().collect();
        if !calls.is_empty() {
            message.insert("tool_calls".into(), Value::Array(calls));
        }
        Ok(StreamReply {
            id: events.first().and_then(|e| e["id"].as_str()).map(String::from),
            message: Value::Object(message),
            finish_reason,
            usage,
        })
    }

    pub fn decrypt_message(&self, message: &Value) -> Result<Value> {
        let mut plain = message.clone();
        for field in TEXT_FIELDS {
            if let Some(text) = message[field].as_str().filter(|s| !s.is_empty()) {
                plain[field] = json!(open(text, &self.client_x25519)?);
            }
        }
        if let Some(calls) = message["tool_calls"].as_array() {
            plain["tool_calls"] = Value::Array(calls.iter().map(|c| transform_call(c, |s| open(s, &self.client_x25519))).collect::<Result<_>>()?);
        }
        Ok(plain)
    }
}

fn transform_call(call: &Value, transform: impl Fn(&str) -> Result<String>) -> Result<Value> {
    let mut call = call.clone();
    for key in ["name", "arguments"] {
        let text = call["function"][key].as_str().unwrap_or("").to_string();
        call["function"][key] = json!(transform(&text)?);
    }
    Ok(call)
}
