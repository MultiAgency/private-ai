//! The NEAR AI Cloud core of the hosted reviewer, ported from `core/` so that
//! a run inside OutLayer makes the same checks, in the same order, with the
//! same messages, and writes receipts the page's checker verifies.
pub mod agent;
pub mod attest;
pub mod doors;
pub mod e2ee;
pub mod failure;
#[cfg(target_arch = "wasm32")]
pub mod github;
#[cfg(target_arch = "wasm32")]
pub mod host;
pub mod job;
pub mod jwt;
#[cfg(target_arch = "wasm32")]
pub mod net;
pub mod receipt;
pub mod repo;
pub mod review;
pub mod sign;
pub mod store;
pub mod wire;

use anyhow::Result;

/// Bytes of a hex string, with or without a `0x` prefix.
pub(crate) fn bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    Ok(hex::decode(hex)?)
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("system randomness");
    out
}

/// An ISO 8601 UTC timestamp with milliseconds, as JavaScript's `toISOString`.
pub fn iso_time(seconds: u64, millis: u32) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z", rem / 3_600, rem % 3_600 / 60, rem % 60)
}

/// A JSON value as OutLayer's worker hashes an output: compact, keys sorted
/// (outlayer-verify's `output_hash`). Turn hashes and the subject commitment
/// use it too, so a checker rebuilds every hash the same way (core/outlayer.mjs `canonical`).
pub fn canonical(value: &serde_json::Value) -> String {
    sorted(value).to_string()
}

/// The same value with every object's keys in sorted order.
pub fn sorted(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&map[k]))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The account whose secrets a build reads (manifest.json `author_secrets.owner`).
/// Only it may open reviews: they run on its NEAR AI key, and it is the
/// owner of the relay's payment key, so OutLayer names it as the relay's caller.
pub fn secret_owner(manifest: &[u8]) -> Option<String> {
    let manifest: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    manifest["author_secrets"]["owner"].as_str().filter(|o| !o.is_empty()).map(String::from)
}
