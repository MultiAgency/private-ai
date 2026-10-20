//! The parts of the network code that are only text handling, kept apart from
//! the wasi-http calls so they build and are tested natively.
use anyhow::Result;
use serde_json::Value;

/// The server-sent events of a streamed reply, without the closing [DONE].
pub fn parse_events(raw: &[u8]) -> Result<Vec<Value>> {
    String::from_utf8_lossy(raw)
        .split('\n')
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .map(|data| Ok(serde_json::from_str(data)?))
        .collect()
}

/// A header value with its `%XX` escapes decoded (Intel's issuer chains arrive
/// percent-encoded). A `%` not followed by two hex digits is kept as it is.
pub fn percent_decode(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16)) {
                out.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Ok(String::from_utf8(out)?)
}

/// `encodeURIComponent` for one path segment.
pub fn encode_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
