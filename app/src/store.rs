//! Job state between runs. OutLayer's storage is encrypted by its keystore
//! enclave and caps one value at about 1 MB, while a review's conversation can
//! run to several: values are compressed, and split into chunks when they are
//! still too large. Key names are opaque (job ids), never repository names.
use anyhow::{anyhow, bail, Context, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::Value;
use std::io::{Read, Write};

/// Under OutLayer's measured limit (1 MB stored, 2 MB refused), with room for overhead.
pub const CHUNK: usize = 900 * 1024;

pub trait Store {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    /// Writes a value anyone may read (OutLayer: public storage, plaintext).
    fn publish(&self, key: &str, value: &[u8]) -> Result<()>;
}

/// Writes a JSON value under `key`, compressed and chunked.
pub fn put(store: &dyn Store, key: &str, value: &Value) -> Result<()> {
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(value.to_string().as_bytes())?;
    let packed = encoder.finish()?;
    let chunks: Vec<&[u8]> = packed.chunks(CHUNK).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        store.set(&format!("{key}#{i}"), chunk)?;
    }
    // The count goes last, so a reader never sees a count whose chunks are missing.
    store.set(key, chunks.len().to_string().as_bytes())
}

/// Reads what `put` wrote, or `None` when nothing is stored under `key`.
pub fn take(store: &dyn Store, key: &str) -> Result<Option<Value>> {
    let Some(count) = store.get(key)? else { return Ok(None) };
    let count: usize = std::str::from_utf8(&count)?.parse().context("stored chunk count")?;
    let mut packed = Vec::new();
    for i in 0..count {
        packed.extend(store.get(&format!("{key}#{i}"))?.ok_or_else(|| anyhow!("stored state is missing a chunk"))?);
    }
    let mut text = String::new();
    ZlibDecoder::new(packed.as_slice()).read_to_string(&mut text).context("stored state is corrupt")?;
    Ok(Some(serde_json::from_str(&text)?))
}

pub fn remove(store: &dyn Store, key: &str) -> Result<()> {
    if let Some(count) = store.get(key)? {
        let count: usize = std::str::from_utf8(&count)?.parse().unwrap_or(0);
        store.delete(key)?;
        for i in 0..count {
            store.delete(&format!("{key}#{i}"))?;
        }
    }
    Ok(())
}

/// For tests and local runs.
#[derive(Default)]
pub struct Memory(std::cell::RefCell<std::collections::HashMap<String, Vec<u8>>>);

impl Store for Memory {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(key).cloned())
    }
    fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        if value.len() > 1024 * 1024 {
            bail!("value over 1 MB");
        }
        self.0.borrow_mut().insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
    fn publish(&self, key: &str, value: &[u8]) -> Result<()> {
        self.0.borrow_mut().insert(format!("public:{key}"), value.into());
        Ok(())
    }
}

impl Memory {
    pub fn keys(&self) -> Vec<String> {
        self.0.borrow().keys().cloned().collect()
    }
}
