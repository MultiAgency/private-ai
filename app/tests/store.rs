//! State bigger than one OutLayer value survives a round trip.
use private_investigator::store::{put, remove, take, Memory, CHUNK};
use serde_json::json;

#[test]
fn large_state_is_compressed_chunked_and_restored() {
    let store = Memory::default();
    // Random-looking text barely compresses, so this needs several chunks.
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let noise: String = (0..3_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(b'a' + (x % 26) as u8)
        })
        .collect();
    let state = json!({ "messages": [noise], "turn": 7 });
    put(&store, "job:x", &state).unwrap();
    let chunks = store.keys().iter().filter(|k| k.starts_with("job:x#")).count();
    assert!(chunks > 1, "{chunks} chunk(s) of at most {CHUNK} bytes");
    assert_eq!(take(&store, "job:x").unwrap().unwrap(), state);
    remove(&store, "job:x").unwrap();
    assert!(store.keys().is_empty());
    assert!(take(&store, "job:x").unwrap().is_none());
}
