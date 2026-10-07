//! The text handling the network code relies on, as `core/nearai.mjs`,
//! `review/github.mjs` and @phala/dcap-qvl do it.
use private_investigator::wire::{encode_segment, parse_events, percent_decode};
use serde_json::json;

#[test]
fn events_are_the_data_lines_without_the_closing_done() {
    let raw = b"data: {\"id\":\"chat-1\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: {\"id\":\"chat-1\",\"usage\":{\"total_tokens\":3}}\n\ndata: [DONE]\n\n";
    let events = parse_events(raw).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["id"], "chat-1");
    assert_eq!(events[1]["usage"], json!({ "total_tokens": 3 }));
}

#[test]
fn lines_that_are_not_data_are_skipped() {
    let raw = b": keep-alive\nevent: message\ndata: {\"id\":\"a\"}\n\nretry: 5\n";
    assert_eq!(parse_events(raw).unwrap(), vec![json!({ "id": "a" })]);
    assert!(parse_events(b"").unwrap().is_empty());
    assert!(parse_events(b"data: [DONE]\n").unwrap().is_empty());
}

#[test]
fn a_data_line_that_is_not_json_is_an_error() {
    assert!(parse_events(b"data: {not json\n").is_err());
}

#[test]
fn escapes_are_decoded() {
    assert_eq!(percent_decode("-----BEGIN%20CERTIFICATE-----%0AMII%3D%0A").unwrap(), "-----BEGIN CERTIFICATE-----\nMII=\n");
    assert_eq!(percent_decode("%2f%2F").unwrap(), "//");
    assert_eq!(percent_decode("plain").unwrap(), "plain");
    assert_eq!(percent_decode("").unwrap(), "");
}

#[test]
fn a_percent_without_two_hex_digits_is_kept() {
    assert_eq!(percent_decode("100%").unwrap(), "100%");
    assert_eq!(percent_decode("50%zz").unwrap(), "50%zz");
    assert_eq!(percent_decode("a%4").unwrap(), "a%4");
}

#[test]
fn a_percent_before_a_multibyte_character_does_not_panic() {
    assert_eq!(percent_decode("%é").unwrap(), "%é");
    assert_eq!(percent_decode("x%éy").unwrap(), "x%éy");
}

#[test]
fn escapes_that_are_not_utf8_are_an_error() {
    assert!(percent_decode("%FF%FE").is_err());
}

#[test]
fn a_path_segment_is_encoded_as_encode_uri_component_does() {
    assert_eq!(encode_segment("lib"), "lib");
    assert_eq!(encode_segment("my file.mjs"), "my%20file.mjs");
    assert_eq!(encode_segment("a+b&c=d"), "a%2Bb%26c%3Dd");
    assert_eq!(encode_segment("100%"), "100%25");
    assert_eq!(encode_segment("../x"), "..%2Fx");
    assert_eq!(encode_segment("é"), "%C3%A9");
    assert_eq!(encode_segment("keep-_.!~*'()"), "keep-_.!~*'()");
}
