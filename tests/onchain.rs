//! RPC response parsing.
//!
//! No network here. These are the decode paths that turn an untrusted RPC
//! response into a verdict, so they get adversarial input rather than only the
//! happy path — a scanner that can be fooled by the answer it gets back is
//! worse than one that never asks.

use inquisitor::onchain::{
    self, Registry, account_data_from_response, account_info_request, base64_decode,
};
use inquisitor::sas::{self, VerdictPayload};
use solana_pubkey::Pubkey;
use std::collections::HashMap;

fn credential() -> Pubkey {
    Pubkey::from_str_const("11111111111111111111111111111112")
}

/// Build a well-formed SAS Attestation account around a payload.
fn account_bytes(payload: &VerdictPayload, signer: &Pubkey) -> Vec<u8> {
    let data = payload.encode();
    let mut out = Vec::new();
    out.push(7u8); // discriminator
    out.extend_from_slice(&[1u8; 32]); // nonce
    out.extend_from_slice(&[2u8; 32]); // credential
    out.extend_from_slice(&[3u8; 32]); // schema
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out.extend_from_slice(&signer.to_bytes());
    out.extend_from_slice(&0i64.to_le_bytes()); // expiry
    out.extend_from_slice(&[0u8; 32]); // token_account
    out
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[test]
fn base64_round_trips() {
    for case in [b"".to_vec(), b"a".to_vec(), b"ab".to_vec(), b"abc".to_vec(), (0..=255u8).collect()] {
        assert_eq!(base64_decode(&base64_encode(&case)), Some(case));
    }
}

#[test]
fn base64_rejects_garbage() {
    assert!(base64_decode("!!!!").is_none());
    assert!(base64_decode("abc$def").is_none());
}

#[test]
fn missing_account_reads_as_no_verdict() {
    // The common case: nobody has published a verdict for this skill yet. It
    // must read as absence, never as an error and never as "clean".
    let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}"#;
    assert!(account_data_from_response(body).is_none());
    assert!(onchain::verdict_from_response(body, credential()).is_none());
}

#[test]
fn published_verdict_decodes() {
    let payload = VerdictPayload {
        level: 3,
        score: 100,
        scanner_version: "0.1.0".to_string(),
        rule_ids: "exfil.secret_outbound".to_string(),
    };
    let signer = Pubkey::from_str_const("11111111111111111111111111111112");
    let encoded = base64_encode(&account_bytes(&payload, &signer));
    let body = format!(
        r#"{{"jsonrpc":"2.0","result":{{"context":{{"slot":1}},"value":{{"data":["{encoded}","base64"],"executable":false,"lamports":1}}}},"id":1}}"#
    );

    let found = onchain::verdict_from_response(&body, credential()).expect("verdict");
    assert_eq!(found.payload, payload);
    assert_eq!(found.signer, Some(signer));
}

#[test]
fn truncated_account_is_rejected() {
    let payload = VerdictPayload {
        level: 3,
        score: 100,
        scanner_version: "0.1.0".to_string(),
        rule_ids: "exfil.secret_outbound".to_string(),
    };
    let full = account_bytes(&payload, &credential());

    // A short read must never become a partial verdict the agent acts on.
    for cut in [0, 10, 50, 96, 100, full.len() - 40] {
        assert!(
            sas::payload_from_account(&full[..cut]).is_none(),
            "truncation at {cut} decoded"
        );
    }
}

#[test]
fn garbage_response_is_rejected() {
    for body in ["", "{}", "not json at all", r#"{"result":{"value":{"data":["!!!!","base64"]}}}"#] {
        assert!(
            onchain::verdict_from_response(body, credential()).is_none(),
            "accepted garbage: {body}"
        );
    }
}

#[test]
fn registry_needs_explicit_configuration() {
    // Unconfigured is the normal state and must degrade to local scanning.
    assert!(Registry::from_section(&HashMap::new()).is_none());

    let mut partial = HashMap::new();
    partial.insert("rpc_url".to_string(), "https://api.devnet.solana.com".to_string());
    assert!(Registry::from_section(&partial).is_none(), "rpc alone is not a registry");
}

#[test]
fn registry_derives_schema_when_omitted() {
    let mut section = HashMap::new();
    section.insert("rpc_url".to_string(), "https://api.devnet.solana.com".to_string());
    section.insert("credential".to_string(), credential().to_string());

    let registry = Registry::from_section(&section).expect("registry");
    // Operators should only have to configure one key; the schema follows.
    assert_eq!(
        registry.schema,
        sas::derive_schema(&credential(), sas::SCHEMA_NAME, sas::SCHEMA_VERSION).0
    );
}

#[test]
fn request_body_targets_the_derived_address() {
    let addr = credential();
    let body = account_info_request(&addr);
    assert!(body.contains(&addr.to_string()));
    assert!(body.contains("getAccountInfo"));
    assert!(body.contains("base64"));
}
