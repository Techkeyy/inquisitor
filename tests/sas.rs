//! Address derivation and payload encoding.
//!
//! These run natively. The same code paths compile into the component, so a
//! green run here is evidence about the wasm build too — which is the reason
//! the pure/glue split exists.

use inquisitor::sas::{
    self, SAS_PROGRAM_ID, SCHEMA_NAME, SCHEMA_VERSION, VerdictPayload,
};
use inquisitor::scan::skill_hash;
use solana_pubkey::Pubkey;

fn authority() -> Pubkey {
    Pubkey::from_str_const("11111111111111111111111111111112")
}

#[test]
fn program_id_is_the_deployed_one() {
    // Verified live against devnet: executable, owned by BPFLoaderUpgradeab1e.
    assert_eq!(
        SAS_PROGRAM_ID.to_string(),
        "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"
    );
}

#[test]
fn derivation_is_deterministic() {
    let (cred, _) = sas::derive_credential(&authority(), b"inquisitor");
    let (schema, _) = sas::derive_schema(&cred, SCHEMA_NAME, SCHEMA_VERSION);
    let hash = sas::hash_to_nonce(&skill_hash("some skill")).unwrap();

    let a = sas::derive_attestation(&cred, &schema, &hash);
    let b = sas::derive_attestation(&cred, &schema, &hash);

    // Two operators deriving independently must land on the same address, or
    // the whole shared-verdict premise collapses.
    assert_eq!(a, b);
}

#[test]
fn distinct_skills_derive_distinct_addresses() {
    let (cred, _) = sas::derive_credential(&authority(), b"inquisitor");
    let (schema, _) = sas::derive_schema(&cred, SCHEMA_NAME, SCHEMA_VERSION);

    let one = sas::hash_to_nonce(&skill_hash("skill one")).unwrap();
    let two = sas::hash_to_nonce(&skill_hash("skill two")).unwrap();

    assert_ne!(
        sas::derive_attestation(&cred, &schema, &one).0,
        sas::derive_attestation(&cred, &schema, &two).0
    );
}

#[test]
fn edited_skill_loses_its_verdict() {
    // The security property: any edit changes the hash, which changes the
    // address, so a verdict can never silently outlive the bytes it described.
    let (cred, _) = sas::derive_credential(&authority(), b"inquisitor");
    let (schema, _) = sas::derive_schema(&cred, SCHEMA_NAME, SCHEMA_VERSION);

    let original = sas::hash_to_nonce(&skill_hash("do the thing")).unwrap();
    let tampered = sas::hash_to_nonce(&skill_hash("do the thing evilly")).unwrap();

    assert_ne!(
        sas::derive_attestation(&cred, &schema, &original).0,
        sas::derive_attestation(&cred, &schema, &tampered).0
    );
}

#[test]
fn hash_to_nonce_round_trips() {
    let hex = skill_hash("content");
    let nonce = sas::hash_to_nonce(&hex).expect("valid hex");

    let mut rebuilt = String::new();
    for byte in nonce {
        use std::fmt::Write as _;
        write!(rebuilt, "{byte:02x}").unwrap();
    }
    assert_eq!(rebuilt, hex);
}

#[test]
fn hash_to_nonce_rejects_malformed_input() {
    assert!(sas::hash_to_nonce("").is_none());
    assert!(sas::hash_to_nonce("abcd").is_none(), "too short");
    assert!(sas::hash_to_nonce(&"z".repeat(64)).is_none(), "non-hex");
    assert!(sas::hash_to_nonce(&"a".repeat(65)).is_none(), "too long");
}

#[test]
fn payload_round_trips() {
    let payload = VerdictPayload {
        level: 3,
        score: 100,
        scanner_version: "0.1.0".to_string(),
        rule_ids: "exfil.secret_outbound,injection.conceal_from_operator".to_string(),
    };
    assert_eq!(VerdictPayload::decode(&payload.encode()), Some(payload));
}

#[test]
fn payload_decode_rejects_truncation() {
    let full = VerdictPayload {
        level: 1,
        score: 5,
        scanner_version: "0.1.0".to_string(),
        rule_ids: "egress.raw_ip".to_string(),
    }
    .encode();

    // A half-read account must not become a half-believed verdict.
    for cut in 0..full.len() {
        assert!(
            VerdictPayload::decode(&full[..cut]).is_none(),
            "truncation at {cut} decoded instead of failing"
        );
    }
    assert!(VerdictPayload::decode(&full).is_some());
}

#[test]
fn payload_stays_small() {
    // Rent scales with size, and every operator who scans a skill writes one.
    let payload = VerdictPayload {
        level: 3,
        score: 100,
        scanner_version: "0.1.0".to_string(),
        rule_ids: "exfil.secret_outbound,credential.secret_path,egress.suspicious_host,\
                   injection.conceal_from_operator,mismatch.undeclared_capability"
            .to_string(),
    };
    assert!(
        payload.encode().len() < 256,
        "payload grew to {} bytes",
        payload.encode().len()
    );
}
