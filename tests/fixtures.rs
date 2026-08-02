//! End-to-end checks against realistic full skill files.
//!
//! The unit tests in `rules.rs` prove each rule in isolation on one-liners.
//! These prove the whole scan on files shaped like something an operator would
//! actually install — which is where over- and under-firing show up.

use std::path::PathBuf;

use inquisitor::scan::scan_skill;
use inquisitor::verdict::Level;

fn fixture(name: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()))
}

#[test]
fn poisoned_helper_is_blocked() {
    let v = scan_skill(&fixture("poisoned-solana-helper.md"));

    assert_eq!(v.level, Level::Malicious);
    assert!(v.level.blocks());

    // The attack is a chain, not one line. All four links should be visible,
    // because the write-up and the operator both need to see the shape of it.
    for expected in [
        "exfil.secret_outbound",
        "credential.secret_path",
        "egress.suspicious_host",
        "injection.conceal_from_operator",
    ] {
        assert!(
            v.findings.iter().any(|f| f.rule_id == expected),
            "expected {expected} to fire; got {:?}",
            v.findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }
}

#[test]
fn clean_skill_stays_clean_despite_security_prose() {
    // This fixture deliberately contains "Never send your private key or seed
    // phrase to any skill" — the exact sentence that would make a naive
    // scanner flag the most responsible skills in the registry.
    let v = scan_skill(&fixture("clean-solana-balance.md"));

    assert_eq!(
        v.level,
        Level::Clean,
        "false positives on a legitimate skill: {:?}",
        v.findings
    );
}

#[test]
fn verdicts_are_reproducible() {
    let content = fixture("poisoned-solana-helper.md");
    let first = scan_skill(&content);
    let second = scan_skill(&content);

    // Same bytes must yield the same hash, score, and ordering — otherwise an
    // attestation published by one operator cannot be checked by the next.
    assert_eq!(first, second);
}

#[test]
fn distinct_skills_get_distinct_hashes() {
    let a = scan_skill(&fixture("poisoned-solana-helper.md"));
    let b = scan_skill(&fixture("clean-solana-balance.md"));
    assert_ne!(a.skill_hash, b.skill_hash);
}
