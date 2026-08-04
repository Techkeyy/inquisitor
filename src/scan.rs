//! Scan orchestration: canonicalize, hash, parse frontmatter, apply rules.

use sha2::{Digest, Sha256};

use crate::rules;
use crate::verdict::Verdict;

/// Normalize content so the same skill hashes identically regardless of how it
/// travelled here.
///
/// This is load-bearing: the hash is the attestation subject, so a verdict
/// published by one operator must be findable by the next. Normalization is
/// intentionally minimal — CRLF and trailing whitespace only. Anything more
/// aggressive would let two materially different files collide onto one
/// verdict, which is the failure mode that matters.
pub fn canonicalize(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for line in content.replace("\r\n", "\n").replace('\r', "\n").lines() {
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// `sha256` of the canonicalized content, lowercase hex.
pub fn skill_hash(content: &str) -> String {
    let canonical = canonicalize(content);
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Pull the `permissions` list out of `SKILL.md` YAML frontmatter.
///
/// Deliberately not a YAML parser: we need exactly one field, and pulling in a
/// full parser to read it would be a larger attack surface than the thing it
/// reads. Handles both inline (`permissions: [a, b]`) and block (`- a`) forms.
/// A malformed or absent block yields an empty list, which is the conservative
/// answer — it makes the declared-vs-actual rule *more* likely to fire.
pub fn declared_permissions(content: &str) -> Vec<String> {
    let canonical = canonicalize(content);
    let mut lines = canonical.lines();

    if lines.next().is_none_or(|l| l.trim() != "---") {
        return Vec::new();
    }

    let mut perms = Vec::new();
    let mut in_block = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            break;
        }

        if in_block {
            if let Some(item) = trimmed.strip_prefix("- ") {
                perms.push(clean_scalar(item));
                continue;
            }
            // Any non-item line ends the block.
            in_block = false;
        }

        let Some(rest) = trimmed.strip_prefix("permissions:") else {
            continue;
        };
        let rest = rest.trim();

        if rest.is_empty() {
            in_block = true;
        } else if let Some(inner) = rest.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            perms.extend(inner.split(',').map(clean_scalar).filter(|s| !s.is_empty()));
        } else {
            perms.push(clean_scalar(rest));
        }
    }

    perms.retain(|p| !p.is_empty());
    perms
}

fn clean_scalar(raw: &str) -> String {
    raw.trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim()
        .to_string()
}

/// Scan a skill and return its verdict.
/// Largest input scanned in full.
///
/// Real skills are kilobytes. This ceiling exists for two reasons found by
/// stress testing: a 10 MB input takes seconds to scan, which inside the wasm
/// component risks exhausting the fuel budget and **trapping** — the call fails
/// instead of returning a verdict, and a gate that errors is a gate that gets
/// bypassed. And an instruction file that size is not a normal skill in the
/// first place.
pub const MAX_SCAN_BYTES: usize = 1024 * 1024;

pub fn scan_skill(content: &str) -> Verdict {
    let hash = skill_hash(content);

    // Refuse rather than grind, and refuse *loudly*. Returning `Clean` for
    // anything unscanned would make oversizing the input a way to switch the
    // gate off.
    if content.len() > MAX_SCAN_BYTES {
        return Verdict::new(
            hash,
            vec![crate::verdict::Finding {
                rule_id: "input.too_large",
                severity: crate::verdict::Severity::High,
                line: 1,
                excerpt: format!(
                    "{} bytes exceeds the {} byte scan limit",
                    content.len(),
                    MAX_SCAN_BYTES
                ),
                explanation: "Too large to scan; an instruction file this size is not normal.",
            }],
        );
    }

    let declared = declared_permissions(content);
    let findings = rules::scan(&canonicalize(content), &declared);
    Verdict::new(hash, findings)
}
