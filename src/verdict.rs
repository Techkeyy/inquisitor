//! Verdict types.
//!
//! A scan produces [`Findings`](Finding), findings carry [`Severity`], and the
//! aggregate severity maps to a [`Level`]. Nothing here does I/O.

use serde::{Deserialize, Serialize};

/// How bad one finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not worth blocking on its own.
    Low,
    /// Suspicious in context; several of these add up.
    Medium,
    /// Strong signal of intent to do something the operator did not ask for.
    High,
    /// Unambiguous. One of these is enough.
    Critical,
}

impl Severity {
    /// Score contribution. Deliberately super-linear: one Critical outweighs
    /// any pile of Lows, because "many small smells" and "one exfiltration
    /// instruction" are not the same claim.
    pub const fn weight(self) -> u32 {
        match self {
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 40,
            Severity::Critical => 100,
        }
    }
}

/// The overall call on a skill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// No findings.
    Clean,
    /// Low-confidence signals. Allow, but say something.
    Caution,
    /// Block by default; the operator may override.
    Suspicious,
    /// Block. Not overridable through the agent.
    Malicious,
}

impl Level {
    /// Map an accumulated score to a level.
    pub const fn from_score(score: u32) -> Self {
        match score {
            0 => Level::Clean,
            1..=14 => Level::Caution,
            15..=79 => Level::Suspicious,
            _ => Level::Malicious,
        }
    }

    /// Whether the agent should be allowed to ingest the skill.
    pub const fn blocks(self) -> bool {
        matches!(self, Level::Suspicious | Level::Malicious)
    }

    /// Compact wire form for the on-chain attestation (schema keeps this a u8).
    pub const fn as_u8(self) -> u8 {
        match self {
            Level::Clean => 0,
            Level::Caution => 1,
            Level::Suspicious => 2,
            Level::Malicious => 3,
        }
    }
}

/// One thing the scanner noticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier, e.g. `exfil.outbound_post`. Stable across versions so
    /// attestations stay comparable.
    pub rule_id: &'static str,
    pub severity: Severity,
    /// 1-based line number in the scanned content.
    pub line: usize,
    /// The matched text, trimmed and length-capped. Never the whole line: this
    /// travels back into the agent's context.
    pub excerpt: String,
    /// One sentence, written for a human deciding whether to install.
    pub explanation: &'static str,
}

/// The result of scanning one skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// `sha256` of the canonicalized content, lowercase hex. The attestation subject.
    pub skill_hash: String,
    pub level: Level,
    /// 0–100, saturating.
    pub score: u32,
    pub findings: Vec<Finding>,
    /// Scanner version that produced this verdict, so a stale attestation is
    /// recognisable as stale.
    pub scanner_version: &'static str,
}

impl Verdict {
    /// Build a verdict from findings, computing score and level.
    pub fn new(skill_hash: String, mut findings: Vec<Finding>) -> Self {
        // Worst first: the agent only ever sees the top few.
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.line.cmp(&b.line)));

        let score = findings
            .iter()
            .map(|f| f.severity.weight())
            .sum::<u32>()
            .min(100);

        Self {
            skill_hash,
            level: Level::from_score(score),
            score,
            findings,
            scanner_version: crate::VERSION,
        }
    }
}
