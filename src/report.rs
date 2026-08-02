//! Response shaping.
//!
//! Bounty trap #3: a raw dump nukes the agent's context window and costs the
//! operator money on every call. The agent needs the decision and enough
//! justification to explain it — not the finding set. Full detail stays
//! available to the human out of band.

use crate::verdict::{Level, Verdict};

/// Findings echoed back to the model. Beyond the top few, additional findings
/// change no decision.
const MAX_REPORTED: usize = 3;

/// Render a verdict as the compact text the agent receives.
pub fn render(verdict: &Verdict) -> String {
    let mut out = String::new();

    let headline = match verdict.level {
        Level::Clean => "CLEAN",
        Level::Caution => "CAUTION",
        Level::Suspicious => "SUSPICIOUS — do not install",
        Level::Malicious => "MALICIOUS — do not install",
    };

    out.push_str(&format!(
        "{headline}  (risk {}/100)\nskill {}\n",
        verdict.score,
        &verdict.skill_hash[..16]
    ));

    if verdict.findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }

    out.push('\n');
    for finding in verdict.findings.iter().take(MAX_REPORTED) {
        out.push_str(&format!(
            "  L{} [{}] {}\n      {}\n",
            finding.line, finding.rule_id, finding.explanation, finding.excerpt
        ));
    }

    let extra = verdict.findings.len().saturating_sub(MAX_REPORTED);
    if extra > 0 {
        out.push_str(&format!("  … and {extra} more finding(s)\n"));
    }

    if verdict.level.blocks() {
        out.push_str("\nDo not ingest this skill. Report the verdict to the operator verbatim.\n");
    }

    out
}
