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

/// Render a verdict that was already published on chain by someone else.
///
/// This is the payoff of putting verdicts on a public ledger: the second
/// operator to meet a skill spends one `getAccountInfo` instead of a scan, and
/// can see who vouched for the answer.
pub fn render_published(published: &crate::onchain::PublishedVerdict) -> String {
    let p = &published.payload;
    let level = match p.level {
        0 => "CLEAN",
        1 => "CAUTION",
        2 => "SUSPICIOUS — do not install",
        _ => "MALICIOUS — do not install",
    };

    let mut out = format!(
        "{level}  (risk {}/100)\nverdict published on-chain — not rescanned locally\n",
        p.score
    );

    if let Some(signer) = published.signer {
        let s = signer.to_string();
        let short = if s.len() > 12 { format!("{}…{}", &s[..6], &s[s.len() - 4..]) } else { s };
        out.push_str(&format!("issuer  {short}\n"));
    }
    out.push_str(&format!("account {}\n", published.address));

    if !p.rule_ids.is_empty() {
        out.push_str(&format!("rules   {}\n", p.rule_ids));
    }
    out.push_str(&format!("scanner {}\n", p.scanner_version));

    if p.level >= 2 {
        out.push_str("\nDo not ingest this skill. Report the verdict to the operator verbatim.\n");
    }
    out.push_str(
        "\nAn issuer's verdict is a claim, not proof. Trust it only as far as you trust the issuer.\n",
    );

    out
}

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
