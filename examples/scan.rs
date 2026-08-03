//! Scan skill files from the command line.
//!
//! The plugin path needs a host build to exercise; this does not. It runs the
//! exact same core, so it is the fastest way to check a skill, to demo the
//! verdict in a terminal, and to start using Inquisitor daily before the
//! component is wired in.
//!
//! ```text
//! cargo run --example scan -- tests/fixtures/poisoned-solana-helper.md
//! cargo run --example scan -- --json ~/.zeroclaw/skills/*/SKILL.md
//! ```
//!
//! Exit code is 0 for allow, 1 for block — so it drops into a pre-install hook
//! or CI step unchanged. `--json` exists for the same reason: a gate nobody can
//! automate is a gate people route around.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let quiet = args.iter().any(|a| a == "--quiet" || a == "-q");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

    if paths.is_empty() {
        eprintln!(
            "usage: scan [--json] [--quiet] <skill.md> [more.md ...]\n\n  \
             --json    emit one JSON record per file\n  \
             --quiet   print only what is blocked\n\n\
             exit 0 = all allowed, 1 = something blocked, 2 = usage or read error"
        );
        return ExitCode::from(2);
    }

    let mut blocked = false;
    let mut records = Vec::new();

    for path in &paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                return ExitCode::from(2);
            }
        };

        let verdict = inquisitor::scan::scan_skill(&content);
        blocked |= verdict.level.blocks();

        if json {
            records.push(serde_json::json!({
                "path": path,
                "skill_hash": verdict.skill_hash,
                "level": verdict.level,
                "score": verdict.score,
                "blocked": verdict.level.blocks(),
                "scanner_version": verdict.scanner_version,
                "findings": verdict.findings.iter().map(|f| serde_json::json!({
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "line": f.line,
                    "excerpt": f.excerpt,
                    "explanation": f.explanation,
                })).collect::<Vec<_>>(),
            }));
        } else if !quiet || verdict.level.blocks() {
            println!("── {path}");
            println!("{}", inquisitor::report::render(&verdict));
        }
    }

    if json {
        let summary = serde_json::json!({
            "scanned": paths.len(),
            "blocked": records.iter().filter(|r| r["blocked"] == true).count(),
            "results": records,
        });
        println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default());
    }

    if blocked {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
