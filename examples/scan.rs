//! Scan skill files from the command line.
//!
//! The plugin path needs a host build to exercise; this does not. It runs the
//! exact same core, so it is the fastest way to check a skill, to demo the
//! verdict in a terminal, and to start using Inquisitor daily before the
//! component is wired in.
//!
//! ```text
//! cargo run --example scan -- tests/fixtures/poisoned-solana-helper.md
//! ```
//!
//! Exit code is 0 for allow, 1 for block — so it drops into a pre-install hook
//! or CI step unchanged.

use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();

    if paths.is_empty() {
        eprintln!("usage: scan <skill.md> [more.md ...]");
        return ExitCode::from(2);
    }

    let mut blocked = false;

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

        println!("── {path}");
        println!("{}", inquisitor::report::render(&verdict));
    }

    if blocked {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
