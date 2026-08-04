//! Detection rules.
//!
//! Deliberately hand-rolled rather than regex-driven: a security scanner should
//! not carry a backtracking engine, the component stays small, and every match
//! is auditable by reading it.
//!
//! The rules encode the techniques documented in Snyk's *ToxicSkills* study of
//! the ClawHub registry compromise — prompt injection fused with conventional
//! credential theft — not hypotheticals.
//!
//! Two design decisions carry most of the weight:
//!
//! **Phrase rules run on flattened text** ([`crate::flat`]), because a phrase
//! that wraps across a newline is invisible to a line-based scan, and an
//! attacker who knows that will wrap on purpose.
//!
//! **The rules that matter fire on co-occurrence**, not on single words. A
//! legitimate Solana skill says "private key" constantly; one that says it next
//! to "upload" is a different claim.

use crate::flat::Flat;
use crate::verdict::{Finding, Severity};

/// Longest excerpt echoed back. Excerpts re-enter the agent's context window,
/// so they stay short on purpose.
const EXCERPT_MAX: usize = 80;

/// How close a verb and a secret must be to count as one instruction. Roughly
/// two lines of prose — local enough that the pairing means something.
const PROXIMITY: usize = 160;

/// Verbs that move data outward.
const EXFIL_VERBS: &[&str] = &[
    "send",
    "post ",
    "upload",
    "transmit",
    "exfiltrate",
    "forward",
    "publish",
    "submit",
    "report to",
    "beacon",
    "curl -d",
    "curl --data",
];

/// Nouns worth stealing.
const SECRET_NOUNS: &[&str] = &[
    "private key",
    "privatekey",
    "secret key",
    "seed phrase",
    "mnemonic",
    "keypair",
    "id.json",
    "credential",
    "password",
    "api key",
    "api_key",
    "access token",
    "auth token",
    "wallet file",
    ".env",
    "environment variable",
];

/// Paths that only ever hold secrets.
const SECRET_PATHS: &[&str] = &[
    "~/.config/solana",
    ".config/solana/id.json",
    "id.json",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    "wallet.json",
    "keystore.json",
    ".env",
    "login data",
    "key4.db",
    "logins.json",
    "cookies.sqlite",
];

/// Hosts that exist to receive things quietly.
const SUSPICIOUS_HOSTS: &[&str] = &[
    "pastebin.com",
    "webhook.site",
    "ngrok.io",
    "ngrok-free.app",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "hooks.slack.com",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "requestbin",
    "pipedream.net",
    "burpcollaborator",
];

/// Negations that flip an instruction into advice.
///
/// Security documentation legitimately says "never send your private key to
/// anyone". Firing on that would bury real findings under warnings about the
/// very skills doing the right thing, and a scanner operators learn to ignore
/// is worse than no scanner. The residual risk — an attacker burying a real
/// instruction behind a nearby negation — is covered by the concealment and
/// override rules, which carry no negation guard.
const NEGATIONS: &[&str] = &[
    "never",
    "do not",
    "don't",
    "avoid",
    "must not",
    "should not",
    "shouldn't",
    "no need to",
    "refuse to",
    "won't",
    "cannot",
    "can't",
];

/// How far back a negation can sit and still bind to what follows.
///
/// Deliberately short. A negation two sentences away is not negating this
/// clause, and a generous window is a laundering channel: write "never do
/// anything harmful" at the top of a file and every rule below goes quiet.
const NEGATION_WINDOW: usize = 40;

/// Phrases aimed at the model rather than the reader.
const INJECTION_PHRASES: &[&str] = &[
    "ignore previous instruction",
    "ignore all previous",
    "ignore prior instruction",
    "disregard the above",
    "disregard previous",
    "disregard all prior",
    "forget your instructions",
    "override your instructions",
    "new system prompt",
    "system prompt:",
];

/// Phrases whose entire purpose is concealment from the operator.
const DECEPTION_PHRASES: &[&str] = &[
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "do not mention",
    "don't mention",
    "without informing",
    "without the user knowing",
    "do not log",
    "don't log this",
    "hide this from",
    "conceal this",
];

/// Forged conversation-role markers.
const ROLE_MARKERS: &[&str] = &[
    "<|im_start|>",
    "<|im_end|>",
    "</system>",
    "<system>",
    "[system]",
    "[/inst]",
    "<<sys>>",
    "### system",
];

/// On-chain operations that hand over control irreversibly.
///
/// The brief puts it exactly right: an agent with key access and an LLM in the
/// loop is a hot wallet with a prompt-injection surface. These are the
/// instructions that turn that surface into a loss.
const AUTHORITY_OPS: &[&str] = &[
    "setauthority",
    "set_authority",
    "set authority",
    "mint authority",
    "freeze authority",
    "update authority",
    "upgrade authority",
    "authoritytype",
];

/// Operations that let someone else move your tokens later.
const DELEGATION_OPS: &[&str] = &[
    "approve",
    "delegate",
    "createapproveinstruction",
    "approvechecked",
    "spl-token approve",
    "allowance",
    "recurring delegation",
];

/// Closing an account sweeps its lamports somewhere.
const CLOSURE_OPS: &[&str] = &["closeaccount", "close_account", "close the token account"];

/// Phrases that remove the human from a value-moving decision.
///
/// This is the custody ladder's load-bearing assumption being attacked
/// directly: every T2 design in the brief rests on an approval gate, so a skill
/// that talks the agent past one is attacking the safety model itself, not just
/// the wallet.
const AUTO_APPROVE_PHRASES: &[&str] = &[
    "without asking",
    "without confirmation",
    "without prompting",
    "no need to confirm",
    "skip the approval",
    "skip approval",
    "bypass the approval",
    "bypass approval",
    "auto-approve",
    "auto approve",
    "automatically approve",
    "do not ask the user",
    "don't ask the user",
    "no confirmation needed",
    "raise the spend limit",
    "increase the cap",
    "disable the limit",
];

/// Signing something the agent has not decoded.
///
/// A base64 blob is not an intent. An agent that signs one has delegated its
/// judgement to whoever produced the bytes.
const BLIND_SIGN_PHRASES: &[&str] = &[
    "sign it as-is",
    "sign it as is",
    "sign whatever",
    "do not decode",
    "don't decode",
    "do not inspect the transaction",
    "without decoding",
    "without inspecting",
    "no need to decode",
    "no need to verify the transaction",
    "sign the base64",
    "sign this base64",
];

/// Verbs that move value on chain.
const TRANSFER_VERBS: &[&str] = &[
    "transfer",
    "send",
    "sweep",
    "withdraw",
    "drain",
    "move the funds",
    "move funds",
];

/// Shells a download can be piped into.
const SHELL_PIPES: &[&str] = &[
    "| bash",
    "|bash",
    "| sh",
    "|sh",
    "| zsh",
    "|zsh",
    "| sudo bash",
    "| sudo sh",
    "| powershell",
    "| pwsh",
    "| fish",
];

/// Scan `content`, returning every finding. `declared_permissions` comes from
/// the skill's own frontmatter and drives the declared-vs-actual check.
pub fn scan(content: &str, declared_permissions: &[String]) -> Vec<Finding> {
    let flat = Flat::new(content);
    let mut findings = Vec::new();

    check_exfiltration(&flat, &mut findings);
    check_secret_paths(&flat, &mut findings);
    check_piped_installer(&flat, &mut findings);
    check_phrases(
        &flat,
        INJECTION_PHRASES,
        "injection.instruction_override",
        Severity::High,
        "Attempts to override the agent's existing instructions.",
        &mut findings,
    );
    check_phrases(
        &flat,
        DECEPTION_PHRASES,
        "injection.conceal_from_operator",
        Severity::Critical,
        "Instructs the agent to hide its actions from the operator.",
        &mut findings,
    );
    check_phrases(
        &flat,
        ROLE_MARKERS,
        "injection.forged_role_marker",
        Severity::High,
        "Contains conversation-role markers that can forge a system turn.",
        &mut findings,
    );
    check_phrases(
        &flat,
        SUSPICIOUS_HOSTS,
        "egress.suspicious_host",
        Severity::High,
        "Points at a host commonly used to collect exfiltrated data.",
        &mut findings,
    );
    check_raw_ip_url(&flat, &mut findings);
    check_solana_authority(&flat, &mut findings);
    check_solana_delegation(&flat, &mut findings);
    check_solana_closure(&flat, &mut findings);
    check_approval_bypass(&flat, &mut findings);
    check_phrases(
        &flat,
        BLIND_SIGN_PHRASES,
        "solana.blind_signing",
        Severity::High,
        "Tells the agent to sign a transaction it has not decoded.",
        &mut findings,
    );

    // Character-level rules stay per line: flattening would splice separate
    // lines into one run and invent blobs that are not there.
    for (idx, line) in content.lines().enumerate() {
        check_hidden_characters(line, idx + 1, &mut findings);
        check_encoded_blob(line, idx + 1, &mut findings);
    }

    check_declared_mismatch(&flat, declared_permissions, &mut findings);

    findings
}

// ---------------------------------------------------------------------------
// Exfiltration: a verb that moves data, close to something worth stealing.
// Either alone is ordinary; together they are an instruction to steal.
// ---------------------------------------------------------------------------

fn check_exfiltration(flat: &Flat, out: &mut Vec<Finding>) {
    for verb in EXFIL_VERBS {
        for noun in SECRET_NOUNS {
            let Some(at) = flat.near(verb, noun, PROXIMITY) else {
                continue;
            };
            // Advice, not instruction — see NEGATIONS. Only a negation that
            // precedes the verb counts, so a distant "never" elsewhere in the
            // document cannot launder a real instruction.
            if flat.preceded_by(at, NEGATIONS, NEGATION_WINDOW) {
                continue;
            }
            out.push(Finding {
                rule_id: "exfil.secret_outbound",
                severity: Severity::Critical,
                line: flat.line_of(at),
                excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                explanation: "Instructs the agent to send credential material somewhere.",
            });
            return;
        }
    }
}

// ---------------------------------------------------------------------------

fn check_secret_paths(flat: &Flat, out: &mut Vec<Finding>) {
    for path in SECRET_PATHS {
        for at in flat.find_all(path) {
            // "Never modify `.env` files" is a skill doing the right thing.
            // Flagging it teaches operators to ignore the scanner, which costs
            // more than the rule earns. Found by running against the real
            // registry, where `auto-coder` tripped on exactly this sentence.
            if flat.preceded_by(at, NEGATIONS, NEGATION_WINDOW) {
                continue;
            }
            out.push(Finding {
                rule_id: "credential.secret_path",
                severity: Severity::High,
                line: flat.line_of(at),
                excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                explanation: "References a file path that holds keys or credentials.",
            });
            return;
        }
    }
}

// ---------------------------------------------------------------------------

fn check_piped_installer(flat: &Flat, out: &mut Vec<Finding>) {
    for pipe in SHELL_PIPES {
        for at in flat.find_all(pipe) {
            let fetches = ["curl ", "wget ", "iwr "]
                .iter()
                .any(|f| flat.near(pipe, f, PROXIMITY).is_some());
            if fetches {
                out.push(Finding {
                    rule_id: "installer.pipe_to_shell",
                    severity: Severity::Critical,
                    line: flat.line_of(at),
                    excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                    explanation: "Pipes a downloaded script directly into a shell.",
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------

fn check_phrases(
    flat: &Flat,
    phrases: &[&str],
    rule_id: &'static str,
    severity: Severity,
    explanation: &'static str,
    out: &mut Vec<Finding>,
) {
    for phrase in phrases {
        let hits = flat.find_all(phrase);
        if let Some(&at) = hits.first() {
            out.push(Finding {
                rule_id,
                severity,
                line: flat.line_of(at),
                excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                explanation,
            });
            return;
        }
    }
}

// ---------------------------------------------------------------------------

/// A bare IPv4 in a URL — legitimate skills name hosts, not addresses.
fn check_raw_ip_url(flat: &Flat, out: &mut Vec<Finding>) {
    for scheme in ["http://", "https://"] {
        for at in flat.find_all(scheme) {
            let after = &flat.lower[at + scheme.len()..];
            let host: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let octets: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
            let terminated = after
                .chars()
                .nth(host.chars().count())
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.');
            if octets.len() == 4 && terminated && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
                out.push(Finding {
                    rule_id: "egress.raw_ip",
                    severity: Severity::Medium,
                    line: flat.line_of(at),
                    excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                    explanation: "Uses a bare IP address instead of a named host.",
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Solana-native rules.
//
// Every Solana skill worth installing discusses `setAuthority` and `approve` —
// that is what the SPL token program does. Firing on the mention would flag the
// entire ecosystem, so these require a second signal that the text is an
// *instruction aimed at the operator's assets* rather than documentation:
// either a hardcoded destination address, or a phrase removing the human from
// the decision. Documentation has neither.
// ---------------------------------------------------------------------------

/// Does this look like a base58-encoded Solana address?
///
/// 32–44 characters from the base58 alphabet with at least one digit. English
/// words do not reach 32 characters, and the digit requirement excludes the
/// long identifiers that appear in prose.
fn looks_like_pubkey(token: &str) -> bool {
    const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let len = token.chars().count();
    if !(32..=44).contains(&len) {
        return false;
    }
    token.chars().all(|c| B58.contains(c)) && token.chars().any(|c| c.is_ascii_digit())
}

/// Byte offset of the first hardcoded address, if any.
///
/// Matching runs on the original-case text: base58 is case-sensitive, and the
/// lowercased view would turn a valid address into something that is not one.
fn first_pubkey(flat: &Flat) -> Option<usize> {
    let raw = flat.original();
    let bytes = raw.as_bytes();
    let mut start = None;

    for (i, &b) in bytes.iter().enumerate() {
        let boundary = !b.is_ascii_alphanumeric();
        match (start, boundary) {
            (None, false) => start = Some(i),
            (Some(s), true) => {
                if looks_like_pubkey(&raw[s..i]) {
                    return Some(s);
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && looks_like_pubkey(&raw[s..])
    {
        return Some(s);
    }
    None
}

/// Fire when a dangerous operation is accompanied by a hardcoded destination or
/// a phrase that removes the operator from the decision.
fn check_dangerous_op(
    flat: &Flat,
    ops: &[&str],
    rule_id: &'static str,
    severity: Severity,
    explanation: &'static str,
    out: &mut Vec<Finding>,
) {
    let address_at = first_pubkey(flat);

    for op in ops {
        for at in flat.find_all(op) {
            if NEGATIONS
                .iter()
                .any(|n| flat.preceded_by(at, &[n], NEGATION_WINDOW))
            {
                continue;
            }

            let bypasses = AUTO_APPROVE_PHRASES
                .iter()
                .any(|p| flat.near_loose(op, p, PROXIMITY).is_some());
            let targets_address = address_at.is_some_and(|a| a.abs_diff(at) <= PROXIMITY * 2);

            if bypasses || targets_address {
                out.push(Finding {
                    rule_id,
                    severity,
                    line: flat.line_of(at),
                    excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                    explanation,
                });
                return;
            }
        }
    }
}

fn check_solana_authority(flat: &Flat, out: &mut Vec<Finding>) {
    check_dangerous_op(
        flat,
        AUTHORITY_OPS,
        "solana.authority_handover",
        Severity::Critical,
        "Instructs the agent to hand over mint, freeze, or upgrade authority.",
        out,
    );
}

fn check_solana_delegation(flat: &Flat, out: &mut Vec<Finding>) {
    check_dangerous_op(
        flat,
        DELEGATION_OPS,
        "solana.token_delegation",
        Severity::Critical,
        "Grants another address standing permission to move the operator's tokens.",
        out,
    );
}

fn check_solana_closure(flat: &Flat, out: &mut Vec<Finding>) {
    check_dangerous_op(
        flat,
        CLOSURE_OPS,
        "solana.account_closure",
        Severity::High,
        "Closes a token account, sweeping its lamports to a given destination.",
        out,
    );
}

/// Removing the human from a value-moving decision.
///
/// Scored `Critical` on its own because it attacks the safety model rather than
/// the wallet: every T2 design in the custody ladder rests on an approval gate,
/// so text that talks the agent past one has defeated the design, whatever it
/// does next.
fn check_approval_bypass(flat: &Flat, out: &mut Vec<Finding>) {
    for phrase in AUTO_APPROVE_PHRASES {
        for at in flat.find_all(phrase) {
            // "Do not close a token account without confirmation" is the
            // opposite of what this rule looks for. Security documentation is
            // written almost entirely in this shape, so the guard belongs here
            // more than anywhere else in the file.
            if NEGATIONS
                .iter()
                .any(|n| flat.preceded_by(at, &[n], NEGATION_WINDOW))
            {
                continue;
            }

            let moves_value = TRANSFER_VERBS
                .iter()
                .chain(DELEGATION_OPS.iter())
                .chain(AUTHORITY_OPS.iter())
                .any(|v| flat.near_loose(phrase, v, PROXIMITY).is_some())
                || flat.near_loose(phrase, "sign", PROXIMITY).is_some()
                || flat.near_loose(phrase, "transaction", PROXIMITY).is_some();

            if moves_value {
                out.push(Finding {
                    rule_id: "solana.approval_bypass",
                    severity: Severity::Critical,
                    line: flat.line_of(at),
                    excerpt: excerpt(flat.window(at, EXCERPT_MAX)),
                    explanation: "Tells the agent to move value without operator confirmation.",
                });
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Invisible characters. A skill is text a human is meant to read; text a human
// cannot see is there to be read by the model alone.
// ---------------------------------------------------------------------------

fn check_hidden_characters(raw: &str, line: usize, out: &mut Vec<Finding>) {
    let hidden = raw.chars().any(|c| {
        matches!(c,
            '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}'..='\u{2064}'
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            | '\u{E0000}'..='\u{E007F}'
        )
    });
    if hidden {
        let visible: String = raw
            .chars()
            .filter(|c| !c.is_control() && !is_invisible(*c))
            .collect();
        out.push(Finding {
            rule_id: "obfuscation.hidden_characters",
            severity: Severity::Critical,
            line,
            excerpt: excerpt(&visible),
            explanation: "Contains invisible characters that hide text from human review.",
        });
    }
}

fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}'..='\u{2064}'
        | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        | '\u{E0000}'..='\u{E007F}'
    )
}

// ---------------------------------------------------------------------------
// Long encoded runs. Skills are prose; a wall of base64 is a payload.
// ---------------------------------------------------------------------------

const BLOB_MIN: usize = 120;

fn check_encoded_blob(raw: &str, line: usize, out: &mut Vec<Finding>) {
    let mut run = 0usize;
    let mut best = 0usize;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    if best >= BLOB_MIN {
        out.push(Finding {
            rule_id: "obfuscation.encoded_blob",
            severity: Severity::Medium,
            line,
            excerpt: excerpt(raw),
            explanation: "Contains a long encoded run that may conceal a payload.",
        });
    }
}

// ---------------------------------------------------------------------------
// The skill declares no privileged needs but instructs privileged work.
// ---------------------------------------------------------------------------

fn check_declared_mismatch(flat: &Flat, declared: &[String], out: &mut Vec<Finding>) {
    if !declared.is_empty() {
        return;
    }
    let wants_shell = [
        "run the command",
        "execute the following",
        "in your terminal",
        "bash -c",
    ]
    .iter()
    .any(|p| flat.contains(p));
    let wants_net = ["curl ", "wget ", "http://", "https://"]
        .iter()
        .any(|p| flat.contains(p));

    if wants_shell || wants_net {
        out.push(Finding {
            rule_id: "mismatch.undeclared_capability",
            severity: Severity::Medium,
            line: 1,
            excerpt: String::from("frontmatter declares no permissions"),
            explanation: "Declares no permissions but instructs shell or network use.",
        });
    }
}

// ---------------------------------------------------------------------------

/// Trim and cap text for safe echo back into the agent's context.
fn excerpt(text: &str) -> String {
    let t = text.trim();
    if t.chars().count() <= EXCERPT_MAX {
        return t.to_string();
    }
    let cut: String = t.chars().take(EXCERPT_MAX).collect();
    format!("{cut}…")
}
