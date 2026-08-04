# Inquisitor — Build Plan

**Deadline: ~Fri 7 Aug 2026** (bounty listing showed 6d 8h remaining on 1 Aug).
**Judging: 21 Aug.**

Six days. The plan is ordered by *risk*, not by architecture — the thing most likely to kill the project is scheduled first.

---

## Day 1 — The risk gate (do not skip, do not reorder)

Two unknowns can invalidate the whole approach. Answer both before writing a line of scanner logic.

### 1a. Does a plugin actually instantiate in the ZeroClaw host?

The brief admits the Solana crates are **compile-verified as a library, not exercised as an instantiated component** inside the host, whose WASI capability grants are narrower.

- Clone `zeroclaw-labs/zeroclaw`, read `wit/v0/*.wit` — **the .wit files are the spec, not the docs**
- Copy `plugins/redact-text` layout exactly
- Build the host: `cargo build --release --features plugins-wasm-cranelift`
- Set `plugins.enabled = true`, add a config entry
- Get a hello-world tool plugin returning a fixed string, called from a live agent

**Gate:** if this does not run by end of Day 1, stop and reassess. Everything downstream assumes it.

### 1b. Nail down SAS

Confirmed so far: Rust client crate is `solana-attestation-service-client`; the model is **credential → schema → attestation**; schema layout is a type-code array (12 = String, 0 = U8); attestations are immutable signed claims by an authority.

**Still unverified — resolve on Day 1:**
- Program ID and PDA seeds (do not trust any secondary source for this; read the program repo)
- Whether `solana-attestation-service-client` compiles to `wasm32-wasip2`, or whether instructions must be hand-encoded
- Expiry and revocation semantics
- Cost per attestation (rent) — this decides whether per-skill attestations are economically sane

**If the client does not build for wasip2:** hand-encode. The bounty pays points for documenting exactly this, and the modular `solana-pubkey` / `solana-instruction` / `solana-message` crates are already compile-verified for the target.

### 1c. Start running something today

30% of the score is "are YOU running it." History cannot be manufactured on Day 6. Even a crude local-only scanner wired into your own agent, logging to a file, starts accumulating real evidence tonight.

**Also today:** first build-in-public post on X. It is the stated tiebreak.

---

## Day 2 — `inquisitor-core`

Pure Rust, zero I/O, fully deterministic. This is the craft score.

- Types: `Finding { rule_id, severity, span, explanation }`, `Verdict { level, score, findings }`
- The 7 rule families from MVP.md
- Content canonicalization + `sha256` → the skill's identity
- **Build the corpus first.** Real poisoned samples derived from the documented ToxicSkills techniques, plus clean skills from `zeroclaw-labs/zeroclaw-skills` as negative cases. Tests are worthless without both.
- Target: every rule has a positive case, a negative case, and a near-miss

No network. No host calls. This crate must be testable with `cargo test` on the host machine — mocked RPC only, per the brief.

---

## Day 3 — `inquisitor-plugin`

- `wasm32-wasip2` component implementing the `tool-plugin` world
- Exports: `name`, `description`, `parameters-schema`, `execute`
- Permissions declared: `http_client`, `config_read` — **and nothing else**
- Thin `#[cfg(target_family = "wasm")]` shim over the pure core, per `plugins/redact-text`
- Config injected under `__config`: RPC URL, issuer pubkey, thresholds. **No secrets in code.**
- Structured logging via the `logging` import
- **Response shaping to ~200 tokens.** Judges will look at what tools return.
- Manifest declares only what is used

**End of day:** a poisoned skill blocked in a live agent, transcript saved.

---

## Day 4 — Solana

- **Read path first** (it is T0 and cannot break anything): given a content hash, query SAS for an existing attestation. Hit → return the cached verdict, skip the scan entirely.
- **Then write path:** publish a verdict as an attestation. Dedicated issuer keypair, fee SOL only.
- Schema design: `{ skill_hash: String, verdict: U8, score: U8, rule_ids: String, scanner_version: String }` — keep it tight, rent scales with size.
- Devnet throughout. Move to mainnet only once stable, and only if rent cost is trivial.

---

## Day 5 — Make it real

- Run it against genuinely installed skills, not just the corpus
- **Build the second-machine demo:** a clean install that refuses a known-bad skill purely from the on-chain record, without downloading or scanning it. This is the showcase's whole argument.
- Capture the prompt-injection transcript: a skill that tries to talk the agent past the gate, and the gate holding
- Gather the "I actually run this" evidence — logs, channel history, dated screenshots
- README with a from-zero reproduction path (15% of the score is another operator replicating it in an evening)

---

## Day 6 — Ship

- **Video, ≤3 min.** Terminal + agent. Four beats:
  1. The poisoned skill — show the malicious line hiding in ordinary instructions
  2. The agent reads it without the gate → tries to exfiltrate
  3. With Inquisitor → blocked, verdict written to Solana, show the explorer
  4. **Second machine refuses it instantly from the chain alone** ← the money shot
- **Write-up** in `#solana-bounty`: what it does, who it is for, ZeroClaw features used, what was built vs composed, **custody tier and threat model**, config/SOP/skill/code links, injection transcript, secrets redacted
- **Lead the write-up with the load-bearing argument:** a runtime with no central authority cannot have a central trust database. Do not bury this — it is the one thing a skeptical judge will push on.
- Do **not** open a registry PR. The brief says merges happen after judging.

---

## Standing rules

- **Redaction:** use a throwaway demo config with disposable keys so nothing needs blurring in post
- **RPC:** paid key before filming; public endpoints throttle during the one good take
- **Commit as `Techkeyy`** (`israelolawale891@gmail.com`) — never add Claude as a contributor
- **Determinism in demos:** pin the model, low temperature; LLM phrasing variance breaks continuity between takes
- Keep the repo in your own account and link it from the showcase

---

## Kill criteria

If Day 1's plugin gate fails and cannot be fixed by end of Day 2, fall back to a **Tier 1 submission**: the same scanner as a well-written skill using the built-in `http_request` tool, plus the SAS read/write path. Weaker craft score, same use case, same safety story, still ships. Correct layering is scored — a Tier 1 solution that works beats a Tier 3 that does not.

---

## Scoring self-check

| Criterion | Weight | Where it is earned |
|---|---|---|
| Use case | 30% | Real daily need; you run it; a stranger would keep running it |
| Safety & custody | 25% | T0 read / T1 write, honestly declared; injection transcript; minimal third-party trust |
| Craft | 20% | Pure core + thin shim; real tests; correct layering; declared-minimal permissions |
| Reproducibility | 15% | README, config, one-command build, throwaway demo setup |
| Showcase | 10% | Four-beat video; second-machine moment |
| Tiebreak | — | Build-in-public posts, starting Day 1 |
