# Inquisitor — MVP

**The checkpoint a ZeroClaw agent calls before ingesting any skill — and the public record of what it found.**

---

## The problem

ZeroClaw agents learn by installing **skills**: plain-text instruction files. The agent reads them and follows them. Anyone can publish one.

That is a code-execution path made of English sentences, and it is already under attack. Snyk's *ToxicSkills* study found ~1,200 malicious skills uploaded to OpenClaw's ClawHub registry — prompt injection in 36%, 1,467 malicious payloads, harvesting LLM API keys, SSH keys, browser vaults, and 60+ types of crypto wallet. 91% combined injection with conventional malware, which is why both AI safety filters and traditional scanners missed them.

A runtime whose entire premise is *"you own your keys and your machine"* has a front door where the thing you are most likely to install is the thing most likely to rob you.

The bounty brief names this problem and declines to solve it:

> "on-chain verification proves integrity, not trustworthiness — a skill is model-visible text, so review anything before your agent ingests it."

Review it with **what**. That is Inquisitor.

---

## The two halves

**1. The gate (local).** Deterministic scan of skill text *before* the agent reads it. Verdict in, block or allow out. No LLM in the hot path.

**2. The record (on-chain).** The verdict is published to Solana as a signed attestation, keyed by the skill's content hash. The next operator to consider that same skill reads the answer instead of re-deriving it — and can see who signed it.

### Why on-chain is load-bearing, not decorative

A self-hosted runtime has **no central authority** — that is the product. So the verdict registry cannot be one company's server, or you have merely swapped "trust the skill author" for "trust whoever runs the registry."

It has to be public, permissionless, and tamper-evident, with every entry signed by its issuer. That is Solana Attestation Service, live on mainnet.

Integrity proves the bytes did not change. **Trustworthiness means somebody looked and put their name on it.**

---

## Identity model

A skill is identified by `sha256(canonicalized content)`.

The hash is the attestation subject. Any edit produces a new hash, which has no attestation, which forces a rescan. Verdicts can never silently outlive the artifact they describe.

---

## Verdict taxonomy

Ported from HULL.

| Verdict | Meaning | Default action |
|---|---|---|
| `clean` | No findings | Allow |
| `caution` | Low-confidence signals | Allow + warn |
| `suspicious` | Multiple or medium-severity findings | Block, override allowed |
| `malicious` | High-confidence exfiltration or injection | Block, hard guard |

Plus: risk score 0–100, the rules that fired, and a one-line reason each.

---

## Detection rules — MVP set

Deterministic, grounded in the documented ToxicSkills techniques. No model calls.

1. **Exfiltration** — instructions to send, POST, or upload file contents outward
2. **Credential references** — keypair paths, `id.json`, seed phrase / mnemonic, private key, `.env`, browser vault paths
3. **Installer patterns** — `curl | bash`, `wget | sh`, global installs from non-registry URLs
4. **Model-directed injection** — text aimed at the model rather than the user: "ignore previous", "do not tell the user", fake `system:` turns, zero-width and bidi control characters
5. **Hardcoded egress** — raw IPs, pastebin, webhook.site, ngrok, Discord/Slack webhook URLs
6. **Declared-vs-actual mismatch** — frontmatter declares no permissions while the body instructs shell or network use
7. **Obfuscation** — base64/base58/hex blobs above a length threshold

Each rule returns a structured finding: id, severity, matched span, one-line explanation.

---

## Response shaping

Bounty trap #3 — a fat tool response nukes the agent's context and costs the operator money on every call.

Inquisitor returns **~200 tokens**: verdict, score, top three reasons, attestation reference. It never echoes skill text back into the context window. The full finding set stays available on disk for the human.

---

## Custody tiers — declared

| Path | Tier | Keys held |
|---|---|---|
| **Read / scan** | **T0** | None. Consuming verdicts requires no wallet at all. |
| **Publish verdict** | **T1** | A dedicated issuer keypair holding only fee SOL. It can sign attestations and nothing else — it is never funded, never approves token delegation, never touches value. |

The issuer key is compromise-tolerant by construction: worst case an attacker publishes false verdicts under an identity that consumers can then stop trusting. No funds are reachable from it, ever.

**Third-party trust declared:** the RPC endpoint (operator-supplied, defaults documented) and the SAS program itself. No MCP servers, no facilitators, no custodians.

---

## What ships in the MVP

- [ ] `inquisitor-core` — pure Rust scanner, 7 rule families, unit-tested against a corpus of real poisoned samples
- [ ] `inquisitor-plugin` — `wasm32-wasip2` tool plugin exposing `inquisitor_check`
- [ ] SAS **read** — look up an existing verdict by content hash before scanning
- [ ] SAS **write** — publish a verdict as an attestation
- [ ] `SKILL.md` — teaches the agent when to call the gate (correct Tier-1 layering: the skill owns the workflow, the plugin does the bounded work)
- [ ] One live block: a poisoned skill stopped in a running agent, transcript captured
- [ ] Second-machine demo: a fresh install refusing the same skill from the on-chain record alone

## Explicitly out of scope

Issuer reputation weighting · multi-issuer consensus · gitlana on-chain skill resolution · OSV/CVE lookup for skill dependencies · a web UI · registry-wide crawling

These are the write-up's "what's next", not day-six scope creep.
