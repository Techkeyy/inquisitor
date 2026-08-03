# Bounty requirements — self-audit

Checked against *"Build Solana-native plugins for Zeroclaw"* (Superteam Brasil).
Honest status, including what is **not** done.

## Submission format

| Requirement | Status |
|---|---|
| A working use case — real agent, real channel, real job involving Solana | **Done.** Agent runs on the `cli` channel, reads verdicts from Solana mainnet. Transcripts in `evidence/`. |
| Link to GitHub repo | **Done** — repo is the submission. |
| Showcase post in `#solana-bounty` | **Operator action.** Text ready in `SHOWCASE.md`. |
| Video, ≤3 minutes, real agent, no slides | **Operator action.** Shot list below. |
| Write-up covering the required points | **Done** — `SHOWCASE.md`. |
| Supporting material for quality/reliability | **Done** — `evidence/`, 59 tests, real-registry scan. |
| Secrets redacted | **Done.** No credential pattern in any tracked file; issuer keypair gitignored; all config values are public addresses. |
| No registry PR opened during the bounty | **Correct** — none opened. |

## Write-up content checklist

Every item the brief names, and where it lives in `SHOWCASE.md`:

| Required | Where |
|---|---|
| What it does | "What it does" |
| Who it's for | "Who it is for" |
| Which ZeroClaw features it uses | "ZeroClaw features used" — table of 7 |
| What you had to build vs compose | "What I built vs composed" |
| Custody tier | "Custody" — T0 read / T1 publish |
| Threat model | "Custody" — includes what it does *not* claim |
| Links to config / SOPs / skills / code | "Reproduce it" + repo |
| Prompt-injection transcript | "The prompt-injection test" |

## Custody ladder

Declared **T0 for the agent, T1 for publishing**, and enforced structurally
rather than promised:

- The agent holds no key and cannot sign. Publishing lives in a **separate
  crate**, so signing dependencies cannot reach the component even by accident.
- Plugin manifest declares exactly `config_read` + `http_client` — nothing else,
  and the two inert permission classes are not requested.
- The issuer key signs attestations and nothing else: never funded beyond fees,
  no token delegation, no reachable asset.
- No raw private key with "no caps, no allowlist, no approval gate" anywhere —
  the disqualifying pattern does not exist here because the agent never signs.

## Explicit rejection criteria

| "We will not accept…" | Why this is not that |
|---|---|
| Concepts, mockups, slideware | It runs. Mainnet attestations, agent transcripts, 59 tests. |
| A plugin with no use case | The use case is the submission; the plugin is one part of it. |
| Thin single-RPC wrappers padded into WASM | The scanner is ~1,400 lines of real logic with 59 tests. The RPC call is one line of a much larger thing, and the tool works with no network at all. |
| Raw private key, no caps/allowlist/approval | The agent holds no key. |
| Trading / sniper / "buy this token" agents | Not applicable — this is defensive tooling. |

## Judging criteria

| Criterion | Weight | Self-assessment |
|---|---|---|
| The use case | 30% | Real need, evidenced by an actual registry compromise. Runs daily via cron SOP. **Weakest point: days of history, not months.** |
| Safety & custody | 25% | Tier honest and structural. Fails closed. Injection transcript included. Third-party trust limited to RPC + SAS. |
| Craft | 20% | Pure core + thin glue, 59 tests, zero `unsafe`, no panics in library code, clippy and rustfmt clean, minimal declared permissions, correct Tier-1/Tier-3 layering. |
| Reproducibility | 15% | One-command build, documented config, works with no network, `--json` for automation. |
| Showcase | 10% | Write-up done; **video is an operator action.** |
| Tiebreak: build-in-public | — | **Not done.** No X posts during the bounty. |

## Traps the brief names

| Trap | Handling |
|---|---|
| 1. Blockhash expiry | Not applicable — no approval-queued transactions. Publishing is synchronous and operator-initiated. |
| 2. The wasm dependency wall | Hit it, measured it, documented it in `SHOWCASE.md` and `README.md`. |
| 3. Flooding the context window | Responses shaped to ~200 tokens; top 3 findings only; skill text never echoed back. |
| 4. `wit/v0` experimental, no `.frozen` | Documented. WIT copied from a pinned checkout. |
| 5. RPC keys in config, never code | Enforced via `__config`; user-supplied endpoints supported. |
| 6. Pyth deprecation | Not applicable — no price feeds. |
| 7. Design for polling, not webhooks | Pull-based by construction: one `getAccountInfo` per check, plus a cron SOP. No inbound ingress required. |

## Verification anyone can run

```bash
cargo test                                          # 59 tests
cargo clippy --all-targets                          # clean
cargo fmt --check                                   # clean
cargo build --release --target wasm32-wasip2        # component
cargo run --example scan -- tests/fixtures/poisoned-solana-helper.md   # exit 1
inquisitor-publish address <skill>                  # derive an address offline
```

## Not done — stated plainly

1. **Video not shot.** Operator action.
2. **Not posted** to `#solana-bounty`. Operator action.
3. **No build-in-public posts.** This is the stated tiebreak and it is forgone.
4. **Only the `cli` channel.** The brief's exemplar uses WhatsApp. For a tool
   operators use while installing skills, the terminal is arguably the honest
   home, but a messaging channel would demo more vividly and is not wired up.
5. **Days of usage history, not months.** No amount of building fixes this —
   only calendar time. The cron SOP accrues real logs daily from now.
6. **No issuer reputation weighting or multi-issuer consensus.** Today a reader
   trusts one pubkey or does not.

## Video shot list — 3 minutes

1. **0:00–0:25** Open the poisoned skill. Show the exfiltration line, then the
   concealment instruction wrapping across the newline.
2. **0:25–1:00** Agent without the gate follows it → show the attempt.
3. **1:00–1:40** Agent with Inquisitor → `MALICIOUS`, refuses, and calls out the
   concealment unprompted.
4. **1:40–2:15** Terminal: the verdict was served **from mainnet, not
   rescanned**. Open the attestation in an explorer.
5. **2:15–2:45** Second machine, no local scan — refuses instantly from the
   chain alone.
6. **2:45–3:00** `cargo test` (59 green) and the real-registry scan, 18/18 clean.

Record with a throwaway config so nothing needs blurring in post.
