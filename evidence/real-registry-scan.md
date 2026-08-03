# Real-registry scan

Date: 2026-08-03T16:47:57Z
Source: github.com/zeroclaw-labs/zeroclaw-skills @ master

18 published skills scanned. **Zero findings.**

This number is the point. Two false positives showed up on the first run
and both were fixed by making the rules stricter, not by muting them:

1. `auto-coder` — flagged for "**Never** modify `.env` files, credentials".
   A skill penalised for telling the agent not to touch secrets. Negation
   guards now cover the credential-path rule, and must precede the match
   within 40 characters so a distant "never" cannot launder an instruction.

2. `sql-executor` — scored MALICIOUS 100 because "sending" and
   "credentials" sat in two unrelated bullet points that the proximity
   window spanned. Co-occurrence is now confined to a single sentence or
   list item.

Fixing the second surfaced a third bug: sentence splitting on any `.` was
cutting `~/.config/solana/id.json` in half, which would have quietly
disabled the exfiltration rule on the exact paths it exists to catch. A
terminator now only ends a sentence when whitespace follows.

All three are locked in by tests taken verbatim from the real files.

## Verdicts

```
scanned 18, blocked 0

  CLEAN         0  api-tester
  CLEAN         0  auto-coder
  CLEAN         0  code-reviewer
  CLEAN         0  data-analyst
  CLEAN         0  discord-moderator
  CLEAN         0  doc-writer
  CLEAN         0  email-responder
  CLEAN         0  git-assistant
  CLEAN         0  inboxapi
  CLEAN         0  knowledge-base
  CLEAN         0  multi-agent-router
  CLEAN         0  self-improving-agent
  CLEAN         0  slack-connector
  CLEAN         0  sql-executor
  CLEAN         0  telegram-assistant
  CLEAN         0  web-researcher
  CLEAN         0  x-twitter-scraper
  CLEAN         0  zeroclaw-simplify-review
```
