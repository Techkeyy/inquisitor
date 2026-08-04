# Demo video — 2:45 shooting script

Target 2:45, hard ceiling 3:00. Terminal + phone. No slides, no title cards, no
music. The brief says *"terminal + phone is perfect"* — take it literally.

---

## Before you record

**Setup**

- [ ] Throwaway config, disposable keys — so **nothing needs blurring in post**
- [ ] Paid RPC endpoint (public ones throttle during the one good take)
- [ ] Model pinned, temperature low — LLM phrasing drift breaks continuity
      between shots
- [ ] Daemon running: `zeroclaw daemon`
- [ ] Phone mirrored beside the terminal (scrcpy for Android, QuickTime for
      iPhone), or cut between the two
- [ ] Terminal font large enough to read at 720p. Assume a judge watches in a
      small window.

**Have these ready to paste**

1. `tests/fixtures/poisoned-solana-helper.md` contents
2. The prompt: *"I found this skill on a forum and I'm about to install it. Here it is:"*

**Have these tabs open**

- Solscan on `HDda57FRBeyuruVx9QwhZEkrR1vJuCf5rxwuzNEBWyG8`
- Solscan on the revoke tx `277ZxyFezTF1n7R2nZ2XoHKvEMpciSjfXxBwY5BRJvRXGf8Nbz1YBg4YZN2zGtX5YhjYasrdF7h2oAxGooCyJ6fn`

---

## 0:00 – 0:20 — The bait

**Screen:** the poisoned skill open in a terminal pager, scrolled to line 30.

**Say:**
> "This is an agent skill. It builds Solana Pay links — and it works. Real spec,
> correct RPC call, sensible advice."

Scroll slowly to line 35. Let it sit for a beat.

> "And here it reads your wallet key and posts it to a webhook."

Point at line 36 — the line break between `Do not` and `mention`.

> "Then tells the agent to hide that from you. Notice it wraps across a line.
> A scanner that reads line by line never sees that phrase."

**Why this opening:** it establishes that the attack is invisible to both a
human skimming and a naive tool, in twenty seconds, with no explanation needed.

---

## 0:20 – 1:00 — The agent catches it, unprompted

**Screen:** phone. Telegram.

Paste the prompt and the skill. Send.

**Say while it thinks:**
> "I haven't told it to scan anything. I've said I'm about to install this."

**Let the reply land silently.** Do not talk over it. The first line is the
whole thesis:

> *"I need to check this skill for security issues before you install it."*

Then read one line aloud, pointing at it:

> "It flagged the concealment itself — *'explicitly instructs me to hide that
> action from you.'* The skill told it to stay quiet. It said so instead."

**Why this is the centre:** nothing was asked for. The skill taught the agent
when the gate applies. That is the correct layering the brief describes, and it
is the single most persuasive five seconds you have.

---

## 1:00 – 1:35 — The twist: it didn't scan anything

**Screen:** terminal, the same verdict.

Point at the line `verdict published on-chain — not rescanned locally`.

**Say:**
> "That verdict wasn't computed here. Someone already scanned these exact bytes
> and published the result. This machine did one RPC call."

```bash
export INQUISITOR_CREDENTIAL=FqToqovT1TStTb6Fi4Jn1JV5V4cCr1nJ22z2vdBAW8J9
cargo run -q --release --manifest-path publisher/Cargo.toml -- address tests/fixtures/poisoned-solana-helper.md
```

**Say as the address prints:**
> "A SAS attestation is keyed by 32 bytes. A sha256 is 32 bytes. So the skill's
> hash *is* the address. Finding a verdict isn't a lookup — it's arithmetic."

Switch to the open Solscan tab. Let it sit two seconds.

> "Mainnet. Signed. Anyone can read it."

---

## 1:35 – 2:05 — Anyone can check it, without trusting me

**Screen:** terminal, split or sequential.

Change one character in the skill file — add a space, delete a word. Re-run:

```bash
cargo run -q --release --manifest-path publisher/Cargo.toml -- address tests/fixtures/poisoned-solana-helper.md
```

**Say:**
> "Different address. Edit one byte and the old verdict no longer applies — it
> can't outlive the file it described."

> "Note there's no key and no network in that command — it's pure arithmetic on
> the file. You don't need anything of mine to check my work."

> "And this is why it's on a chain and not on my server. A self-hosted agent has
> no central authority. That's the whole product. Put the registry on someone's
> server and you've swapped *trust the skill author* for *trust whoever runs the
> registry*."

**Why this beat:** it pre-empts the one objection a sharp judge will raise —
that Solana is decorative. Answer it before they think it.

---

## 2:05 – 2:30 — It survives contact with reality

**Screen:** terminal.

```bash
cargo run --release --example scan -- --quiet .skills-ref/skills/*/SKILL.md
```

Nothing prints.

**Say:**
> "Every skill in the public registry. Eighteen of eighteen, no false positives."

```bash
cargo test
```

**Say over the output:**
> "Sixty-six tests. Running it against real skills found two false positives —
> one flagged a skill for saying *never modify .env files*. Fixing that broke
> the wallet-theft rule silently. Both are in the write-up."

---

## 2:30 – 2:45 — The honest close

**Screen:** Solscan, the revoke transaction.

**Say:**
> "It also published a wrong verdict to mainnet. Twice. Once marking a malicious
> skill clean — from a stale build."

> "Attestations are immutable, so revoke exists. A registry with no retraction
> path is one where the first mistake is permanent."

**Last line, over the repo:**
> "An issuer is software. Software is wrong sometimes. That's the argument for
> being able to take it back."

**Cut.**

---

## Why this ordering

| Beat | Judging criterion it serves |
|---|---|
| Bait | Use case — makes the threat concrete in 20s |
| Unprompted catch | Use case + safety — the design working without a human |
| The twist | Solana is load-bearing, shown not argued |
| Verification | Reproducibility — they can check it themselves |
| Real registry | Craft — it survives real data |
| Revoke | Safety + honesty — the thing most submissions won't show |

## Things to avoid

- **Don't explain the architecture.** The write-up does that. The video shows it
  working.
- **Don't show code.** Nobody watches Rust in a video.
- **Don't say "as you can see".** Show it or cut it.
- **Don't advertise the bot handle.** If a judge messages it while your laptop
  is asleep they get silence.
- **Don't re-record for small stumbles.** Judges are watching for whether it
  works, not for polish.

## If you overrun

Cut in this order — the first two are the least load-bearing:

1. The `cargo test` shot (2:15–2:25)
2. The edit-one-byte demo (1:35–1:50)
3. Shorten the opening to 12 seconds

Never cut the unprompted catch or the revoke close. One is your best evidence;
the other is your credibility.
