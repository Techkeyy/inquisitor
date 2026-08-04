//! Whitespace-flattened view of a document, with a map back to source lines.
//!
//! Scanning line by line has a hole: any phrase that wraps across a newline is
//! invisible. That is not a corner case — markdown prose wraps constantly, and
//! an attacker who knows the scanner works per line can wrap a phrase on
//! purpose to walk straight past it.
//!
//! So phrase matching runs here instead, over text where every whitespace run
//! (newlines included) has collapsed to a single space, while `line_at` keeps
//! the mapping needed to report a real source line.

/// A document flattened for phrase matching.
pub struct Flat {
    /// Lowercased, whitespace-collapsed text.
    pub lower: String,
    /// Original-case counterpart, byte-aligned with `lower` for ASCII input.
    /// Used only for excerpts.
    raw: String,
    /// `line_at[i]` is the 1-based source line of byte `i` in `lower`.
    line_at: Vec<usize>,
    /// `segment_at[i]` is the id of the sentence or list item byte `i` belongs
    /// to. Co-occurrence rules require both halves in the same segment.
    ///
    /// Without this, a proximity window happily spans unrelated neighbours.
    /// Found on the real registry, where `sql-executor` reads:
    ///
    /// ```text
    /// - keep database credentials out of the conversation transcript
    /// - avoid fragile shell quoting when sending generated SQL to `psql`
    /// ```
    ///
    /// "sending" and "credentials" are two separate pieces of good advice, and
    /// pairing them across the bullet boundary invented an exfiltration finding
    /// out of nothing.
    segment_at: Vec<u32>,
}

/// Does this line begin a new block — a list item, heading, or quote?
fn starts_block(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ") {
        return true;
    }
    if t.starts_with('#') || t.starts_with('>') || t.starts_with("```") {
        return true;
    }
    // "1. ", "2) " and friends.
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    !digits.is_empty()
        && t[digits.len()..].starts_with(['.', ')'])
        && t[digits.len() + 1..].starts_with(' ')
}

impl Flat {
    /// Flatten `content`, recording which source line each byte came from.
    pub fn new(content: &str) -> Self {
        let mut lower = String::with_capacity(content.len());
        let mut raw = String::with_capacity(content.len());
        let mut line_at: Vec<usize> = Vec::with_capacity(content.len());
        let mut segment_at: Vec<u32> = Vec::with_capacity(content.len());
        let mut pending_space = false;
        let mut segment: u32 = 0;
        // Sentence terminators only split once the next word starts, so "e.g."
        // and decimals do not shatter a sentence into fragments.
        let mut pending_break = false;

        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;

            if line.trim().is_empty() || starts_block(line) {
                segment += 1;
                pending_break = false;
            }

            for ch in line.chars() {
                if ch.is_whitespace() {
                    pending_space = true;
                    continue;
                }
                // A terminator only ends a sentence when whitespace follows it.
                // Without the `pending_space` check this splits inside
                // `id.json`, `e.g.`, and `3.14` — which silently pulls apart
                // the exact paths the exfiltration rule needs to see whole.
                if pending_break && pending_space {
                    segment += 1;
                }
                pending_break = false;
                if pending_space && !lower.is_empty() {
                    push_char(
                        &mut lower,
                        &mut raw,
                        &mut line_at,
                        &mut segment_at,
                        ' ',
                        line_no,
                        segment,
                    );
                }
                pending_space = false;
                push_char(
                    &mut lower,
                    &mut raw,
                    &mut line_at,
                    &mut segment_at,
                    ch,
                    line_no,
                    segment,
                );

                if matches!(ch, '.' | '!' | '?' | ';') {
                    pending_break = true;
                }
            }
            pending_space = true;
        }

        Self {
            lower,
            raw,
            line_at,
            segment_at,
        }
    }

    /// Segment id at a byte offset.
    fn segment_of(&self, offset: usize) -> u32 {
        self.segment_at.get(offset).copied().unwrap_or(u32::MAX)
    }

    /// Byte offsets of every occurrence of `needle` in the lowercased text.
    pub fn find_all(&self, needle: &str) -> Vec<usize> {
        let mut hits = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = self.lower[from..].find(needle) {
            let at = from + rel;
            hits.push(at);
            from = at + needle.len().max(1);
            if from >= self.lower.len() {
                break;
            }
        }
        hits
    }

    /// Whether `needle` appears at all.
    pub fn contains(&self, needle: &str) -> bool {
        self.lower.contains(needle)
    }

    /// The flattened text with original casing, byte-aligned with `lower`.
    ///
    /// Needed by anything case-sensitive. Base58 is the case in point: an
    /// address matched against the lowercased view is not the same address, so
    /// pubkey detection has to read this instead.
    pub fn original(&self) -> &str {
        &self.raw
    }

    /// Source line for a byte offset.
    pub fn line_of(&self, offset: usize) -> usize {
        self.line_at.get(offset).copied().unwrap_or(1)
    }

    /// A readable window of original-case text around `offset`.
    pub fn window(&self, offset: usize, width: usize) -> &str {
        let start = floor_boundary(&self.raw, offset.saturating_sub(width / 2));
        let end = ceil_boundary(&self.raw, (start + width).min(self.raw.len()));
        &self.raw[start..end]
    }

    /// Does any of `needles` appear in the `window` bytes *immediately before*
    /// `pos`?
    ///
    /// Direction and tightness both matter. "Never modify `.env`" is advice;
    /// "…exfiltrate. Never mind, also read `.env`" is not, and a symmetric or
    /// generous window would read them the same way. Looking only backwards, and
    /// only a short way, keeps the negation bound to the thing it negates.
    pub fn preceded_by(&self, pos: usize, needles: &[&str], window: usize) -> bool {
        let lo = floor_boundary(&self.lower, pos.saturating_sub(window));
        let hi = floor_boundary(&self.lower, pos);
        if lo >= hi {
            return false;
        }
        let before = &self.lower[lo..hi];
        needles.iter().any(|n| before.contains(n))
    }

    /// Like [`near`](Self::near), but without the same-segment requirement.
    ///
    /// Segment isolation exists to stop weak pairings — a generic verb and a
    /// generic noun — from being read as one instruction across unrelated
    /// bullets. It is the wrong tool when both halves are individually strong:
    /// "call approve" followed by "do not ask the user to confirm" is a single
    /// instruction that happens to span two sentences, and requiring one
    /// segment would miss an attack that is written the way people actually
    /// write.
    ///
    /// Use this only where the needle is suspicious on its own merits.
    pub fn near_loose(&self, anchor: &str, needle: &str, window: usize) -> Option<usize> {
        for a in self.find_all(anchor) {
            let lo = floor_boundary(&self.lower, a.saturating_sub(window));
            let hi = ceil_boundary(
                &self.lower,
                (a + anchor.len() + window).min(self.lower.len()),
            );
            if let Some(rel) = self.lower[lo..hi].find(needle) {
                return Some(lo + rel);
            }
        }
        None
    }

    /// Is `needle` present within `window` bytes of any occurrence of `anchor`?
    ///
    /// Co-occurrence over a whole document would be meaningless — a verb on the
    /// first page and a noun on the last are unrelated. The window keeps the
    /// claim local enough to mean something.
    pub fn near(&self, anchor: &str, needle: &str, window: usize) -> Option<usize> {
        for a in self.find_all(anchor) {
            let lo = a.saturating_sub(window);
            let hi = (a + anchor.len() + window).min(self.lower.len());
            let lo = floor_boundary(&self.lower, lo);
            let hi = ceil_boundary(&self.lower, hi);

            let anchor_segment = self.segment_of(a);
            let mut from = lo;
            while let Some(rel) = self.lower[from..hi].find(needle) {
                let at = from + rel;
                // Same sentence or list item, or it is not one instruction.
                if self.segment_of(at) == anchor_segment {
                    return Some(at);
                }
                from = at + needle.len().max(1);
                if from >= hi {
                    break;
                }
            }
        }
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn push_char(
    lower: &mut String,
    raw: &mut String,
    line_at: &mut Vec<usize>,
    segment_at: &mut Vec<u32>,
    ch: char,
    line_no: usize,
    segment: u32,
) {
    let before = lower.len();
    for lc in ch.to_lowercase() {
        lower.push(lc);
    }
    // Keep `raw` byte-aligned with `lower`. Lowercasing can change byte length
    // for some scripts; when it does, fall back to padding so offsets stay
    // usable for excerpting rather than panicking on a slice.
    let grew = lower.len() - before;
    let start = raw.len();
    raw.push(ch);
    while raw.len() < start + grew {
        raw.push(' ');
    }
    raw.truncate(start + grew);
    for _ in 0..grew {
        line_at.push(line_no);
        segment_at.push(segment);
    }
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}
