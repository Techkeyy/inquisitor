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
}

impl Flat {
    /// Flatten `content`, recording which source line each byte came from.
    pub fn new(content: &str) -> Self {
        let mut lower = String::with_capacity(content.len());
        let mut raw = String::with_capacity(content.len());
        let mut line_at: Vec<usize> = Vec::with_capacity(content.len());
        let mut pending_space = false;

        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            for ch in line.chars() {
                if ch.is_whitespace() {
                    pending_space = true;
                    continue;
                }
                if pending_space && !lower.is_empty() {
                    push_char(&mut lower, &mut raw, &mut line_at, ' ', line_no);
                }
                pending_space = false;
                push_char(&mut lower, &mut raw, &mut line_at, ch, line_no);
            }
            pending_space = true;
        }

        Self { lower, raw, line_at }
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
            if let Some(rel) = self.lower[lo..hi].find(needle) {
                return Some(lo + rel);
            }
        }
        None
    }
}

fn push_char(
    lower: &mut String,
    raw: &mut String,
    line_at: &mut Vec<usize>,
    ch: char,
    line_no: usize,
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
