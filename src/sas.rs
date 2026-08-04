//! Solana Attestation Service addressing.
//!
//! The design hinges on one coincidence: a SAS attestation is keyed by a 32-byte
//! `nonce`, and a sha256 is 32 bytes. So the skill's content hash *is* the
//! nonce.
//!
//! That turns a lookup into arithmetic. Given a known credential and schema,
//! anyone holding a skill file can derive the exact address its verdict would
//! live at and settle the question in a single `getAccountInfo`. No index, no
//! search, no crawling a registry, no trusting whoever runs the index — which
//! is the whole point, because a self-hosted runtime has no index to trust.
//!
//! Seeds verified against the program source, not documentation:
//! `program/src/processor/{create_credential,create_schema,create_attestation}.rs`.

use solana_pubkey::Pubkey;

/// SAS program, identical on mainnet and devnet.
pub const SAS_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG");

pub const CREDENTIAL_SEED: &[u8] = b"credential";
pub const SCHEMA_SEED: &[u8] = b"schema";
pub const ATTESTATION_SEED: &[u8] = b"attestation";
pub const EVENT_AUTHORITY_SEED: &[u8] = b"__event_authority";

/// `["__event_authority"]` — required by the close path, which emits an event
/// via self-CPI.
pub fn derive_event_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &SAS_PROGRAM_ID)
}

/// Schema name Inquisitor publishes verdicts under.
pub const SCHEMA_NAME: &[u8] = b"inquisitor-verdict-v1";

/// Schema version byte. The program appends this to the schema seeds.
pub const SCHEMA_VERSION: u8 = 1;

/// `["credential", authority, name]`
pub fn derive_credential(authority: &Pubkey, name: &[u8]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[CREDENTIAL_SEED, authority.as_ref(), name],
        &SAS_PROGRAM_ID,
    )
}

/// `["schema", credential, name, [version]]`
pub fn derive_schema(credential: &Pubkey, name: &[u8], version: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SCHEMA_SEED, credential.as_ref(), name, &[version]],
        &SAS_PROGRAM_ID,
    )
}

/// `["attestation", credential, schema, nonce]`, where `nonce` is the skill's
/// sha256. This is the function that makes a verdict findable by anyone.
pub fn derive_attestation(
    credential: &Pubkey,
    schema: &Pubkey,
    skill_hash: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            ATTESTATION_SEED,
            credential.as_ref(),
            schema.as_ref(),
            skill_hash,
        ],
        &SAS_PROGRAM_ID,
    )
}

/// Parse a lowercase-hex sha256 into the raw bytes used as the nonce.
pub fn hash_to_nonce(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The payload Inquisitor writes into an attestation.
///
/// Deliberately tiny: rent scales with account size, and this is written once
/// per distinct skill by every operator who scans one. Anything a reader can
/// recompute locally does not belong on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictPayload {
    /// `Level::as_u8`.
    pub level: u8,
    /// Risk score, 0–100.
    pub score: u8,
    /// Scanner version that produced this, so stale rule sets are visible.
    pub scanner_version: String,
    /// Comma-separated rule ids that fired.
    pub rule_ids: String,
}

impl VerdictPayload {
    /// Borsh-compatible encoding: `u8, u8, string, string`, where a string is a
    /// u32 little-endian length followed by its bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(self.level);
        out.push(self.score);
        push_str(&mut out, &self.scanner_version);
        push_str(&mut out, &self.rule_ids);
        out
    }

    /// Inverse of [`encode`](Self::encode). Returns `None` on any malformed
    /// input rather than guessing — a verdict that cannot be read cleanly must
    /// not be treated as a verdict at all.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cur = 0usize;
        let level = *bytes.get(cur)?;
        cur += 1;
        let score = *bytes.get(cur)?;
        cur += 1;
        let scanner_version = take_str(bytes, &mut cur)?;
        let rule_ids = take_str(bytes, &mut cur)?;
        Some(Self {
            level,
            score,
            scanner_version,
            rule_ids,
        })
    }
}

/// Pull the verdict payload out of a raw SAS `Attestation` account.
///
/// Layout (borsh, from `clients/rust/.../accounts/attestation.rs`):
/// `discriminator u8 | nonce [32] | credential [32] | schema [32] | data Vec<u8>
///  | signer [32] | expiry i64 | token_account [32]`
///
/// Only `data` is ours; everything before it is fixed-width, so the offset is a
/// constant rather than a parse.
pub fn payload_from_account(account: &[u8]) -> Option<VerdictPayload> {
    /// discriminator + nonce + credential + schema
    const DATA_OFFSET: usize = 1 + 32 + 32 + 32;
    /// signer + expiry + token_account
    const TRAILER: usize = 32 + 8 + 32;

    let len_bytes: [u8; 4] = account.get(DATA_OFFSET..DATA_OFFSET + 4)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let start = DATA_OFFSET + 4;
    let end = start.checked_add(len)?;

    // Require the whole account, not just enough of it to reach the payload.
    // The trailing fields carry the signer — the identity that makes a verdict
    // worth anything — so an account too short to hold them is not a verdict
    // that has been half-read, it is not a verdict at all.
    if account.len() < end.checked_add(TRAILER)? {
        return None;
    }

    VerdictPayload::decode(account.get(start..end)?)
}

/// The signer that wrote an attestation — the identity a reader decides whether
/// to trust. Same fixed-width reasoning, but `data` is variable so this one has
/// to walk past it.
pub fn signer_from_account(account: &[u8]) -> Option<Pubkey> {
    const DATA_OFFSET: usize = 1 + 32 + 32 + 32;

    let len_bytes: [u8; 4] = account.get(DATA_OFFSET..DATA_OFFSET + 4)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let signer_at = DATA_OFFSET.checked_add(4)?.checked_add(len)?;
    let raw: [u8; 32] = account.get(signer_at..signer_at + 32)?.try_into().ok()?;
    Some(Pubkey::new_from_array(raw))
}

/// Append a borsh-style string: u32 little-endian length, then bytes.
///
/// The length is written with a saturating conversion rather than a cast. A
/// string longer than `u32::MAX` cannot occur here — payloads are capped far
/// below that — but a silent wrap would produce an account that decodes to
/// something other than what was scanned, and a verdict that does not describe
/// the bytes it claims to is worse than no verdict.
fn push_str(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn take_str(bytes: &[u8], cur: &mut usize) -> Option<String> {
    let len_bytes: [u8; 4] = bytes.get(*cur..*cur + 4)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    *cur += 4;
    let raw = bytes.get(*cur..*cur + len)?;
    *cur += len;
    String::from_utf8(raw.to_vec()).ok()
}
