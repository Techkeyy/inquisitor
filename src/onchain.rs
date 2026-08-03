//! Reading verdicts from Solana.
//!
//! Strictly read-only, and that is a custody claim, not an implementation
//! detail: the agent process never holds a key, never signs, and cannot move
//! value. Publishing is a separate operator action outside the agent entirely
//! (see `examples/publish.rs`).
//!
//! HTTP goes through `wasi:http`, which the host links only after the
//! `http_client` grant is validated. There is no socket surface in a component,
//! so ordinary HTTP clients cannot work here.

use crate::sas::{self, VerdictPayload};
use solana_pubkey::Pubkey;

/// Everything needed to find a verdict, resolved from operator config.
pub struct Registry {
    pub rpc_url: String,
    pub credential: Pubkey,
    pub schema: Pubkey,
}

impl Registry {
    /// Build from the flat `__config` map. Returns `None` when the operator has
    /// not configured a registry, which is the normal unconfigured state and
    /// must degrade to local-only scanning rather than an error.
    pub fn from_section(section: &std::collections::HashMap<String, String>) -> Option<Self> {
        let rpc_url = section.get("rpc_url").filter(|v| !v.is_empty())?.clone();
        let credential = section
            .get("credential")
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<Pubkey>().ok())?;
        let schema = match section.get("schema").filter(|v| !v.is_empty()) {
            Some(v) => v.parse::<Pubkey>().ok()?,
            // Derivable from the credential, so operators need only set one key.
            None => sas::derive_schema(&credential, sas::SCHEMA_NAME, sas::SCHEMA_VERSION).0,
        };
        Some(Self { rpc_url, credential, schema })
    }

    /// Address a verdict for `skill_hash` would occupy.
    pub fn attestation_address(&self, skill_hash: &[u8; 32]) -> Pubkey {
        sas::derive_attestation(&self.credential, &self.schema, skill_hash).0
    }
}

/// A verdict found on chain, with the identity that signed it.
pub struct PublishedVerdict {
    pub payload: VerdictPayload,
    pub signer: Option<Pubkey>,
    pub address: Pubkey,
}

/// Build the `getAccountInfo` request body for an address.
///
/// Split out from the transport so it can be tested without a network.
pub fn account_info_request(address: &Pubkey) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{address}",{{"encoding":"base64"}}]}}"#
    )
}

/// Pull the base64 account blob out of a `getAccountInfo` response.
///
/// A hand-rolled extraction rather than a JSON dependency: the shape is fixed,
/// and a missing account is `"value":null`, which must read as "no verdict"
/// rather than as an error.
pub fn account_data_from_response(body: &str) -> Option<String> {
    let value_at = body.find("\"value\"")?;
    let rest = &body[value_at..];
    if rest[..rest.len().min(20)].contains("null") {
        return None;
    }
    let data_at = rest.find("\"data\"")?;
    let after = &rest[data_at..];
    let open = after.find('[')?;
    let first_quote = after[open..].find('"')? + open + 1;
    let close = after[first_quote..].find('"')? + first_quote;
    Some(after[first_quote..close].to_string())
}

/// Minimal base64 decoder.
///
/// Small enough to read in one sitting, which matters more than convenience for
/// code that parses attacker-reachable input inside a sandbox.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in input.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Decode a `getAccountInfo` response into a verdict, if one is there.
pub fn verdict_from_response(body: &str, address: Pubkey) -> Option<PublishedVerdict> {
    let b64 = account_data_from_response(body)?;
    let raw = base64_decode(&b64)?;
    let payload = sas::payload_from_account(&raw)?;
    Some(PublishedVerdict {
        payload,
        signer: sas::signer_from_account(&raw),
        address,
    })
}

/// Fetch a published verdict, or `None` if nobody has published one.
///
/// Any transport failure is `None`, not an error: an unreachable RPC must fall
/// back to scanning locally, never block the operator, and never — under any
/// circumstance — be mistaken for "no findings".
#[cfg(target_family = "wasm")]
pub fn lookup(registry: &Registry, skill_hash: &[u8; 32]) -> Option<PublishedVerdict> {
    let address = registry.attestation_address(skill_hash);
    let resp = waki::Client::new()
        .post(&registry.rpc_url)
        .header("Content-Type", "application/json")
        .body(account_info_request(&address).into_bytes())
        .connect_timeout(std::time::Duration::from_secs(5))
        .send()
        .ok()?;
    let body = String::from_utf8(resp.body().ok()?).ok()?;
    verdict_from_response(&body, address)
}
