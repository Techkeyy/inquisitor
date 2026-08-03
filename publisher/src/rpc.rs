//! Minimal Solana JSON-RPC client.
//!
//! Three methods is the whole requirement, and `solana-client` costs an
//! `openssl-sys` build that Windows cannot satisfy out of the box. This does
//! the same job over rustls with no native toolchain.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde_json::{Value, json};
use solana_hash::Hash;
use solana_program::pubkey::Pubkey;
use solana_transaction::Transaction;
use std::str::FromStr;

pub struct Rpc {
    url: String,
}

impl Rpc {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let resp: Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .with_context(|| format!("rpc {method} failed"))?
            .into_json()?;

        if let Some(err) = resp.get("error") {
            bail!("rpc {method} error: {err}");
        }
        Ok(resp)
    }

    /// Whether an account exists. A missing account is `"value": null`, which is
    /// an answer, not a failure.
    pub fn account_exists(&self, address: &Pubkey) -> Result<bool> {
        let resp = self.call(
            "getAccountInfo",
            json!([address.to_string(), {"encoding": "base64"}]),
        )?;
        Ok(!resp["result"]["value"].is_null())
    }

    pub fn balance(&self, address: &Pubkey) -> Result<u64> {
        let resp = self.call("getBalance", json!([address.to_string()]))?;
        Ok(resp["result"]["value"].as_u64().unwrap_or(0))
    }

    pub fn latest_blockhash(&self) -> Result<Hash> {
        let resp = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
        let raw = resp["result"]["value"]["blockhash"]
            .as_str()
            .context("no blockhash in response")?;
        Hash::from_str(raw).context("malformed blockhash")
    }

    /// Submit a signed transaction and wait for confirmation.
    pub fn send_and_confirm(&self, tx: &Transaction) -> Result<String> {
        let wire = bincode::serialize(tx).context("cannot serialize transaction")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&wire);

        let resp = self.call(
            "sendTransaction",
            json!([encoded, {"encoding": "base64", "preflightCommitment": "confirmed"}]),
        )?;
        let sig = resp["result"]
            .as_str()
            .context("no signature in response")?
            .to_string();

        self.await_confirmation(&sig)?;
        Ok(sig)
    }

    /// Poll until the signature confirms. Bounded: a transaction that has not
    /// landed in ~30s has almost certainly expired, and reporting that honestly
    /// beats hanging.
    fn await_confirmation(&self, signature: &str) -> Result<()> {
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let resp = self.call("getSignatureStatuses", json!([[signature]]))?;
            let status = &resp["result"]["value"][0];
            if status.is_null() {
                continue;
            }
            if let Some(err) = status.get("err")
                && !err.is_null()
            {
                bail!("transaction {signature} failed on chain: {err}");
            }
            if let Some(conf) = status.get("confirmationStatus").and_then(Value::as_str)
                && matches!(conf, "confirmed" | "finalized")
            {
                return Ok(());
            }
        }
        bail!("transaction {signature} not confirmed within 30s")
    }
}
