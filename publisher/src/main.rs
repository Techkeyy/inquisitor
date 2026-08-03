//! Publishes Inquisitor verdicts to the Solana Attestation Service.
//!
//! This is an **operator** tool, not an agent tool. The agent reads verdicts and
//! holds no key; publishing one is a deliberate act by a human who is putting
//! their identity behind a claim. Keeping the two in separate binaries makes
//! that separation structural rather than a matter of discipline.
//!
//! ```text
//! inquisitor-publish setup                      # one-time: credential + schema
//! inquisitor-publish publish path/to/SKILL.md   # scan, then attest
//! inquisitor-publish address path/to/SKILL.md   # where a verdict would live
//! ```

mod rpc;

use anyhow::{Context, Result, bail};
use inquisitor::sas::{SCHEMA_NAME, SCHEMA_VERSION, VerdictPayload};
use inquisitor::{sas, scan};
use solana_attestation_service_client::instructions::{
    CloseAttestationBuilder, CreateAttestationBuilder, CreateCredentialBuilder, CreateSchemaBuilder,
};
use solana_keypair::Keypair;
use solana_program::instruction::Instruction;
use solana_program::pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::rpc::Rpc;

/// System program address. Hard-coded rather than pulled from a crate: it is a
/// constant of the network and this avoids another dependency.
const SYSTEM_PROGRAM: Pubkey = solana_program::pubkey!("11111111111111111111111111111111");

/// Credential name. Together with the issuer pubkey this defines the namespace
/// a verdict lives in, so two issuers never collide.
const CREDENTIAL_NAME: &str = "inquisitor";

/// Attestations do not expire. A verdict describes immutable bytes, so there is
/// nothing for time to invalidate — and staleness is already carried by
/// `scanner_version`, which a reader can judge for itself.
const NO_EXPIRY: i64 = 0;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let rpc_url = std::env::var("INQUISITOR_RPC")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    match cmd {
        "keygen" => keygen(),
        "setup" => setup(&rpc_url),
        "publish" => {
            let path = args.get(1).context("usage: publish <skill file>")?;
            publish(&rpc_url, path)
        }
        "address" => {
            let path = args.get(1).context("usage: address <skill file>")?;
            address(path)
        }
        "revoke" => {
            let path = args.get(1).context("usage: revoke <skill file>")?;
            revoke(&rpc_url, path)
        }
        _ => {
            eprintln!(
                "inquisitor-publish\n\n  \
                 keygen                 create an issuer keypair\n  \
                 setup                  create the credential and schema (one-time)\n  \
                 publish <skill file>   scan a skill and attest the verdict\n  \
                 address <skill file>   print where a verdict for it would live\n\n\
                 env:\n  \
                 INQUISITOR_RPC       RPC endpoint (default: devnet)\n  \
                 INQUISITOR_KEYPAIR   issuer keypair path (default: ~/.config/solana/id.json)\n"
            );
            Ok(())
        }
    }
}

/// Load the issuer key.
///
/// This key signs attestations and nothing else. It should hold fee lamports
/// and no assets: if it is ever compromised the damage is false verdicts under
/// an identity readers can stop trusting, not stolen funds.
fn issuer() -> Result<Keypair> {
    let path = std::env::var("INQUISITOR_KEYPAIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        format!("{home}/.config/solana/id.json")
    });
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read issuer keypair at {path}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("{path} is not a Solana keypair JSON array"))?;
    if bytes.len() != 64 {
        bail!("{path} holds {} bytes, expected 64", bytes.len());
    }
    Keypair::try_from(&bytes[..]).map_err(|e| anyhow::anyhow!("malformed keypair in {path}: {e}"))
}

fn client(rpc_url: &str) -> Rpc {
    Rpc::new(rpc_url)
}

/// Create an issuer keypair.
///
/// This identity signs verdicts and nothing else. Fund it with fee lamports
/// only — never reuse a wallet that holds assets, because the whole argument
/// for publishing verdicts from an agent host is that a compromise costs you
/// reputation rather than money.
fn keygen() -> Result<()> {
    let path = std::env::var("INQUISITOR_KEYPAIR").unwrap_or_else(|_| ".issuer.json".to_string());

    if std::path::Path::new(&path).exists() {
        bail!("{path} already exists — refusing to overwrite an issuer key");
    }

    let keypair = Keypair::new();
    let bytes: Vec<u8> = keypair.to_bytes().to_vec();
    std::fs::write(&path, serde_json::to_string(&bytes)?)
        .with_context(|| format!("cannot write {path}"))?;

    println!("issuer  {}", keypair.pubkey());
    println!("written {path}");
    println!("\nFund it on devnet before publishing:");
    println!("  solana airdrop 1 {} --url devnet", keypair.pubkey());
    Ok(())
}

fn setup(rpc_url: &str) -> Result<()> {
    let issuer = issuer()?;
    let rpc = client(rpc_url);

    let (credential, _) =
        sas::derive_credential(&to_inq(&issuer.pubkey()), CREDENTIAL_NAME.as_bytes());
    let (schema, _) = sas::derive_schema(&credential, SCHEMA_NAME, SCHEMA_VERSION);

    let credential = to_sdk(&credential);
    let schema = to_sdk(&schema);

    println!("issuer     {}", issuer.pubkey());
    println!("credential {credential}");
    println!("schema     {schema}");

    let mut instructions = Vec::new();

    if !rpc.account_exists(&credential)? {
        instructions.push(
            CreateCredentialBuilder::new()
                .payer(issuer.pubkey())
                .credential(credential)
                .authority(issuer.pubkey())
                .system_program(SYSTEM_PROGRAM)
                .name(CREDENTIAL_NAME.to_string())
                .signers(vec![issuer.pubkey()])
                .instruction(),
        );
    } else {
        println!("credential already exists — skipping");
    }

    if !rpc.account_exists(&schema)? {
        instructions.push(
            CreateSchemaBuilder::new()
                .payer(issuer.pubkey())
                .authority(issuer.pubkey())
                .credential(credential)
                .schema(schema)
                .system_program(SYSTEM_PROGRAM)
                .name(String::from_utf8_lossy(SCHEMA_NAME).to_string())
                .description("Inquisitor skill supply-chain verdict".to_string())
                // u8, u8, string, string
                .layout(vec![0, 0, 12, 12])
                .field_names(vec![
                    "level".to_string(),
                    "score".to_string(),
                    "scanner_version".to_string(),
                    "rule_ids".to_string(),
                ])
                .instruction(),
        );
    } else {
        println!("schema already exists — skipping");
    }

    if instructions.is_empty() {
        println!("\nnothing to do — registry already set up");
        return Ok(());
    }

    let sig = send(&rpc, &issuer, instructions)?;
    println!("\nregistry created: {sig}");
    Ok(())
}

fn publish(rpc_url: &str, path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
    let verdict = scan::scan_skill(&content);

    let issuer = issuer()?;
    let rpc = client(rpc_url);

    let (credential, _) =
        sas::derive_credential(&to_inq(&issuer.pubkey()), CREDENTIAL_NAME.as_bytes());
    let (schema, _) = sas::derive_schema(&credential, SCHEMA_NAME, SCHEMA_VERSION);
    let nonce =
        sas::hash_to_nonce(&verdict.skill_hash).context("scanner produced a malformed hash")?;
    let (attestation, _) = sas::derive_attestation(&credential, &schema, &nonce);

    println!("skill      {}", verdict.skill_hash);
    println!(
        "verdict    {:?} (risk {}/100)",
        verdict.level, verdict.score
    );
    println!("attestation {}", to_sdk(&attestation));

    if rpc.account_exists(&to_sdk(&attestation))? {
        println!("\nalready published — attestations are immutable, nothing to do");
        return Ok(());
    }

    let payload = VerdictPayload {
        level: verdict.level.as_u8(),
        score: verdict.score.min(u8::MAX as u32) as u8,
        scanner_version: verdict.scanner_version.to_string(),
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id)
            .collect::<Vec<_>>()
            .join(","),
    };

    let ix = CreateAttestationBuilder::new()
        .payer(issuer.pubkey())
        .authority(issuer.pubkey())
        .credential(to_sdk(&credential))
        .schema(to_sdk(&schema))
        .attestation(to_sdk(&attestation))
        .system_program(SYSTEM_PROGRAM)
        .nonce(Pubkey::new_from_array(nonce))
        .data(payload.encode())
        .expiry(NO_EXPIRY)
        .instruction();

    let sig = send(&rpc, &issuer, vec![ix])?;
    println!("\npublished: {sig}");
    Ok(())
}

/// Withdraw a verdict.
///
/// Issuers are wrong sometimes — this tool published a false positive against
/// `auto-coder` from a stale build within an hour of going live. An attestation
/// is immutable, so the honest correction is to close the account and publish
/// again from a build you trust. A registry with no retraction path is one
/// where the first mistake is permanent, and nobody should trust an issuer who
/// cannot take something back.
///
/// Closing refunds the rent to the payer.
fn revoke(rpc_url: &str, path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
    let verdict = scan::scan_skill(&content);

    let issuer = issuer()?;
    let rpc = client(rpc_url);

    let (credential, _) =
        sas::derive_credential(&to_inq(&issuer.pubkey()), CREDENTIAL_NAME.as_bytes());
    let (schema, _) = sas::derive_schema(&credential, SCHEMA_NAME, SCHEMA_VERSION);
    let nonce = sas::hash_to_nonce(&verdict.skill_hash).context("malformed hash")?;
    let (attestation, _) = sas::derive_attestation(&credential, &schema, &nonce);
    let (event_authority, _) = sas::derive_event_authority();

    println!("skill       {}", verdict.skill_hash);
    println!("attestation {}", to_sdk(&attestation));

    if !rpc.account_exists(&to_sdk(&attestation))? {
        println!("\nnothing published at that address — nothing to revoke");
        return Ok(());
    }

    let ix = CloseAttestationBuilder::new()
        .payer(issuer.pubkey())
        .authority(issuer.pubkey())
        .credential(to_sdk(&credential))
        .attestation(to_sdk(&attestation))
        .event_authority(to_sdk(&event_authority))
        .system_program(SYSTEM_PROGRAM)
        .attestation_program(to_sdk(&sas::SAS_PROGRAM_ID))
        .instruction();

    let sig = send(&rpc, &issuer, vec![ix])?;
    println!("\nrevoked: {sig}");
    Ok(())
}

fn address(path: &str) -> Result<()> {
    let content = std::fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
    let verdict = scan::scan_skill(&content);
    let issuer = issuer()?;

    let (credential, _) =
        sas::derive_credential(&to_inq(&issuer.pubkey()), CREDENTIAL_NAME.as_bytes());
    let (schema, _) = sas::derive_schema(&credential, SCHEMA_NAME, SCHEMA_VERSION);
    let nonce = sas::hash_to_nonce(&verdict.skill_hash).context("malformed hash")?;
    let (attestation, _) = sas::derive_attestation(&credential, &schema, &nonce);

    println!("skill       {}", verdict.skill_hash);
    println!("credential  {}", to_sdk(&credential));
    println!("schema      {}", to_sdk(&schema));
    println!("attestation {}", to_sdk(&attestation));
    Ok(())
}

fn send(rpc: &Rpc, issuer: &Keypair, instructions: Vec<Instruction>) -> Result<String> {
    let balance = rpc.balance(&issuer.pubkey()).unwrap_or(0);
    if balance == 0 {
        bail!(
            "issuer {} has no lamports — fund it before publishing \
             (devnet: solana airdrop 1 {})",
            issuer.pubkey(),
            issuer.pubkey()
        );
    }

    let blockhash = rpc.latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&issuer.pubkey()),
        &[issuer],
        blockhash,
    );
    rpc.send_and_confirm(&tx)
}

// The plugin and the SDK use different Pubkey types from the same 32 bytes.
// Converting explicitly keeps the shared derivation logic in one place rather
// than duplicating seeds across two crates.

fn to_sdk(key: &solana_pubkey::Pubkey) -> Pubkey {
    Pubkey::new_from_array(key.to_bytes())
}

fn to_inq(key: &Pubkey) -> solana_pubkey::Pubkey {
    solana_pubkey::Pubkey::new_from_array(key.to_bytes())
}
