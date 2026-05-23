//! Deploy a Gnosis Safe at the SDK-derived address via the V2 relayer.
//!
//! Uses `POST /submit` with type=SAFE-CREATE and an EIP-712 CreateProxy signature.
//! The relayer submits the on-chain deployment and pays the gas.
//!
//!   cargo run --bin deploy_safe
//!
//! Requires `relayer_api_key` and `relayer_api_key_address` in config.json.

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{Address, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{SolStruct, SolValue};
use alloy_sol_types::sol;
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::str::FromStr;

sol! {
    struct CreateProxy {
        address paymentToken;
        uint256 payment;
        address paymentReceiver;
    }
}

// ── Constants ──────────────────────────────────────────────────────────

const FACTORY_ADDR: &str = "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b";
const RELAYER_BASE: &str = "https://relayer-v2.polymarket.com";
const SAFE_INIT_CODE_HASH: &str =
    "2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf";

// ── Helpers ────────────────────────────────────────────────────────────

fn load_config(path: &str) -> Result<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn auth_hdrs(k: &str, a: &str) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert(
        reqwest::header::HeaderName::from_static("relayer_api_key"),
        reqwest::header::HeaderValue::from_str(k).unwrap(),
    );
    h.insert(
        reqwest::header::HeaderName::from_static("relayer_api_key_address"),
        reqwest::header::HeaderValue::from_str(a).unwrap(),
    );
    h
}

/// Compute the SDK-style CREATE2 Safe address for an EOA.
fn derive_safe_address(eoa: Address, factory: Address) -> Address {
    let salt = alloy::primitives::keccak256((eoa,).abi_encode());
    let code_hash = B256::from_str(SAFE_INIT_CODE_HASH).unwrap();
    factory.create2(salt, code_hash)
}

// ── Relayer-based Safe deployment ──────────────────────────────────────

async fn deploy_safe_via_relayer(
    client: &reqwest::Client,
    signer: &PrivateKeySigner,
    rk: &str,
    ra: &str,
    eoa: Address,
    safe_addr: Address,
    factory: Address,
) -> Result<()> {
    // ── 1. Check if already deployed ────────────────────────────────
    let dp = client
        .get(format!("{RELAYER_BASE}/deployed?address={safe_addr:#x}"))
        .headers(auth_hdrs(rk, ra))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await
        .unwrap_or_default();
    if dp.get("deployed").and_then(|v| v.as_bool()).unwrap_or(false) {
        println!("✅ Safe already deployed at {safe_addr:#x}");
        return Ok(());
    }
    println!("⏳ Safe {safe_addr:#x} not deployed — requesting deployment via relayer...");

    // ── 2. Sign CreateProxy EIP-712 typed data ──────────────────────
    let domain = Eip712Domain {
        name: Some(Cow::Borrowed("Polymarket Contract Proxy Factory")),
        version: None,
        chain_id: Some(U256::from(137)),
        verifying_contract: Some(factory),
        salt: None,
    };

    let msg = CreateProxy {
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    };

    let hash = msg.eip712_signing_hash(&domain);
    let sig = signer.sign_hash(&hash).await?;
    let v_byte: u8 = if sig.v() { 28u8 } else { 27u8 };
    let mut packed = Vec::with_capacity(65);
    packed.extend_from_slice(&sig.r().to_be_bytes::<32>());
    packed.extend_from_slice(&sig.s().to_be_bytes::<32>());
    packed.push(v_byte);
    let sig_hex = format!("0x{}", alloy::hex::encode(&packed));

    println!("  EIP-712 hash: 0x{}", alloy::hex::encode(hash));
    println!("  Signature: {sig_hex}");

    // ── 3. Build request body ───────────────────────────────────────
    let z = format!("{:#x}", Address::ZERO);
    let body = serde_json::json!({
        "type": "SAFE-CREATE",
        "from": format!("{eoa:#x}"),
        "to": format!("{factory:#x}"),
        "proxyWallet": format!("{safe_addr:#x}"),
        "data": "0x",
        "signature": sig_hex,
        "signatureParams": {
            "paymentToken": z,
            "payment": "0",
            "paymentReceiver": z,
        },
    });

    // ── 4. Submit ──────────────────────────────────────────────────
    let ct = reqwest::header::HeaderValue::from_static("application/json");
    let resp = client
        .post(format!("{RELAYER_BASE}/submit"))
        .headers(auth_hdrs(rk, ra))
        .header(reqwest::header::CONTENT_TYPE, ct)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("Relayer rejected deployment: {status}: {text}");
    }

    let sv: serde_json::Value = serde_json::from_str(&text)?;
    let tx_id = sv["transactionID"]
        .as_str()
        .context("no transactionID in response")?
        .to_string();
    println!("  ✅ Submitted! ID: {tx_id}, state: {:?}", sv["state"].as_str());

    // ── 5. Poll for confirmation ───────────────────────────────────
    for i in 0..60 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let r = client
            .get(format!("{RELAYER_BASE}/transaction?id={tx_id}"))
            .headers(auth_hdrs(rk, ra))
            .send()
            .await?;
        if !r.status().is_success() {
            continue;
        }
        // Endpoint returns an array — find our transaction by ID
        let txns: Vec<serde_json::Value> = r.json().await.unwrap_or_default();
        let td = txns.iter().find(|t| {
            t["transactionID"].as_str() == Some(&tx_id)
        });
        let s = td.and_then(|t| t["state"].as_str()).unwrap_or("unknown");
        println!("  Poll {i}/60: state={s}");

        match s {
            "STATE_CONFIRMED" | "STATE_MINED" => {
                let tx_hash = td
                    .and_then(|t| t["transactionHash"].as_str())
                    .unwrap_or(&tx_id);
                println!(
                    "  ✅ Safe deployed! https://polygonscan.com/tx/{tx_hash}"
                );
                return Ok(());
            }
            "STATE_FAILED" => {
                let reason = td
                    .and_then(|t| t["failureReason"].as_str())
                    .unwrap_or("unknown");
                anyhow::bail!("Safe deployment failed: {reason}");
            }
            _ => {}
        }
    }
    anyhow::bail!("Timeout waiting for Safe deployment");
}

// ── Main ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let cfg = load_config("config.json")?;
    let p = &cfg["polymarket"];
    let pk = p["private_key"].as_str().context("private_key")?;
    let rk = p["relayer_api_key"].as_str().context("relayer_api_key")?;
    let ra = p["relayer_api_key_address"]
        .as_str()
        .context("relayer_api_key_address")?;

    let signer = PrivateKeySigner::from_str(pk)?;
    let eoa = signer.address();
    let factory: Address = Address::from_str(FACTORY_ADDR)?;
    let safe_addr = derive_safe_address(eoa, factory);

    println!("EOA:         {eoa:#x}");
    println!("Factory:     {factory:#x}");
    println!("Safe addr:   {safe_addr:#x}");

    let client = reqwest::Client::new();
    deploy_safe_via_relayer(&client, &signer, rk, ra, eoa, safe_addr, factory).await
}
