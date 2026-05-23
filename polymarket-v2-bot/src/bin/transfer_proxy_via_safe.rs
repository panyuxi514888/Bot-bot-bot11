//! Transfer 1 USDC from derived proxy (0x88cc...9549) to config proxy (0x30f6...a2e48).
//! Flow: EOA signs rlx: message → relayer (type:PROXY) → ProxyFactory → proxy wallet
use alloy::hex::ToHexExt;
use alloy::primitives::{Address, Bytes, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use std::str::FromStr;

// ── Constants ──────────────────────────────────────────────────────────

const PROXY_FACTORY: &str = "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052";
const RELAY_HUB: &str = "0xD216153c06E857cD7f72665E0aF1d7D82172F494";
const PROXY_WALLET: &str = "0x88cc81f9b42132d47a176b05fd85eaa758945549";
const DEST_WALLET: &str = "0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48";
const USDC: &str = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const AMOUNT: u64 = 1_000_000; // 1 USDC

sol! {
    struct ProxyTransaction {
        uint8 typeCode;
        address to;
        uint256 value;
        bytes data;
    }
    function proxy(ProxyTransaction[] txns);
}

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

fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Build the rlx: prefixed message hash for PROXY type relayer transactions.
fn create_proxy_struct_hash(
    from: Address, to: Address, data: &[u8],
    tx_fee: U256, gas_price: U256, gas_limit: U256,
    nonce: u64, relay_hub: Address, relay: Address,
) -> [u8; 32] {
    let mut message = Vec::new();
    message.extend_from_slice(b"rlx:");
    message.extend_from_slice(from.as_slice());
    message.extend_from_slice(to.as_slice());
    message.extend_from_slice(data);
    message.extend_from_slice(&tx_fee.to_be_bytes::<32>());
    message.extend_from_slice(&gas_price.to_be_bytes::<32>());
    message.extend_from_slice(&gas_limit.to_be_bytes::<32>());
    message.extend_from_slice(&U256::from(nonce).to_be_bytes::<32>());
    message.extend_from_slice(relay_hub.as_slice());
    message.extend_from_slice(relay.as_slice());
    keccak256(&message).into()
}

#[derive(serde::Deserialize)]
struct RelayPayload {
    address: String,
    #[serde(deserialize_with = "deserialize_nonce")]
    nonce: u64,
}

fn deserialize_nonce<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let s = String::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().unwrap();

    let cfg = load_config("config.json")?;
    let p = &cfg["polymarket"];
    let pk = p["private_key"].as_str().context("private_key")?;
    let rk = p["relayer_api_key"].as_str().context("relayer_api_key")?;
    let ra = p["relayer_api_key_address"].as_str().context("relayer_api_key_address")?;
    let rpc_url = cfg["rpc"].as_str().context("rpc")?;

    let signer = PrivateKeySigner::from_str(pk)?;
    let eoa = signer.address();
    let proxy_factory: Address = PROXY_FACTORY.parse()?;
    let relay_hub: Address = RELAY_HUB.parse()?;
    let proxy_wallet: Address = PROXY_WALLET.parse()?;
    let dest: Address = DEST_WALLET.parse()?;
    let usdc: Address = USDC.parse()?;

    println!("EOA:           {eoa:#x}");
    println!("ProxyFactory:  {proxy_factory:#x}");
    println!("RelayHub:      {relay_hub:#x}");
    println!("ProxyWallet:   {proxy_wallet:#x}");
    println!("Dest:          {dest:#x}");
    println!("USDC:          {usdc:#x}");

    // Build USDC transfer(address,uint256) inner calldata
    let transfer_sel = selector("transfer(address,uint256)");
    let mut inner_calldata = transfer_sel.to_vec();
    inner_calldata.extend_from_slice(&(dest, U256::from(AMOUNT)).abi_encode_params());
    println!("\nUSDC transfer calldata: 0x{}", alloy::hex::encode(&inner_calldata));

    // Build proxy(ProxyTransaction[]) outer calldata
    let proxy_txns = vec![ProxyTransaction {
        typeCode: 1,  // PROXY_CALL_TYPE_CODE from polyoxide
        to: usdc,
        value: U256::ZERO,
        data: Bytes::from(inner_calldata),
    }];
    let outer_calldata = proxyCall { txns: proxy_txns }.abi_encode();
    println!("Proxy calldata: 0x{}", alloy::hex::encode(&outer_calldata));

    // Get relay payload (nonce + relay address) from relayer API
    let client = reqwest::Client::new();
    let base = "https://relayer-v2.polymarket.com";

    println!("\n── Fetching relay payload (nonce & relay address) ──");
    let relay_url = format!("{base}/relay-payload?address={eoa:#x}&type=PROXY");
    let relay_resp: RelayPayload = client
        .get(&relay_url)
        .headers(auth_hdrs(rk, ra))
        .send()
        .await
        .context("Failed to fetch relay payload")?
        .json()
        .await
        .context("Failed to parse relay payload")?;
    let relay_addr: Address = relay_resp.address.parse().context("Invalid relay address")?;
    let nonce = relay_resp.nonce;
    println!("  relay: {relay_addr:#x}");
    println!("  nonce: {nonce}");

    // Build rlx: prefixed struct hash and sign
    let tx_fee = U256::ZERO;
    let gas_price = U256::ZERO;
    let gas_limit = U256::from(10_000_000u64);

    let struct_hash = create_proxy_struct_hash(
        eoa, proxy_factory, &outer_calldata,
        tx_fee, gas_price, gas_limit, nonce, relay_hub, relay_addr,
    );

    let sig = signer.sign_message(&struct_hash).await?;
    // Proxy signature: v = 27 (y_parity=0) or 28 (y_parity=1)
    let v = if sig.v() { 28u8 } else { 27u8 };
    let mut packed_sig = Vec::with_capacity(65);
    packed_sig.extend_from_slice(&sig.r().to_be_bytes::<32>());
    packed_sig.extend_from_slice(&sig.s().to_be_bytes::<32>());
    packed_sig.push(v);
    let sig_hex = format!("0x{}", alloy::hex::encode(&packed_sig));

    // Submit PROXY-type transaction to relayer
    let body = serde_json::json!({
        "type": "PROXY",
        "from": format!("{eoa:#x}"),
        "to": format!("{proxy_factory:#x}"),
        "proxyWallet": format!("{proxy_wallet:#x}"),
        "data": outer_calldata.encode_hex_with_prefix(),
        "signature": sig_hex,
        "signatureParams": {
            "relayerFee": "0",
            "gasLimit": "10000000",
            "gasPrice": "0",
            "relayHub": format!("{relay_hub:#x}"),
            "relay": format!("{relay_addr:#x}")
        },
        "nonce": nonce.to_string(),
    });

    println!("\n── Submitting PROXY tx to relayer ──");
    println!("  body: {}", serde_json::to_string_pretty(&body).unwrap_or_default());
    let resp = client
        .post(format!("{base}/submit"))
        .headers(auth_hdrs(rk, ra))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("Submit failed {status}: {text}");
    }
    let sv: serde_json::Value = serde_json::from_str(&text)?;
    let tx_id = sv["transactionID"].as_str().context("no transactionID")?.to_string();
    println!("  ✅ Submitted! ID: {tx_id}, state: {:?}", sv["state"].as_str());

    // Poll for confirmation
    let max_polls = 30u32;
    for i in 0..max_polls {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let r = client
            .get(format!("{base}/transaction?id={tx_id}"))
            .headers(auth_hdrs(rk, ra))
            .send().await?;
        if !r.status().is_success() { continue; }
        let txns: Vec<serde_json::Value> = r.json().await.unwrap_or_default();
        let td = txns.iter().find(|t| t["transactionID"].as_str() == Some(&tx_id));
        let s = td.and_then(|t| t["state"].as_str()).unwrap_or("unknown");
        println!("  poll {i}/{}: state={s}", max_polls);
        match s {
            "STATE_CONFIRMED" | "STATE_MINED" => {
                let th = td.and_then(|t| t["transactionHash"].as_str()).unwrap_or(&tx_id);
                println!("\n✅ 1 USDC transferred! https://polygonscan.com/tx/{th}");
                return Ok(());
            }
            "STATE_FAILED" => {
                let reason = td.and_then(|t| t["failureReason"].as_str()).unwrap_or("unknown");
                anyhow::bail!("Transaction failed: {reason}");
            }
            _ => {}
        }
    }
    anyhow::bail!("Timeout waiting for confirmation");
}
