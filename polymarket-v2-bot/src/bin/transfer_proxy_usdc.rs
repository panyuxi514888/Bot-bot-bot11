//! Transfer 1 USDC from 0x88cc...9549 (derived proxy) to 0x30f6...a2e48 (config proxy).
//! Calls the proxy wallet's proxy(ProxyTransaction[]) function as the EOA owner.
use alloy::consensus::{SignableTransaction, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use anyhow::{Context, Result};
use std::str::FromStr;

const CHAIN_ID: u64 = 137;
const PROXY_WALLET: &str = "0x88cc81f9b42132d47a176b05fd85eaa758945549";
const DEST_WALLET: &str = "0x1111111111111111111111111111111111111111";
const USDC: &str = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
// 1 USDC = 1_000_000 (6 decimals)
const AMOUNT: u64 = 1_000_000;

sol! {
    struct ProxyTransaction {
        uint8 typeCode;
        address to;
        uint256 value;
        bytes data;
    }
    function proxy(ProxyTransaction[] txns);
}

fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn load_config(path: &str) -> Result<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider().install_default().unwrap();

    let cfg = load_config("config.json")?;
    let pk = cfg["polymarket"]["private_key"].as_str().context("private_key")?;
    let rpc_url = cfg["rpc"].as_str().context("rpc")?;

    let signer = PrivateKeySigner::from_str(pk)?;
    let eoa = signer.address();
    let proxy: Address = PROXY_WALLET.parse()?;
    let dest: Address = DEST_WALLET.parse()?;
    let usdc: Address = USDC.parse()?;

    println!("EOA:    {eoa:#x}");
    println!("Proxy:  {proxy:#x}");
    println!("Dest:   {dest:#x}");
    println!("USDC:   {usdc:#x}");

    // Build USDC transfer(address,uint256) inner calldata
    let transfer_sel = selector("transfer(address,uint256)");
    let mut inner_calldata = transfer_sel.to_vec();
    inner_calldata.extend_from_slice(&(dest, U256::from(AMOUNT)).abi_encode_params());

    // Build proxy(ProxyTransaction[]) calldata
    let proxy_txns = vec![ProxyTransaction {
        typeCode: 0, // Regular CALL
        to: usdc,
        value: U256::ZERO,
        data: Bytes::from(inner_calldata.clone()),
    }];
    let outer_calldata = proxyCall { txns: proxy_txns }.abi_encode();

    println!("\nExecuting transfer via proxy wallet...");
    println!("  inner calldata (USDC transfer): 0x{}", alloy::hex::encode(&inner_calldata));
    println!("  outer calldata (proxy):          0x{}", alloy::hex::encode(&outer_calldata));

    // Simulate first
    let client = reqwest::Client::new();
    let sim_params = serde_json::json!([{"from": format!("{eoa:#x}"), "to": format!("{proxy:#x}"), "data": format!("0x{}", alloy::hex::encode(&outer_calldata))}, "latest"]);
    let sim_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":sim_params});
    let sim_resp: serde_json::Value = client.post(rpc_url).json(&sim_body).send().await?.json().await?;
    if let Some(err) = sim_resp.get("error") {
        anyhow::bail!("Simulation failed: {err}");
    }
    println!("  ✅ Simulation passed!");

    // Send the real tx
    let nonce: u64 = {
        let params = serde_json::json!([format!("{eoa:#x}"), "latest"]);
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":params});
        let resp: serde_json::Value = client.post(rpc_url).json(&body).send().await?.json().await?;
        let h = resp["result"].as_str().context("bad nonce response")?;
        u64::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)?
    };

    let gas_price: u128 = {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_gasPrice","params":[]});
        let resp: serde_json::Value = client.post(rpc_url).json(&body).send().await?.json().await?;
        let h = resp["result"].as_str().context("bad gasPrice")?;
        u128::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)?
    };

    // Estimate gas
    let est_params = serde_json::json!([{"from": format!("{eoa:#x}"), "to": format!("{proxy:#x}"), "data": format!("0x{}", alloy::hex::encode(&outer_calldata))}, "latest"]);
    let est_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":est_params});
    let est_resp: serde_json::Value = client.post(rpc_url).json(&est_body).send().await?.json().await?;
    let gas_hex = est_resp["result"].as_str().context("bad estimate")?;
    let gas_limit = u64::from_str_radix(gas_hex.strip_prefix("0x").unwrap_or(gas_hex), 16)? + 50000;

    println!("  nonce={nonce} gas_price={gas_price} gas_limit={gas_limit}");

    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price,
        gas_limit,
        to: TxKind::Call(proxy),
        value: U256::ZERO,
        input: Bytes::from(outer_calldata),
    };
    let hash = tx.signature_hash();
    let sig = signer.sign_hash(&hash).await?;
    let signed = tx.into_signed(sig);

    let mut buf = Vec::new();
    signed.encode_2718(&mut buf);
    let raw = format!("0x{}", alloy::hex::encode(&buf));
    let send_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw]});
    let send_resp: serde_json::Value = client.post(rpc_url).json(&send_body).send().await?.json().await?;
    if let Some(err) = send_resp.get("error") {
        anyhow::bail!("Send failed: {err}");
    }
    let tx_hash = send_resp["result"].as_str().context("no tx hash")?;
    println!("  ✅ Tx sent: {tx_hash}");
    println!("  https://polygonscan.com/tx/{tx_hash}");

    // Wait for confirmation
    for _i in 0..60 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let params = serde_json::json!([tx_hash]);
        let receipt_body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":params});
        let receipt_resp: serde_json::Value = client.post(rpc_url).json(&receipt_body).send().await?.json().await?;
        if receipt_resp["result"].is_null() { continue; }
        let status = receipt_resp["result"]["status"].as_str().unwrap_or("0x0");
        if status == "0x1" {
            println!("  ✅ Confirmed!");
            return Ok(());
        }
        anyhow::bail!("Transaction failed on-chain");
    }
    anyhow::bail!("Timeout");
}
