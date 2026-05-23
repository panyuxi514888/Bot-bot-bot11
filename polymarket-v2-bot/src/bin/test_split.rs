//! End-to-end test: prepare condition, fund Safe, approve CTF exchange, split position.
//!
//!   cargo run --bin test_split
//!
//! Steps:
//!   1. Prepare a test condition on the CTF exchange (if not exists) — via direct tx
//!   2. Transfer pUSD from EOA → Safe — via direct tx
//!   3. Safe approves CTF exchange (via relayer SAFE tx)
//!   4. Safe calls splitPosition (via relayer SAFE tx)

use alloy::consensus::{SignableTransaction, TxLegacy};
use alloy::dyn_abi::Eip712Domain;
use alloy::eips::eip2718::Encodable2718;
use alloy::hex::ToHexExt;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{SolStruct, SolValue};
use alloy_sol_types::sol;
use anyhow::{Context, Result};
use std::str::FromStr;

// ── Constants ──────────────────────────────────────────────────────────

const FACTORY_ADDR: &str = "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b";
const CTF_ADDR: &str = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045";
const PUSD_ADDR: &str = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB";
const SAFE_INIT_CODE_HASH: &str =
    "2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf";
const CHAIN_ID: u64 = 137;

sol! {
    struct SafeTx {
        address to; uint256 value; bytes data; uint8 operation;
        uint256 safeTxGas; uint256 baseGas; uint256 gasPrice;
        address gasToken; address refundReceiver; uint256 nonce;
    }
}

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

fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

// ── Low-level RPC via reqwest ─────────────────────────────────────────

async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .send()
        .await?;
    let rv: serde_json::Value = resp.json().await?;
    if let Some(e) = rv.get("error") {
        anyhow::bail!("RPC error: {e}");
    }
    Ok(rv["result"].clone())
}

async fn eth_call(url: &str, to: &str, data: &str) -> Result<Vec<u8>> {
    let params = serde_json::json!([{"to": to, "data": data}, "latest"]);
    let result = rpc_call(url, "eth_call", params).await?;
    let hex = result.as_str().context("eth_call returned non-string")?;
    Ok(hex::decode(hex.strip_prefix("0x").unwrap_or(hex))?)
}

async fn eth_nonce(url: &str, addr: &str) -> Result<u64> {
    let params = serde_json::json!([addr, "latest"]);
    let result = rpc_call(url, "eth_getTransactionCount", params).await?;
    let h = result.as_str().context("nonce returned non-string")?;
    Ok(u64::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)?)
}

async fn eth_gas_price(url: &str) -> Result<u128> {
    let result = rpc_call(url, "eth_gasPrice", serde_json::json!([])).await?;
    let h = result.as_str().context("gasPrice returned non-string")?;
    Ok(u128::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)?)
}

async fn eth_estimate_gas(url: &str, from: &str, to: &str, data: &str) -> Result<u64> {
    let params = serde_json::json!([{"from": from, "to": to, "data": data}, "latest"]);
    let result = rpc_call(url, "eth_estimateGas", params).await?;
    let h = result.as_str().context("estimateGas returned non-string")?;
    Ok(u64::from_str_radix(h.strip_prefix("0x").unwrap_or(h), 16)?)
}

async fn eth_send_raw(url: &str, raw: &[u8]) -> Result<String> {
    let params = serde_json::json!([format!("0x{}", hex::encode(raw))]);
    let result = rpc_call(url, "eth_sendRawTransaction", params).await?;
    Ok(result.as_str().context("sendRawTx returned non-string")?.to_string())
}

async fn eth_wait_tx(url: &str, tx_hash: &str) -> Result<()> {
    for i in 0..60 {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let params = serde_json::json!([tx_hash]);
        let result = rpc_call(url, "eth_getTransactionReceipt", params).await?;
        if result.is_null() {
            if i % 10 == 9 {
                println!("  Waiting for tx {tx_hash}... ({})", i + 1);
            }
            continue;
        }
        let status = result["status"].as_str().unwrap_or("0x0");
        if status == "0x1" {
            println!("  ✅ Confirmed: https://polygonscan.com/tx/{tx_hash}");
            return Ok(());
        }
        anyhow::bail!("Transaction failed: {tx_hash} status={status}");
    }
    anyhow::bail!("Timeout waiting for tx {tx_hash}");
}

/// Send a legacy transaction from the EOA via alloy's TxLegacy.
async fn send_legacy_tx(
    url: &str, signer: &PrivateKeySigner, to: Address, data: Vec<u8>, gas_limit: Option<u64>,
) -> Result<String> {
    let eoa = signer.address();
    let nonce = eth_nonce(url, &format!("{eoa:#x}")).await?;
    let gp = eth_gas_price(url).await?;
    let gl = match gas_limit {
        Some(g) => g,
        None => {
            let data_hex = format!("0x{}", hex::encode(&data));
            let est = eth_estimate_gas(url, &format!("{eoa:#x}"), &format!("{to:#x}"), &data_hex).await?;
            est + 100_000 // buffer
        }
    };

    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: gp,
        gas_limit: gl,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: Bytes::from(data),
    };
    let hash = tx.signature_hash();
    let sig = signer.sign_hash(&hash).await?;
    let signed = tx.into_signed(sig);

    let mut buf = Vec::new();
    signed.encode_2718(&mut buf);
    let tx_hash = eth_send_raw(url, &buf).await?;
    println!("  Tx sent: {tx_hash}");
    eth_wait_tx(url, &tx_hash).await?;
    Ok(tx_hash)
}

// ── Calldata builders ─────────────────────────────────────────────────

fn build_split_calldata(collateral: Address, parent_coll_id: B256, condition_id: B256, partition: Vec<U256>, amount: U256) -> Vec<u8> {
    let sel = &selector("splitPosition(address,bytes32,bytes32,uint256[],uint256)");
    let params = (collateral, parent_coll_id, condition_id, partition, amount).abi_encode_params();
    [sel, params.as_slice()].concat()
}

fn build_approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
    let sel = &selector("approve(address,uint256)");
    let params = (spender, amount).abi_encode_params();
    [sel, params.as_slice()].concat()
}

fn build_transfer_calldata(to: Address, amount: U256) -> Vec<u8> {
    let sel = &selector("transfer(address,uint256)");
    let params = (to, amount).abi_encode_params();
    [sel, params.as_slice()].concat()
}

fn build_prepare_condition_calldata(oracle: Address, question_id: B256, outcome_slot_count: U256) -> Vec<u8> {
    let sel = &selector("prepareCondition(address,bytes32,uint256)");
    let params = (oracle, question_id, outcome_slot_count).abi_encode_params();
    [sel, params.as_slice()].concat()
}

fn build_balance_of_calldata(owner: Address) -> Vec<u8> {
    let sel = &selector("balanceOf(address)");
    let params = (owner,).abi_encode_params();
    [sel, params.as_slice()].concat()
}

fn build_get_outcome_slot_calldata(condition_id: B256) -> Vec<u8> {
    let sel = &selector("getOutcomeSlotCount(bytes32)");
    let params = (condition_id,).abi_encode_params();
    [sel, params.as_slice()].concat()
}

// ── Relayer interaction ────────────────────────────────────────────────

async fn poll_relayer(
    client: &reqwest::Client, base: &str, rk: &str, ra: &str,
    tx_id: &str, label: &str, max_polls: u32,
) -> Result<String> {
    for i in 0..max_polls {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let r = client
            .get(format!("{base}/transaction?id={tx_id}"))
            .headers(auth_hdrs(rk, ra))
            .send().await?;
        if !r.status().is_success() { continue; }
        let txns: Vec<serde_json::Value> = r.json().await.unwrap_or_default();
        let td = txns.iter().find(|t| t["transactionID"].as_str() == Some(tx_id));
        let s = td.and_then(|t| t["state"].as_str()).unwrap_or("unknown");
        println!("  {label} poll {i}/{max_polls}: state={s}");
        match s {
            "STATE_CONFIRMED" | "STATE_MINED" => {
                let th = td.and_then(|t| t["transactionHash"].as_str()).unwrap_or(tx_id);
                println!("  ✅ {label} confirmed! https://polygonscan.com/tx/{th}");
                return Ok(th.to_string());
            }
            "STATE_FAILED" => {
                let reason = td.and_then(|t| t["failureReason"].as_str()).unwrap_or("unknown");
                anyhow::bail!("{label} failed: {reason}");
            }
            _ => {}
        }
    }
    anyhow::bail!("{label} timeout");
}

async fn submit_safe_tx(
    client: &reqwest::Client, rpc_url: &str, base: &str, rk: &str, ra: &str,
    signer: &PrivateKeySigner, eoa: Address, target: Address,
    calldata: &[u8], safe_addr: Address, label: &str,
) -> Result<String> {
    println!("\n── {label} (safe={safe_addr:#x}) ──");

    // Query on-chain nonce from Safe contract
    let nonce_data = "0xaffed0e0"; // keccak256("nonce()") selector
    let nonce_result = eth_call(rpc_url, &format!("{safe_addr:#x}"), nonce_data).await?;
    let nonce = if nonce_result.len() >= 32 {
        U256::from_be_slice(&nonce_result[..32]).to::<u64>()
    } else {
        0u64
    };
    println!("  on-chain nonce: {nonce}");

    let safe_tx = SafeTx {
        to: target, value: U256::ZERO, data: Bytes::from(calldata.to_vec()),
        operation: 0, safeTxGas: U256::ZERO, baseGas: U256::ZERO,
        gasPrice: U256::ZERO, gasToken: Address::ZERO,
        refundReceiver: Address::ZERO, nonce: U256::from(nonce),
    };

    // EIP-712 signing — matches polyoxide-relay client exactly
    let domain = Eip712Domain {
        name: None,
        version: None,
        chain_id: Some(U256::from(CHAIN_ID)),
        verifying_contract: Some(safe_addr),
        salt: None,
    };
    let struct_hash = safe_tx.eip712_signing_hash(&domain);
    let sig = signer.sign_message(struct_hash.as_slice()).await?;
    let v = if sig.v() { 32u8 } else { 31u8 };
    let mut p = Vec::with_capacity(65);
    p.extend_from_slice(&sig.r().to_be_bytes::<32>());
    p.extend_from_slice(&sig.s().to_be_bytes::<32>());
    p.push(v);

    let z = format!("{:#x}", Address::ZERO);
    let body = serde_json::json!({
        "type": "SAFE",
        "from": format!("{eoa:#x}"),
        "to": format!("{target:#x}"),
        "proxyWallet": format!("{safe_addr:#x}"),
        "data": calldata.encode_hex_with_prefix(),
        "signature": format!("0x{}", alloy::hex::encode(&p)),
        "signatureParams": {
            "gasPrice": "0", "operation": "0", "safeTxnGas": "0",
            "baseGas": "0", "gasToken": z, "refundReceiver": z
        },
        "value": "0",
        "nonce": nonce.to_string(),
    });
    let resp = client
        .post(format!("{base}/submit"))
        .headers(auth_hdrs(rk, ra))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body).send().await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("{label} submit failed {status}: {text}");
    }
    let sv: serde_json::Value = serde_json::from_str(&text)?;
    let tx_id = sv["transactionID"].as_str().context("no transactionID")?.to_string();
    println!("  ✅ Submitted! ID: {tx_id}, state: {:?}", sv["state"].as_str());
    Ok(tx_id)
}

// ── Main ───────────────────────────────────────────────────────────────

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
    let factory: Address = Address::from_str(FACTORY_ADDR)?;
    let ctf: Address = Address::from_str(CTF_ADDR)?;
    let pusd: Address = Address::from_str(PUSD_ADDR)?;

    // Derive SDK-style Safe address
    let salt = keccak256((eoa,).abi_encode());
    let code_hash = B256::from_str(SAFE_INIT_CODE_HASH)?;
    let safe_addr = factory.create2(salt, code_hash);

    println!("EOA:  {eoa:#x}");
    println!("Safe: {safe_addr:#x}");
    println!("CTF:  {ctf:#x}");
    println!("pUSD: {pusd:#x}");

    let client = reqwest::Client::new();
    let base = "https://relayer-v2.polymarket.com";

    // ── Step 1: Prepare condition (if needed) ──────────────────────
    let question_id = B256::from(keccak256(b"test-split-position-001"));
    let oracle = eoa;
    let outcome_slot_count = U256::from(2);
    let condition_id = B256::from(keccak256(
        &[oracle.as_slice(), question_id.as_slice(), &outcome_slot_count.to_be_bytes::<32>()].concat(),
    ));
    println!("\n── Condition ──");
    println!("  questionId:  {question_id:#x}");
    println!("  conditionId: {condition_id:#x}");

    let slot_data = build_get_outcome_slot_calldata(condition_id);
    let slot_hex = format!("0x{}", hex::encode(&slot_data));
    let slot_result = eth_call(rpc_url, CTF_ADDR, &slot_hex).await?;
    let existing_slots = if slot_result.len() >= 32 {
        U256::from_be_slice(&slot_result[..32])
    } else {
        U256::ZERO
    };
    if existing_slots == U256::ZERO {
        println!("  Condition not found. Preparing via EOA tx...");
        let prep_data = build_prepare_condition_calldata(oracle, question_id, outcome_slot_count);
        send_legacy_tx(rpc_url, &signer, ctf, prep_data, None).await?;
        println!("  ✅ Condition prepared!");
    } else {
        println!("  Condition exists (slots={existing_slots}).");
    }

    // ── Step 2: Fund Safe with pUSD ────────────────────────────────
    const PUSD_AMOUNT: u64 = 1_000;
    let amount = U256::from(PUSD_AMOUNT);

    // Check EOA pUSD balance
    let bal_data = build_balance_of_calldata(eoa);
    let bal_hex = format!("0x{}", hex::encode(&bal_data));
    let bal_result = eth_call(rpc_url, PUSD_ADDR, &bal_hex).await?;
    let eoa_bal = if bal_result.len() >= 32 {
        U256::from_be_slice(&bal_result[..32])
    } else {
        U256::ZERO
    };
    println!("\n── Funding ──");
    println!("  EOA pUSD balance: {eoa_bal}");
    if eoa_bal < amount {
        anyhow::bail!("EOA doesn't have enough pUSD (need {amount}, have {eoa_bal})");
    }

    // Check Safe pUSD balance
    let bal_data = build_balance_of_calldata(safe_addr);
    let bal_hex = format!("0x{}", hex::encode(&bal_data));
    let bal_result = eth_call(rpc_url, PUSD_ADDR, &bal_hex).await?;
    let safe_bal = if bal_result.len() >= 32 {
        U256::from_be_slice(&bal_result[..32])
    } else {
        U256::ZERO
    };
    println!("  Safe pUSD balance before: {safe_bal}");

    if safe_bal < amount {
        let tx_data = build_transfer_calldata(safe_addr, amount);
        println!("  Transferring {amount} pUSD from EOA → Safe...");
        send_legacy_tx(rpc_url, &signer, pusd, tx_data, None).await?;
        println!("  ✅ Funded Safe with {amount} pUSD");
    } else {
        println!("  Safe already has enough pUSD.");
    }

    // ── Step 3: Safe approves CTF exchange (via relayer) ───────────
    let approve_data = build_approve_calldata(ctf, amount);
    let tx_id = submit_safe_tx(
        &client, rpc_url, base, rk, ra, &signer, eoa, pusd,
        &approve_data, safe_addr, "Approve CTF exchange",
    ).await?;
    poll_relayer(&client, base, rk, ra, &tx_id, "Approve", 30).await?;

    // ── Step 4: SplitPosition via Safe (via relayer) ───────────────
    let split_data = build_split_calldata(
        pusd, B256::ZERO, condition_id,
        vec![U256::from(1), U256::from(2)], amount,
    );
    let tx_id = submit_safe_tx(
        &client, rpc_url, base, rk, ra, &signer, eoa, ctf,
        &split_data, safe_addr, "SplitPosition",
    ).await?;
    poll_relayer(&client, base, rk, ra, &tx_id, "Split", 30).await?;

    println!("\n✅ All steps completed successfully!");
    Ok(())
}
