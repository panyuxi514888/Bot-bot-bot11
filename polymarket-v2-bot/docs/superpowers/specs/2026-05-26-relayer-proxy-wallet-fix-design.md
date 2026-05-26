# Replace Custom Relayer with rs-builder-relayer-client SDK

**Date:** 2026-05-26
**Status:** Draft

## Problem

The bot's custom relayer implementation (`execute_relayer_tx` in `api.rs`) hardcodes Safe wallet address derivation via CREATE2. The user's wallet is a Magic.link Proxy wallet (address `0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48`), not a Safe wallet. This causes:

1. **Address mismatch**: The derived Safe address never matches the actual proxy wallet address, so CTF operations (split/merge) send tokens to the wrong address.
2. **Wrong signature format**: SafeTx EIP-712 signatures are used instead of the format expected for proxy wallets.

The CLOB API path (order placement) already correctly uses the proxy wallet address as `funder`. CTF operations must use the same address for consistency.

### Current wallet configuration

| Key | Value |
|-----|-------|
| EOA | `0x2200709f4eeee905a9f463afc92e215630bc6b62` |
| Proxy wallet | `0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48` |
| Signature type | 3 (Poly1271) |
| Relayer API key address | `0x2200709f4eeee905a9f463afc92e215630bc6b62` |

## Solution

Replace the hand-written relayer HTTP interaction (~220 lines) with the `rs-builder-relayer-client` v0.1.3 SDK. The SDK natively supports Proxy wallets with explicit address injection, on-chain nonce reading, and quota-exhausted fallback to direct execution.

### Why rs-builder-relayer-client over fixing the custom code

- The SDK already implements proxy wallet support including correct signature formats
- `DirectExecutor::new_proxy_with_address` accepts explicit proxy address (no derivation)
- On-chain nonce reading avoids staleness issues
- Quota exhaustion fallback is built-in
- Reference implementation at `https://github.com/libaice/test-rs-polymarket-builder-relayer-sdk` validates the pattern

## Architecture Changes

### Dependencies

**Add:**
```toml
rs-builder-relayer-client = "0.1.3"
ethers = "2"
```

**Remove:**
```toml
polyoxide-relay = "0.15"
```

`ethers` coexists with the existing `alloy` dependency. Alloy continues to handle CLOB orders and CTF direct path; ethers is only used to create `LocalWallet` for the SDK.

### Modified files

| File | Change |
|------|--------|
| `Cargo.toml` | Add `rs-builder-relayer-client`, `ethers`; remove `polyoxide-relay` |
| `src/api.rs` | Remove `execute_relayer_tx`, `split_shares_via_relayer`, `merge_shares_via_relayer`. Add `get_relay_client()`, rewrite `split_shares`/`merge_shares`/`redeem_tokens` relayer paths |
| `src/config.rs` | No changes required |

### Config (no changes)

Existing `config.json` fields are sufficient:

```json
{
  "polymarket": {
    "private_key": "...",
    "proxy_wallet_address": "0x30f6...2e48",
    "signature_type": 3,
    "use_relayer": true,
    "relayer_api_key": "...",
    "relayer_api_key_address": "0x2200...6b62"
  }
}
```

### RelayerTxType mapping

```rust
fn relayer_tx_type(signature_type: Option<u8>) -> RelayerTxType {
    match signature_type {
        Some(1) | Some(3) => RelayerTxType::Proxy,
        Some(2) => RelayerTxType::Safe,
        _ => RelayerTxType::Eoa,
    }
}
```

Note: `RelayerTxType::from_signature_type()` in the SDK only handles 0/1/2. The wrapper above additionally maps type 3 (Poly1271) to Proxy, which is correct since Poly1271 wallets are proxy contracts with EIP-1271 signature validation.

## New Code Structure

### RelayClient initialization (lazy, cached)

```rust
impl PolymarketApi {
    async fn get_relay_client(&self) -> Result<RelayClient> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required"))?;
        let wallet: ethers::signers::LocalWallet = private_key.parse()?;

        let auth = AuthMethod::relayer_key(
            self.relayer_api_key.as_deref().unwrap_or(""),
            self.relayer_api_key_address.as_deref().unwrap_or(""),
        );

        let tx_type = relayer_tx_type(self.signature_type);
        let mut client = RelayClient::new(137, wallet, auth, tx_type).await?;

        if let Some(rpc) = &self.rpc_url {
            client.set_rpc_url(rpc.clone());
        }
        Ok(client)
    }
}
```

### Split via relayer

```rust
async fn split_via_relayer(&self, client: &RelayClient, condition_id: &str, amount: f64) -> Result<String> {
    let cid = parse_condition_id(condition_id)?;
    let tx = operations::split_regular(cid, &[1, 2], to_u256(amount));
    let result = client.execute(vec![tx], "Split").await?.wait().await?;
    Ok(format!("{:?}", result.tx_hash))
}
```

### Merge via relayer

```rust
async fn merge_via_relayer(&self, client: &RelayClient, condition_id: &str, amount: f64) -> Result<String> {
    let cid = parse_condition_id(condition_id)?;
    let tx = operations::merge_regular(cid, &[1, 2], to_u256(amount));
    let result = client.execute(vec![tx], "Merge").await?.wait().await?;
    Ok(format!("{:?}", result.tx_hash))
}
```

### Redeem via relayer (new capability)

```rust
async fn redeem_via_relayer(&self, client: &RelayClient, condition_id: &str) -> Result<String> {
    let cid = parse_condition_id(condition_id)?;
    let tx = operations::redeem_regular(cid, &[1, 2]);
    let result = client.execute(vec![tx], "Redeem").await?.wait().await?;
    Ok(format!("{:?}", result.tx_hash))
}
```

## Error Handling & Fallback

```
relayer execute()
  ├─ Ok(handle) → handle.wait().await
  │   ├─ Ok(result) → return tx_hash
  │   └─ Err(timeout) → retry once, then error
  │
  ├─ Err(RelayerError::QuotaExhausted)
  │   └─ DirectExecutor::new_proxy_with_address(rpc, wallet, 137, proxy_addr)
  │       → direct.execute(&tx).await
  │
  └─ Err(other) → fall through to existing retry framework
```

The existing `split_shares_with_retry` and `merge_shares_with_retry` methods are preserved. Their internals are updated to call the SDK-based relayer methods. The retry loop handles transient failures; the SDK handles quota exhaustion internally where possible.

## Preserved Logic

| Component | Status |
|-----------|--------|
| CLOB order placement (`place_order`, `presign_order`, `try_post_presigned`) | Unchanged |
| CLOB authentication (`authenticate`, L1/L2 headers) | Unchanged |
| CTF direct path via `CtfClient` (self-pay gas) | Unchanged, serves as fallback when `use_relayer = false` |
| `split_shares_with_retry` | Retry framework kept, internal calls updated |
| `merge_shares_with_retry` | Retry framework kept, internal calls updated |
| `check_pending_merges_on_startup` | Updated to use SDK merge |
| Market discovery, strategy loop, WebSocket subscription | Unchanged |

## Deleted Code

| Code | Location | Approx. lines |
|------|----------|---------------|
| `execute_relayer_tx()` | `api.rs` | ~190 lines |
| `split_shares_via_relayer()` | `api.rs` | ~15 lines |
| `merge_shares_via_relayer()` | `api.rs` | ~15 lines |
| `polyoxide-relay` dep | `Cargo.toml` | 1 line |
| Safe CREATE2 constants (`FACTORY_ADDR`, `SAFE_INIT_CODE_HASH`) | `api.rs` | 2 lines |

## Contract Addresses

The SDK internally maintains contract addresses. Verified against official Polymarket docs:

| Contract | Official | SDK/Project | Match |
|----------|----------|-------------|-------|
| CTF (Conditional Tokens) | `0x4D97...6045` | `0x4D97...6045` | Yes |
| pUSD collateral | `0xC011...2DFB` | `0xC011...2DFB` | Yes |
| CTF Exchange V2 | `0xE111...996B` | `0xE111...996B` | Yes |
| Proxy Factory | `0xaB45...4052` | `0xaB45...4052` | Yes |
| CtfCollateralAdapter | `0xAdA1...cE1f` | Not in SDK v0.6.0 | Monitor |

The `CtfCollateralAdapter` is a newer contract not yet integrated into the SDK. If relayer split/merge calls start failing, this adapter may need to be explicitly used. For now, the SDK's `operations::split_regular/merge_regular` use the direct CTF path which works with the current relayer API.

## Risks & Unknowns

1. **ethers + alloy coexistence**: Both create their own HTTP providers. This doubles RPC connections but is functionally safe since they operate independently.
2. **`RelayerTxType::Proxy` vs signature_type 3**: The SDK maps type 3 to `None`. Our wrapper maps it to `Proxy`. If the relayer API rejects this mapping, we may need to use `RelayerTxType::Eoa` or fork the SDK.
3. **Proxy wallet direct fallback**: Proxy wallet direct execution may behave differently than Safe. The SDK's `DirectExecutor::new_proxy_with_address` is designed for this, but has not been tested with the user's specific wallet.
