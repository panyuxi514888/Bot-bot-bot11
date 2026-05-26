# Replace Custom Relayer with rs-builder-relayer-client SDK — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-written relayer HTTP code with `rs-builder-relayer-client` v0.1.3 SDK so CTF operations (split/merge/redeem) use the correct proxy wallet address (`0x30f6...2e48`).

**Architecture:** Add `rs-builder-relayer-client` and `ethers` dependencies alongside existing `alloy`. Alloy handles CLOB orders and CTF direct path; ethers creates the `LocalWallet` for the new SDK. The SDK's `RelayClient` (with `RelayerTxType::Proxy`) replaces ~220 lines of manual Safe-specific relayer HTTP code.

**Tech Stack:** Rust, `rs-builder-relayer-client` v0.1.3, `ethers` v2, `alloy` v1.3, `polymarket_client_sdk_v2` v0.6.0-canary.1

**Spec:** `docs/superpowers/specs/2026-05-26-relayer-proxy-wallet-fix-design.md`

---

### Task 1: Update Cargo.toml dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add new dependencies, remove old one**

Replace these lines in `Cargo.toml`:

```toml
# Remove this line:
polyoxide-relay = "0.15"

# Add these lines (in the [dependencies] section, alphabetical order):
ethers = "2"
rs-builder-relayer-client = "0.1.3"
```

Full diff for `[dependencies]` section:

```diff
- polyoxide-relay = "0.15"
+ ethers = "2"
+ rs-builder-relayer-client = "0.1.3"
```

- [ ] **Step 2: Run cargo update to resolve dependency tree**

```bash
cargo update
```

Expected: Should resolve without version conflicts. `ethers` v2 and `alloy` v1.3 can coexist.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add rs-builder-relayer-client and ethers, remove polyoxide-relay

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Add SDK imports and helper functions

**Files:**
- Modify: `src/api.rs` (add imports after line 40, add helpers before `impl PolymarketApi`)

- [ ] **Step 1: Add new use statements**

After line 40 (`use polymarket_client_sdk_v2::{POLYGON, contract_config};`), add:

```rust
// Relayer SDK (gasless CTF operations via Builder/Relayer API)
use rs_builder_relayer_client::{
    AuthMethod, DirectExecutor, RelayClient, RelayerError, RelayerTxType,
    operations,
};
```

- [ ] **Step 2: Add helper functions before `impl PolymarketApi`**

After the `ApiKeyResponse` struct (after line 120, before `pub struct PolymarketApi`), add:

```rust
/// Map config signature_type to SDK's RelayerTxType.
/// SDK only handles 0/1/2; we add 3 (Poly1271) → Proxy.
fn relayer_tx_type(signature_type: Option<u8>) -> RelayerTxType {
    match signature_type {
        Some(1) | Some(3) => RelayerTxType::Proxy,
        Some(2) => RelayerTxType::Safe,
        _ => RelayerTxType::Eoa,
    }
}

/// Convert "0x..." condition_id string to [u8; 32].
fn parse_condition_id(condition_id: &str) -> Result<[u8; 32]> {
    let hex_str = condition_id.strip_prefix("0x").unwrap_or(condition_id);
    let bytes = hex::decode(hex_str)
        .context("Invalid condition_id hex")?;
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&bytes);
    Ok(cid)
}

/// Convert f64 dollar amount to U256 wei (USDC has 6 decimals).
fn amount_to_u256(amount: f64) -> alloy::primitives::U256 {
    alloy::primitives::U256::from((amount * 1_000_000.0) as u64)
}
```

- [ ] **Step 3: Commit**

```bash
git add src/api.rs
git commit -m "feat: add SDK imports and helper functions for relayer migration

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Add RelayClient initialization method

**Files:**
- Modify: `src/api.rs` (add `get_relay_client` method to `impl PolymarketApi`)

- [ ] **Step 1: Add the method to `impl PolymarketApi`**

Add after the `warmup()` method (after line 428, before the `// ── P1: Pre-signed order support ──` comment):

```rust
    // ── Relayer SDK: lazy-init RelayClient ──

    /// Create or return a cached RelayClient for gasless CTF operations.
    /// The client is configured as Proxy wallet type (Magic.link / Poly1271).
    async fn get_relay_client(&self) -> Result<RelayClient> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required for relayer operations"))?;
        let wallet: ethers::signers::LocalWallet = private_key.parse()
            .context("Failed to parse private key as ethers LocalWallet")?;

        let auth = AuthMethod::relayer_key(
            self.relayer_api_key.as_deref().unwrap_or(""),
            self.relayer_api_key_address.as_deref().unwrap_or(""),
        );

        let tx_type = relayer_tx_type(self.signature_type);
        let mut client = RelayClient::new(137, wallet, auth, tx_type).await
            .context("Failed to create RelayClient")?;

        if let Some(ref rpc) = self.rpc_url {
            client.set_rpc_url(rpc.clone());
        }

        Ok(client)
    }
```

- [ ] **Step 2: Commit**

```bash
git add src/api.rs
git commit -m "feat: add get_relay_client method using rs-builder-relayer-client SDK

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Add SDK-based split/merge/redeem relayer methods

**Files:**
- Modify: `src/api.rs` (add methods to `impl PolymarketApi`)

- [ ] **Step 1: Add the three relayer methods**

Add after `get_relay_client()` (which was added in Task 3):

```rust
    /// Split USDC into conditional tokens via relayer (gasless).
    async fn split_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
        amount: f64,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let amt = amount_to_u256(amount);
        let tx = operations::split_regular(cid, &[1, 2], amt);
        let handle = client.execute(vec![tx], "Split").await
            .context("Relayer split execute failed")?;
        let result = handle.wait().await
            .context("Relayer split wait failed")?;
        Ok(format!("{:?}", result.tx_hash))
    }

    /// Merge conditional tokens back to USDC via relayer (gasless).
    async fn merge_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
        amount: f64,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let amt = amount_to_u256(amount);
        let tx = operations::merge_regular(cid, &[1, 2], amt);
        let handle = client.execute(vec![tx], "Merge").await
            .context("Relayer merge execute failed")?;
        let result = handle.wait().await
            .context("Relayer merge wait failed")?;
        Ok(format!("{:?}", result.tx_hash))
    }

    /// Redeem winning tokens via relayer (gasless).
    async fn redeem_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let tx = operations::redeem_regular(cid, &[1, 2]);
        let handle = client.execute(vec![tx], "Redeem").await
            .context("Relayer redeem execute failed")?;
        let result = handle.wait().await
            .context("Relayer redeem wait failed")?;
        Ok(format!("{:?}", result.tx_hash))
    }
```

- [ ] **Step 2: Commit**

```bash
git add src/api.rs
git commit -m "feat: add SDK-based split/merge/redeem relayer methods

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5: Rewrite `split_shares` to use SDK when use_relayer is true

**Files:**
- Modify: `src/api.rs` (replace `split_shares` body, lines 869-905)

- [ ] **Step 1: Replace the `split_shares` method**

Replace the current method (lines 869-905):

```rust
    pub async fn split_shares(&self, condition_id: &str, amount: f64) -> Result<String> {
        if self.use_relayer {
            return self.split_via_sdk_relayer(
                &self.get_relay_client().await?,
                condition_id,
                amount,
            ).await;
        }
```

That's the **first 5 lines** of the method. The rest of the direct path (lines 874-905) stays unchanged — keep the `let signer = self.create_signer()?;` through `Ok(format!("{:?}", result.transaction_hash))` block.

Full new method:

```rust
    pub async fn split_shares(&self, condition_id: &str, amount: f64) -> Result<String> {
        if self.use_relayer {
            return self.split_via_sdk_relayer(
                &self.get_relay_client().await?,
                condition_id,
                amount,
            ).await;
        }

        let signer = self.create_signer()?;
        let rpc_url = self.get_rpc_url();

        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect(&rpc_url)
            .await
            .context("Failed to connect to RPC")?;

        let ct = CtfClient::new(provider, POLYGON)?;

        let condition_id_clean = condition_id.strip_prefix("0x").unwrap_or(condition_id);
        let condition_id_b256 = B256::from_str(condition_id_clean)
            .context(format!("Invalid condition_id: {}", condition_id))?;

        let config = contract_config(POLYGON, false)
            .ok_or_else(|| anyhow::anyhow!("No contract config for POLYGON"))?;
        let collateral = config.collateral;

        let amount_u256 = U256::from((amount * 1_000_000.0) as u64);

        let req = SplitPositionRequest::for_binary_market(
            collateral,
            condition_id_b256,
            amount_u256,
        );

        let result = ct.split_position(&req).await
            .context("Failed to split position")?;

        Ok(format!("{:?}", result.transaction_hash))
    }
```

- [ ] **Step 2: Verify the split_shares_with_retry method still compiles**

`split_shares_with_retry` (line 1006) calls `self.split_shares(condition_id, amount).await` — this signature hasn't changed. No edits needed.

- [ ] **Step 3: Commit**

```bash
git add src/api.rs
git commit -m "feat: rewrite split_shares to route through SDK relayer

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6: Rewrite `merge_shares` to use SDK when use_relayer is true

**Files:**
- Modify: `src/api.rs` (replace `merge_shares` body, lines 907-956)

- [ ] **Step 1: Replace the `merge_shares` method**

Replace lines 907-910 (the relayer branch) with SDK call. The direct path (lines 912-955) stays unchanged.

Full new method:

```rust
    pub async fn merge_shares(&self, condition_id: &str, amount: f64) -> Result<String> {
        if self.use_relayer {
            return self.merge_via_sdk_relayer(
                &self.get_relay_client().await?,
                condition_id,
                amount,
            ).await;
        }

        let signer = self.create_signer()?;
        let rpc_url = self.get_rpc_url();

        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&rpc_url)
            .await
            .context("Failed to connect to RPC")?;

        let ct = CtfClient::new(provider, POLYGON)?;

        let condition_id_clean = condition_id.strip_prefix("0x").unwrap_or(condition_id);
        let condition_id_b256 = B256::from_str(condition_id_clean)
            .context(format!("Invalid condition_id: {}", condition_id))?;

        let config = contract_config(POLYGON, false)
            .ok_or_else(|| anyhow::anyhow!("No contract config for POLYGON"))?;
        let collateral = config.collateral;

        let amount_u256 = U256::from((amount * 1_000_000.0) as u64);

        let req = MergePositionsRequest::builder()
            .collateral_token(collateral)
            .condition_id(condition_id_b256)
            .partition(vec![U256::from(1)])
            .amount(amount_u256)
            .build();

        let result = match ct.merge_positions(&req).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Merge with partition [1] failed: {}. Trying [2]...", e);
                let req2 = MergePositionsRequest::builder()
                    .collateral_token(collateral)
                    .condition_id(condition_id_b256)
                    .partition(vec![U256::from(2)])
                    .amount(amount_u256)
                    .build();
                ct.merge_positions(&req2).await
                    .map_err(|e2| anyhow::anyhow!("Merge failed: {} / {}", e, e2))?
            }
        };

        Ok(format!("{:?}", result.transaction_hash))
    }
```

- [ ] **Step 2: Commit**

```bash
git add src/api.rs
git commit -m "feat: rewrite merge_shares to route through SDK relayer

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7: Add relayer path to redeem_tokens

**Files:**
- Modify: `src/api.rs` (lines 958-1004)

- [ ] **Step 1: Add relayer branch**

At the top of `redeem_tokens` (after line 963), add the relayer branch:

```rust
    pub async fn redeem_tokens(
        &self,
        condition_id: &str,
        _token_id: &str,
        outcome: &str,
    ) -> Result<RedeemResponse> {
        if self.use_relayer {
            let tx_hash = self.redeem_via_sdk_relayer(
                &self.get_relay_client().await?,
                condition_id,
            ).await?;
            return Ok(RedeemResponse {
                success: true,
                message: Some(format!("Redeemed via relayer. TX: {}", tx_hash)),
                transaction_hash: Some(tx_hash),
                amount_redeemed: None,
            });
        }

        // existing direct path below (unchanged)
        let signer = self.create_signer()?;
        // ... rest stays the same
```

- [ ] **Step 2: Commit**

```bash
git add src/api.rs
git commit -m "feat: add relayer path to redeem_tokens using SDK

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 8: Remove old relayer code

**Files:**
- Modify: `src/api.rs` (delete dead code)

- [ ] **Step 1: Delete `execute_relayer_tx` method (lines 1099-1289)**

Delete the entire `async fn execute_relayer_tx(&self, calldata: Vec<u8>, label: &str) -> Result<String>` method and everything inside it.

- [ ] **Step 2: Delete `split_shares_via_relayer` method (lines 1291-1307)**

Delete the entire `async fn split_shares_via_relayer` method.

- [ ] **Step 3: Delete `merge_shares_via_relayer` method (lines 1309-1325)**

Delete the entire `async fn merge_shares_via_relayer` method. NOTE: This method is `pub` (used by tests or other modules). Verify with grep:

```bash
grep -rn 'merge_shares_via_relayer' src/
```

Expected: Only found in `api.rs` definition — safe to delete.

- [ ] **Step 4: Remove `splitPosition`, `mergePositions`, and `SafeTx` from sol! macro (lines 57-98)**

Replace the `sol!` block with a version that only keeps `ClobAuth`:

```rust
sol! {
    /// EIP-712 struct for Polymarket L1 auth (ClobAuthDomain)
    #[allow(missing_docs)]
    struct ClobAuth {
        address address;
        string  timestamp;
        uint256 nonce;
        string  message;
    }
}
```

Delete: `splitPosition` function def (lines 59-65), `mergePositions` function def (lines 68-74), `SafeTx` struct (lines 87-98).

- [ ] **Step 5: Delete Safe CREATE2 constants**

Delete lines 1111-1113 (inside the now-deleted `execute_relayer_tx` — will be removed with the function). Verify the constants don't exist elsewhere:

```bash
grep -rn 'FACTORY_ADDR\|SAFE_INIT_CODE_HASH' src/api.rs
```

Expected: No matches after deletion.

- [ ] **Step 6: Commit**

```bash
git add src/api.rs
git commit -m "refactor: remove old hand-written relayer code (~220 lines)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 9: Clean up unused imports

**Files:**
- Modify: `src/api.rs` (lines 1-40)

- [ ] **Step 1: Remove unused imports**

The following imports are no longer needed:

```diff
- use alloy::sol_types::{SolStruct, SolValue};
+ use alloy::sol_types::SolStruct;

- use alloy_sol_types::{sol, SolCall};
+ use alloy_sol_types::sol;

- use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
+ use alloy::primitives::{Address, B256, U256};
```

`Bytes` was only used in `SafeTx` (line 1174). `keccak256` was only used for CREATE2 salt (line 1115). `SolValue` was only used for `.abi_encode()` on the EOA for CREATE2 salt (line 1115). `SolCall` was only used for `.abi_encode()` on split/merge calldata (lines 1304, 1322).

- [ ] **Step 2: Commit**

```bash
git add src/api.rs
git commit -m "chore: remove unused imports after relayer code removal

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 10: Build and verify

**Files:**
- No file changes — verification only

- [ ] **Step 1: cargo check**

```bash
cargo check 2>&1
```

Expected: No errors. If there are import errors (e.g., `SolStruct` still needed), add back only what's required.

- [ ] **Step 2: cargo build**

```bash
cargo build 2>&1
```

Expected: Successful build. Fix any warnings about unused imports.

- [ ] **Step 3: Run existing tests**

```bash
cargo test 2>&1
```

Expected: All existing tests pass. Check that tests in `api.rs` (especially those referencing `TEST_FUNDER` and `create_funder_l1_headers`) still compile and pass.

- [ ] **Step 4: Verify test binaries still compile**

```bash
cargo build --bins 2>&1
```

Expected: All binaries compile (including `check_proxy`, `deploy_safe`, `test_split`, `transfer_proxy_usdc`, `transfer_proxy_via_safe`, `check_selectors`).

- [ ] **Step 5: Commit (if any fixes from build)**

```bash
git add src/api.rs
git commit -m "fix: build fixes after relayer SDK integration

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

Skip this step if build was clean.

---

### Task 11: Final verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test --release 2>&1
```

- [ ] **Step 2: Check git log for clean history**

```bash
git log --oneline -12
```

- [ ] **Step 3: Mark plan complete**

All tasks done.
