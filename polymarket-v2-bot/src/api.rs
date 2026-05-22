use crate::models::*;
use anyhow::{Context, Result};
use log::{error, warn};
use reqwest::Client as ReqwestClient;
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_sol_types::{sol, SolCall};

use polymarket_client_sdk_v2::clob::types::{OrderType, Side, OrderStatusType, SignatureType};
use polymarket_client_sdk_v2::clob::types::request::{OrdersRequest, PriceRequest};
use polymarket_client_sdk_v2::clob::{Client as ClobClient, Config as ClobConfig};
use polymarket_client_sdk_v2::ctf::Client as CtfClient;
use polymarket_client_sdk_v2::ctf::types::{
    SplitPositionRequest, MergePositionsRequest, RedeemPositionsRequest,
};
use polymarket_client_sdk_v2::types::Decimal;
use polymarket_client_sdk_v2::{POLYGON, contract_config};

// Type alias for authenticated v2 CLOB client
type AuthClobClient = polymarket_client_sdk_v2::clob::Client<
    polymarket_client_sdk_v2::auth::state::Authenticated<
        polymarket_client_sdk_v2::auth::Normal,
    >,
>;

fn mask_url(url: &str) -> String {
    if url.len() > 50 {
        format!("{}...{}", &url[..35], &url[url.len()-10..])
    } else {
        url.to_string()
    }
}

sol! {
    #[allow(missing_docs)]
    function splitPosition(
        address collateralToken,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] partition,
        uint256 amount
    );

    #[allow(missing_docs)]
    function mergePositions(
        address collateralToken,
        bytes32 parentCollectionId,
        bytes32 conditionId,
        uint256[] partition,
        uint256 amount
    );
}

pub struct PolymarketApi {
    client: ReqwestClient,
    gamma_url: String,
    clob_url: String,
    api_key: Option<String>,
    api_secret: Option<String>,
    api_passphrase: Option<String>,
    private_key: Option<String>,
    proxy_wallet_address: Option<String>,
    signature_type: Option<u8>,
    rpc_url: Option<String>,
    rpc_backup_url: Option<String>,
    use_relayer: bool,
    relayer_api_key: Option<String>,
    relayer_api_key_address: Option<String>,
    authenticated_clob: Arc<tokio::sync::RwLock<Option<AuthClobClient>>>,
    signer: Arc<tokio::sync::RwLock<Option<PrivateKeySigner>>>,
}

impl PolymarketApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gamma_url: String,
        clob_url: String,
        api_key: Option<String>,
        api_secret: Option<String>,
        api_passphrase: Option<String>,
        private_key: Option<String>,
        proxy_wallet_address: Option<String>,
        signature_type: Option<u8>,
        rpc_url: Option<String>,
        rpc_backup_url: Option<String>,
        use_relayer: bool,
        relayer_api_key: Option<String>,
        relayer_api_key_address: Option<String>,
    ) -> Self {
        let http_client = ReqwestClient::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client: http_client,
            gamma_url,
            clob_url,
            api_key,
            api_secret,
            api_passphrase,
            private_key,
            proxy_wallet_address,
            signature_type,
            rpc_url,
            rpc_backup_url,
            use_relayer,
            relayer_api_key,
            relayer_api_key_address,
            authenticated_clob: Arc::new(tokio::sync::RwLock::new(None)),
            signer: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    fn get_rpc_url(&self) -> String {
        if let Some(ref url) = self.rpc_url {
            return url.clone();
        }
        if let Ok(env_url) = std::env::var("POLYGON_RPC_URL") {
            if !env_url.is_empty() {
                return env_url;
            }
        }
        if let Ok(env_key) = std::env::var("ALCHEMY_API_KEY") {
            if !env_key.is_empty() {
                return format!("https://polygon-mainnet.g.alchemy.com/v2/{}", env_key);
            }
        }
        "https://polygon-rpc.com".to_string()
    }

    fn create_signer(&self) -> Result<PrivateKeySigner> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key is required"))?;
        PrivateKeySigner::from_str(private_key)
            .context("Failed to create signer")
            .map(|s| s.with_chain_id(Some(POLYGON)))
    }

    async fn get_clob_client(&self) -> Result<AuthClobClient> {
        let guard = self.authenticated_clob.read().await;
        guard.clone()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated. Call authenticate() first."))
    }

    async fn get_signer(&self) -> Result<PrivateKeySigner> {
        let guard = self.signer.read().await;
        guard.clone()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated."))
    }

    pub async fn authenticate(&self) -> Result<()> {
        let signer = self.create_signer()?;
        let address = signer.address();

        // Parse funder (proxy wallet) and signature type
        let funder = match &self.proxy_wallet_address {
            Some(proxy_addr) => Some(
                Address::from_str(proxy_addr).context("Invalid proxy wallet address")?,
            ),
            None => None,
        };

        let sig_type = match self.signature_type {
            Some(2) => SignatureType::GnosisSafe,
            Some(3) => SignatureType::Poly1271,
            _ => SignatureType::Eoa,
        };

        // Derive API credentials scoped to the proxy wallet (funder)
        let credentials = {
            let bootstrap = ClobClient::new(
                &self.clob_url,
                ClobConfig::default(),
            )?;
            bootstrap
                .create_or_derive_api_key(&signer, None)
                .await
                .context("Failed to create/derive API key for proxy wallet")?
        };

        let config = ClobConfig::builder().use_server_time(true).build();
        let mut auth_builder = ClobClient::new(&self.clob_url, config)?
            .authentication_builder(&signer)
            .credentials(credentials);

        if let Some(f) = funder {
            auth_builder = auth_builder.funder(f);
        }
        auth_builder = auth_builder.signature_type(sig_type);

        let client = auth_builder
            .authenticate()
            .await
            .context("Failed to authenticate with Polymarket CLOB V2 API")?;

        let mut guard = self.authenticated_clob.write().await;
        *guard = Some(client);

        let mut signer_guard = self.signer.write().await;
        *signer_guard = Some(signer);

        eprintln!("   ✓ Successfully authenticated with Polymarket CLOB V2 API");
        eprintln!("   ✓ Signer address: {:?}", address);
        if let Some(proxy_addr) = &self.proxy_wallet_address {
            eprintln!("   ✓ Proxy wallet: {}", proxy_addr);
        }
        Ok(())
    }

    pub async fn get_market_by_slug(&self, slug: &str) -> Result<Market> {
        use polymarket_client_sdk_v2::gamma::Client as GammaClient;
        use polymarket_client_sdk_v2::gamma::types::request::EventBySlugRequest;

        let gamma = GammaClient::new(&self.gamma_url)?;
        let req = EventBySlugRequest::builder().slug(slug.to_string()).build();
        let event = gamma.event_by_slug(&req).await
            .context(format!("Failed to fetch event by slug: {}", slug))?;

        if let Some(markets) = event.markets {
            if let Some(gamma_market) = markets.into_iter().next() {
                return Ok(Market {
                    condition_id: gamma_market.condition_id
                        .map(|c| {
                            let bytes: [u8; 32] = c.into();
                            format!("0x{}", hex::encode(bytes))
                        })
                        .unwrap_or_default(),
                    market_id: Some(gamma_market.id),
                    question: gamma_market.question.unwrap_or_default(),
                    slug: gamma_market.slug.unwrap_or_default(),
                    end_date_iso: gamma_market.end_date.map(|d| d.to_rfc3339()),
                    active: event.active.unwrap_or(false),
                    closed: event.closed.unwrap_or(false),
                });
            }
        }
        anyhow::bail!("No markets found for slug: {}", slug)
    }

    pub async fn get_market(&self, condition_id: &str) -> Result<MarketDetails> {
        let clob = self.get_clob_client().await?;
        let response = clob.market(condition_id).await
            .context(format!("Failed to fetch market: {}", condition_id))?;

        Ok(MarketDetails {
            condition_id: condition_id.to_string(),
            question: response.question,
            tokens: response.tokens.into_iter().map(|t| MarketToken {
                outcome: t.outcome,
                token_id: t.token_id.to_string(),
                winner: t.winner,
            }).collect(),
            active: response.active,
            closed: response.closed,
            end_date_iso: response.end_date_iso
                .map(|d| d.to_rfc3339())
                .unwrap_or_default(),
        })
    }

    pub async fn check_market_resolved(&self, condition_id: &str) -> Result<(bool, Option<String>, bool, bool)> {
        let market = self.get_market(condition_id).await?;
        let is_resolved = market.closed;

        let up_wins = market.tokens.iter().any(|t| t.outcome.to_lowercase() == "yes" && t.winner);
        let down_wins = market.tokens.iter().any(|t| t.outcome.to_lowercase() == "no" && t.winner);

        let winner = if up_wins {
            Some("up".to_string())
        } else if down_wins {
            Some("down".to_string())
        } else {
            None
        };

        log::info!("[RESOLVED] Condition {}: resolved={}, up_wins={}, down_wins={}",
            condition_id, is_resolved, up_wins, down_wins);

        Ok((is_resolved, winner, up_wins, down_wins))
    }

    pub async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let clob = self.get_clob_client().await?;
        let signer = self.get_signer().await?;

        let side = match order.side.as_str() {
            "BUY" => Side::Buy,
            "SELL" => Side::Sell,
            _ => anyhow::bail!("Invalid side: {}", order.side),
        };

        let price = Decimal::from_str(&order.price)
            .context(format!("Invalid price: {}", order.price))?;
        let size = Decimal::from_str(&order.size)
            .context(format!("Invalid size: {}", order.size))?;
        let token_id = U256::from_str(&order.token_id)
            .context(format!("Invalid token_id: {}", order.token_id))?;

        eprintln!("📤 Placing {} {} {} @ {}", order.side, order.size, order.token_id, order.price);

        let mut builder = clob
            .limit_order()
            .token_id(token_id)
            .size(size)
            .price(price)
            .side(side);

        if order.time_in_force.as_deref() == Some("GTD") {
            if let Some(expiry) = order.expire_after {
                let expiration = chrono::DateTime::from_timestamp(expiry, 0)
                    .ok_or_else(|| anyhow::anyhow!("Invalid expiration"))?;
                builder = builder.order_type(OrderType::GTD).expiration(expiration);
            }
        }

        let response = match builder.build_sign_and_post(&signer).await {
            Ok(r) => r,
            Err(e) => {
                error!("build_sign_and_post SDK error: {:#}", e);
                anyhow::bail!("Failed to create, sign, and post order: {:#}", e);
            }
        };

        if !response.success {
            let msg = response.error_msg.as_deref().unwrap_or("Unknown error");
            error!("❌ Order rejected: {}", msg);
            anyhow::bail!("Order rejected: {}", msg);
        }

        eprintln!("✅ Order placed! ID: {}", response.order_id);
        Ok(OrderResponse {
            order_id: Some(response.order_id.clone()),
            status: response.status.to_string(),
            message: Some(format!("Order ID: {}", response.order_id)),
        })
    }

    pub async fn get_price(&self, token_id: &str, side: &str) -> Result<rust_decimal::Decimal> {
        let clob = self.get_clob_client().await?;
        let side_enum = match side.to_uppercase().as_str() {
            "SELL" => Side::Sell,
            _ => Side::Buy,
        };
        let tid = U256::from_str(token_id)
            .context(format!("Invalid token_id: {}", token_id))?;

        let req = PriceRequest::builder()
            .token_id(tid)
            .side(side_enum)
            .build();

        let resp = clob.price(&req).await
            .context("Failed to fetch price")?;
        Ok(resp.price)
    }

    pub async fn are_both_orders_filled(
        &self,
        up_order_id: &str,
        down_order_id: &str,
    ) -> Result<(bool, bool)> {
        let clob = self.get_clob_client().await?;

        let up_filled = clob.order(up_order_id).await
            .map(|o| o.status == OrderStatusType::Matched)
            .unwrap_or(false);

        let down_filled = clob.order(down_order_id).await
            .map(|o| o.status == OrderStatusType::Matched)
            .unwrap_or(false);

        Ok((up_filled, down_filled))
    }

    pub async fn get_open_orders(&self, _condition_id: &str) -> Result<Vec<OpenOrder>> {
        let clob = self.get_clob_client().await?;
        let req = OrdersRequest::builder().build();
        let page = clob.orders(&req, None).await
            .context("Failed to get open orders")?;

        let orders: Vec<OpenOrder> = page.data.into_iter().map(|o| OpenOrder {
            order_id: o.id,
            market: Some(o.market.to_string()),
            side: format!("{:?}", o.side).to_uppercase(),
            size: o.original_size.to_string(),
            price: o.price.to_string(),
            status: format!("{:?}", o.status),
            fill_size: Some(o.size_matched.to_string()),
            avg_fill_price: None,
            token_id: o.asset_id.to_string(),
        }).collect();
        Ok(orders)
    }

    pub async fn get_redeemable_positions(&self, wallet: &str) -> Result<Vec<String>> {
        let url = "https://data-api.polymarket.com/positions";
        let user = if wallet.starts_with("0x") {
            wallet.to_string()
        } else {
            format!("0x{}", wallet)
        };
        let response = self
            .client
            .get(url)
            .query(&[
                ("user", user.as_str()),
                ("redeemable", "true"),
                ("limit", "500"),
            ])
            .send()
            .await
            .context("Failed to fetch redeemable positions")?;
        if !response.status().is_success() {
            anyhow::bail!(
                "Data API returned {} for redeemable positions",
                response.status()
            );
        }
        let positions: Vec<Value> = response.json().await.unwrap_or_default();
        let mut condition_ids: Vec<String> = positions
            .iter()
            .filter(|p| {
                let size = p
                    .get("size")
                    .and_then(|s| s.as_f64())
                    .or_else(|| p.get("size").and_then(|s| s.as_u64().map(|u| u as f64)))
                    .or_else(|| {
                        p.get("size")
                            .and_then(|s| s.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                    });
                size.map(|s| s > 0.0).unwrap_or(false)
            })
            .filter_map(|p| {
                p.get("conditionId").and_then(|c| c.as_str()).map(|s| {
                    if s.starts_with("0x") {
                        s.to_string()
                    } else {
                        format!("0x{}", s)
                    }
                })
            })
            .collect();
        condition_ids.sort();
        condition_ids.dedup();
        Ok(condition_ids)
    }

    pub async fn get_mergeable_positions(&self, wallet: &str) -> Result<Vec<MergeablePosition>> {
        let url = "https://data-api.polymarket.com/positions";
        let user = if wallet.starts_with("0x") {
            wallet.to_string()
        } else {
            format!("0x{}", wallet)
        };
        let response = self
            .client
            .get(url)
            .query(&[
                ("user", user.as_str()),
                ("mergeable", "true"),
                ("limit", "500"),
            ])
            .send()
            .await
            .context("Failed to fetch mergeable positions")?;
        if !response.status().is_success() {
            log::warn!("Data API returned {} for mergeable positions", response.status());
            return Ok(Vec::new());
        }
        let positions: Vec<Value> = response.json().await.unwrap_or_default();
        let mergeable_positions: Vec<MergeablePosition> = positions
            .iter()
            .filter_map(|p| {
                let size = p
                    .get("size")
                    .and_then(|s| s.as_f64())
                    .or_else(|| p.get("size").and_then(|s| s.as_u64().map(|u| u as f64)))
                    .or_else(|| {
                        p.get("size")
                            .and_then(|s| s.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                    })?;
                if size <= 0.0 {
                    return None;
                }
                let condition_id = p.get("conditionId").and_then(|c| c.as_str()).map(|s| {
                    if s.starts_with("0x") {
                        s.to_string()
                    } else {
                        format!("0x{}", s)
                    }
                })?;
                let title = p
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Unknown")
                    .to_string();
                Some(MergeablePosition {
                    condition_id,
                    size,
                    title,
                })
            })
            .collect();
        Ok(mergeable_positions)
    }

    pub async fn split_shares(&self, condition_id: &str, amount: f64) -> Result<String> {
        if self.use_relayer {
            return self.split_shares_via_relayer(condition_id, amount).await;
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

    pub async fn merge_shares(&self, condition_id: &str, amount: f64) -> Result<String> {
        if self.use_relayer {
            return self.merge_shares_via_relayer(condition_id, amount).await;
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

    pub async fn redeem_tokens(
        &self,
        condition_id: &str,
        _token_id: &str,
        outcome: &str,
    ) -> Result<RedeemResponse> {
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

        let index_sets = if outcome.to_uppercase().contains("UP") {
            vec![U256::from(1)]
        } else {
            vec![U256::from(2)]
        };

        let req = RedeemPositionsRequest::builder()
            .collateral_token(collateral)
            .condition_id(condition_id_b256)
            .index_sets(index_sets)
            .build();

        let result = ct.redeem_positions(&req).await
            .context("Failed to redeem tokens")?;

        Ok(RedeemResponse {
            success: true,
            message: Some(format!("Redeemed. TX: {:?}", result.transaction_hash)),
            transaction_hash: Some(format!("{:?}", result.transaction_hash)),
            amount_redeemed: None,
        })
    }

    pub async fn split_shares_with_retry(
        &self,
        condition_id: &str,
        amount: f64,
        max_retries: u32,
        initial_delay_ms: u64,
    ) -> Result<String> {
        let mut attempts = 0;
        let mut delay = initial_delay_ms;
        let mut last_error: Option<String> = None;

        while attempts < max_retries {
            attempts += 1;
            log::info!("[RETRY] Split attempt {}/{}...", attempts, max_retries);

            match self.split_shares(condition_id, amount).await {
                Ok(tx_hash) => {
                    log::info!("[RETRY] ✅ Split success on attempt {}! TX: {}", attempts, tx_hash);
                    return Ok(tx_hash);
                }
                Err(e) => {
                    let error_str = format!("{}", e);
                    last_error = Some(error_str.clone());
                    log::warn!("[RETRY] ❌ Attempt {} failed: {}", attempts, error_str);

                    let is_retryable = !error_str.contains("insufficient balance")
                        && !error_str.contains("user rejected")
                        && !error_str.contains("API key disabled");
                    if !is_retryable {
                        log::warn!("[RETRY] Non-retryable error, giving up");
                        break;
                    }
                    if attempts < max_retries {
                        log::info!("[RETRY] Retrying in {}ms...", delay);
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                        delay = delay.saturating_mul(2).min(10000);
                    }
                }
            }
        }
        Err(last_error
            .map(anyhow::Error::msg)
            .unwrap_or_else(|| anyhow::anyhow!("Split failed after {} attempts", max_retries)))
    }

    pub async fn merge_shares_with_retry(
        &self,
        condition_id: &str,
        amount: f64,
        max_retries: u32,
        initial_delay_ms: u64,
    ) -> Result<String> {
        let mut attempts = 0;
        let mut delay = initial_delay_ms;
        let mut last_error: Option<String> = None;

        while attempts < max_retries {
            attempts += 1;
            log::info!("[MERGE-RETRY] Merge attempt {}/{}...", attempts, max_retries);

            match self.merge_shares(condition_id, amount).await {
                Ok(tx_hash) => {
                    log::info!("[MERGE-RETRY] ✅ Merge success on attempt {}! TX: {}", attempts, tx_hash);
                    return Ok(tx_hash);
                }
                Err(e) => {
                    let error_str = format!("{}", e);
                    last_error = Some(error_str.clone());
                    log::warn!("[MERGE-RETRY] ❌ Attempt {} failed: {}", attempts, error_str);

                    let is_retryable = !error_str.contains("insufficient balance")
                        && !error_str.contains("insufficient funds")
                        && !error_str.contains("user rejected")
                        && !error_str.contains("condition already resolved")
                        && !error_str.contains("subtraction overflow")
                        && !error_str.contains("execution reverted");
                    if !is_retryable {
                        log::warn!("[MERGE-RETRY] Non-retryable error, giving up");
                        break;
                    }
                    if attempts < max_retries {
                        log::info!("[MERGE-RETRY] Retrying in {}ms...", delay);
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                        delay = delay.saturating_mul(2).min(10000);
                    }
                }
            }
        }
        Err(last_error
            .map(anyhow::Error::msg)
            .unwrap_or_else(|| anyhow::anyhow!("Merge failed after {} attempts", max_retries)))
    }

    async fn execute_relayer_tx(&self, calldata: Vec<u8>, label: &str) -> Result<String> {
        use polyoxide_relay::{
            BuilderAccount, RelayClient, SafeTransaction, WalletType,
        };

        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required for Relayer {}", label))?;
        let relayer_key = self.relayer_api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("relayer_api_key required"))?;
        let relayer_key_addr = self.relayer_api_key_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("relayer_api_key_address required"))?;

        let ctf_addr: Address = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045".parse()?;

        let account = BuilderAccount::with_relayer_api_key(
            private_key.to_string(),
            relayer_key.to_string(),
            relayer_key_addr.to_string(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create BuilderAccount: {}", e))?;

        // Default relayer URL: https://relayer-v2.polymarket.com
        let relay = RelayClient::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create RelayClient builder: {}", e))?
            .with_account(account)
            .wallet_type(WalletType::Safe)
            .chain_id(137)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build RelayClient: {}", e))?;

        let tx = SafeTransaction {
            to: ctf_addr,
            value: U256::ZERO,
            data: Bytes::from(calldata),
            operation: 0,
        };

        let submitted = relay.execute(vec![tx], None).await
            .map_err(|e| anyhow::anyhow!("Relayer execute ({}) failed: {}", label, e))?;

        let tx_id = submitted.transaction_id.to_string();
        log::info!("[RELAYER] {} submitted. ID: {}", label, tx_id);

        let max_polls = 30u32;
        for i in 0..max_polls {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            let tx = relay.get_transaction(&tx_id).await
                .map_err(|e| anyhow::anyhow!("Polling error: {}", e))?;
            log::debug!("[RELAYER] {} poll {}/{} -- state: {}", label, i + 1, max_polls, tx.state);
            if tx.state == "STATE_CONFIRMED" {
                if let Some(tx_hash) = &tx.transaction_hash {
                    return Ok(tx_hash.to_string());
                }
                return Ok(tx_id);
            }
            if tx.state == "STATE_FAILED" {
                anyhow::bail!("Relayer {} failed: state={:?}", label, tx.state);
            }
            if i % 5 == 4 {
                log::info!("[RELAYER] {} still waiting... poll {}/{}", label, i + 1, max_polls);
            }
        }
        anyhow::bail!("Relayer {} did not confirm within timeout", label)
    }

    async fn split_shares_via_relayer(&self, condition_id: &str, amount: f64) -> Result<String> {
        let condition_id_clean = condition_id.strip_prefix("0x").unwrap_or(condition_id);
        let condition_id_b256 = B256::from_str(condition_id_clean)
            .context("Invalid condition_id")?;
        let amount_u256 = U256::from((amount * 1_000_000.0) as u64);

        let calldata = splitPositionCall {
            collateralToken: Address::from_str("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB")?,
            parentCollectionId: B256::ZERO,
            conditionId: condition_id_b256,
            partition: vec![U256::from(1), U256::from(2)],
            amount: amount_u256,
        }
        .abi_encode();

        self.execute_relayer_tx(calldata, "Split").await
    }

    pub async fn merge_shares_via_relayer(&self, condition_id: &str, amount: f64) -> Result<String> {
        let condition_id_clean = condition_id.strip_prefix("0x").unwrap_or(condition_id);
        let condition_id_b256 = B256::from_str(condition_id_clean)
            .context("Invalid condition_id")?;
        let amount_u256 = U256::from((amount * 1_000_000.0) as u64);

        let calldata = mergePositionsCall {
            collateralToken: Address::from_str("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB")?,
            parentCollectionId: B256::ZERO,
            conditionId: condition_id_b256,
            partition: vec![U256::from(1), U256::from(2)],
            amount: amount_u256,
        }
        .abi_encode();

        self.execute_relayer_tx(calldata, "Merge").await
    }
}
