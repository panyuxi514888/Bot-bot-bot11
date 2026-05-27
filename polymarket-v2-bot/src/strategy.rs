use crate::api::PolymarketApi;
use crate::clob_client::ClobClient;
use crate::config::Config;
use crate::discovery::MarketDiscovery;
use crate::models::*;
use anyhow::Result;
use chrono::Utc;
use chrono_tz::America::New_York;
use futures::StreamExt;
use log::{debug, error, info, warn};
use polymarket_client_sdk_v2::clob::types::Side as SdkSide;
use polymarket_client_sdk_v2::clob::ws::types::response::TradeMessageStatus;
use polymarket_client_sdk_v2::clob::ws::WsMessage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;

const MARKET_DURATION_SECS: i64 = 300;
const MARKET_DURATION_SECS_U64: u64 = 300;
const GTD_DURATION_SECS: i64 = 360; // 6 minutes

pub struct PreLimitStrategy {
    api: Arc<PolymarketApi>,
    config: Config,
    discovery: MarketDiscovery,
    state: Arc<Mutex<Option<PreLimitOrderState>>>,
    total_profit: Arc<Mutex<f64>>,
    trades: Arc<Mutex<HashMap<String, CycleTrade>>>,
    closure_checked: Arc<Mutex<HashMap<String, bool>>>,
    clob_client: Option<Arc<ClobClient>>,
    // P1: Background merge state
    pending_merges: Arc<Mutex<HashMap<String, PendingMerge>>>,
}

#[derive(Debug, Clone)]
struct CycleTrade {
    condition_id: String,
    period_timestamp: u64,
    market_duration_secs: u64,
    up_token_id: Option<String>,
    down_token_id: Option<String>,
    up_shares: f64,
    down_shares: f64,
    up_avg_price: f64,
    down_avg_price: f64,
    split_tx_hash: Option<String>,
}

impl PreLimitStrategy {
    pub async fn new(api: Arc<PolymarketApi>, config: Config) -> Self {
        let discovery = MarketDiscovery::new(api.clone());

        // Initialize CLOB client if private key is available
        info!("Checking if private key is available in config...");
        let clob_client = if config.polymarket.private_key.is_some() {
            info!("Private key found in config, attempting to create CLOB client");
            match ClobClient::new(&config).await {
                Ok(client) => {
                    info!("Successfully created CLOB client");
                    Some(Arc::new(client))
                }
                Err(e) => {
                    warn!("Failed to create CLOB client: {}", e);
                    None
                }
            }
        } else {
            info!("No private key found in config, skipping CLOB client initialization");
            None
        };

        Self {
            api,
            config,
            discovery,
            state: Arc::new(Mutex::new(None)),
            total_profit: Arc::new(Mutex::new(0.0)),
            trades: Arc::new(Mutex::new(HashMap::new())),
            closure_checked: Arc::new(Mutex::new(HashMap::new())),
            clob_client,
            // P1: Initialize pending merges
            pending_merges: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(dead_code)]
    pub async fn get_total_profit(&self) -> f64 {
        *self.total_profit.lock().await
    }

    async fn check_pending_merges_on_startup(&self) {
        info!("[STARTUP] Checking for pending merges from previous runs...");
        
        let wallet = match self.config.polymarket.proxy_wallet_address.as_ref() {
            Some(w) => w.clone(),
            None => {
                if let Some(pk) = &self.config.polymarket.private_key {
                    match crate::config::derive_polymarket_address(pk) {
                        Ok(addr) => addr,
                        Err(e) => {
                            warn!("[STARTUP] Failed to derive wallet address: {}", e);
                            return;
                        }
                    }
                } else {
                    warn!("[STARTUP] No wallet address available, skipping pending merge check");
                    return;
                }
            }
        };

        match self.api.get_mergeable_positions(&wallet).await {
            Ok(positions) if !positions.is_empty() => {
                info!("[STARTUP] Found {} mergeable positions from previous runs", positions.len());
                
                for pos in positions {
                    info!("[STARTUP] Merging position: {} (size: {})", &pos.condition_id[..16.min(pos.condition_id.len())], pos.size);
                    
                    const MAX_RETRIES: u32 = 3;
                    const INITIAL_DELAY_MS: u64 = 2000;
                    
                    match self.api.merge_shares_with_retry(&pos.condition_id, pos.size, MAX_RETRIES, INITIAL_DELAY_MS).await {
                        Ok(tx_hash) => {
                            info!("[STARTUP] Successfully merged {} (tx: {})", &pos.condition_id[..16.min(pos.condition_id.len())], tx_hash);
                        }
                        Err(e) => {
                            warn!("[STARTUP] Failed to merge {}: {}", &pos.condition_id[..16.min(pos.condition_id.len())], e);
                        }
                    }
                }
            }
            Ok(_) => {
                info!("[STARTUP] No pending merges found");
            }
            Err(e) => {
                warn!("[STARTUP] Failed to check mergeable positions: {}", e);
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        // Create cancellation token for graceful shutdown
        let shutdown_token = CancellationToken::new();
        let shutdown_token_clone = shutdown_token.clone();

        // Spawn Ctrl+C handler
        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("Received Ctrl+C, initiating graceful shutdown...");
                    shutdown_token_clone.cancel();
                }
                Err(e) => {
                    error!("Failed to listen for Ctrl+C: {}", e);
                }
            }
        });

        // Initialize CLOB subscription if client is available
        if let Some(clob_client) = &self.clob_client {
            info!(
                "Starting CLOB order and trade status subscription (event-driven SELL placement)"
            );

            let clob_client_clone = clob_client.clone();
            let state_clone = self.state.clone();
            let api_clone = self.api.clone();
            let config_clone = self.config.clone();
            let shutdown_token_clone = shutdown_token.clone();

            // Spawn task to handle CLOB subscription directly with shutdown support
            // This now handles both Order and Trade events for event-driven SELL placement
            tokio::spawn(async move {
                if let Err(e) = Self::handle_clob_subscription_direct(
                    clob_client_clone,
                    state_clone,
                    api_clone,
                    config_clone,
                    shutdown_token_clone,
                )
                .await
                {
                    error!("CLOB subscription error: {}", e);
                }
            });
        } else {
            warn!("CLOB client not available - order status updates will be disabled. Please check your config.json file and ensure private_key is set.");
        }

        // Main strategy loop with shutdown support
        info!("Starting main strategy loop");

        // P1: Check pending merges on startup (after restart)
        self.check_pending_merges_on_startup().await;

        // Main strategy loop with shutdown support
        loop {
            if shutdown_token.is_cancelled() {
                info!("Shutdown signal received, stopping strategy loop");
                break;
            }

            if let Err(e) = self.process_market().await {
                error!("Error processing market: {}", e);
            }

            tokio::select! {
                _ = sleep(Duration::from_millis(self.config.strategy.check_interval_ms)) => {}
                _ = shutdown_token.cancelled() => {
                    info!("Shutdown signal received during sleep, stopping strategy loop");
                    break;
                }
            }
        }

        info!("Strategy shutdown complete");
        Ok(())
    }

    async fn process_market(&self) -> Result<()> {
        let current_period_et = Self::get_current_5m_period_et();
        let current_time_et = Self::get_current_time_et();
        let next_period_start = current_period_et + MARKET_DURATION_SECS;

        let mut state_guard = self.state.lock().await;
        let state = state_guard.clone();

        match state {
            Some(mut s) => {
                if current_time_et > s.expiry {
                    let mut merge_success = true;

                    let actual_up_shares = s.up_shares_received;
                    let actual_down_shares = s.down_shares_received;
                    let total_shares = actual_up_shares + actual_down_shares;
                    let total_spent_usdc = s.up_spent_usdc + s.down_spent_usdc;
                    const SPLIT_AMOUNT: f64 = 5.0;

                    info!("[MERGE] Actual shares - UP: {}, DOWN: {}, Total: {}", actual_up_shares, actual_down_shares, total_shares);
                    info!("[MERGE] Actual USDC spent - UP: ${:.4}, DOWN: ${:.4}, Total: ${:.4}", s.up_spent_usdc, s.down_spent_usdc, total_spent_usdc);

                    const MERGE_MAX_RETRIES: u32 = 3;
                    const MERGE_INITIAL_DELAY_MS: u64 = 2000;
                    const MERGE_CHECK_INTERVAL_SECS: u64 = 30;
                    const MERGE_MAX_WAIT_SECS: u64 = 600;
                    
                    if total_shares < 0.01 {
                        info!("[MERGE] No shares to merge (total: {}), skipping", total_shares);
                    } else if !self.config.strategy.simulation_mode {
                        let condition_id = s.condition_id.clone();
                        let condition_id_for_display = condition_id.clone();
                        let api_clone = self.api.clone();
                        let pending_merges_clone = self.pending_merges.clone();
                        let merge_amount = SPLIT_AMOUNT;
                        
                        let initial_merge = PendingMerge {
                            condition_id: condition_id.clone(),
                            amount: merge_amount,
                            created_at: chrono::Utc::now().timestamp(),
                            status: crate::models::MergeStatus::InProgress,
                            last_error: None,
                            attempts: 0,
                        };
                        
                        {
                            let mut pending = pending_merges_clone.lock().await;
                            pending.insert(condition_id.clone(), initial_merge);
                        }
                        
                        let api_clone2 = self.api.clone();
                        let pending_merges_clone2 = self.pending_merges.clone();
                        tokio::spawn(async move {
                            let condition_id_inner = condition_id.clone();
                            let pending_merges_inner = pending_merges_clone.clone();
                            
                            info!("[BG-MERGE] Waiting for market resolved...");
                            
                            let start = std::time::Instant::now();
                            let mut market_resolved = false;
                            
                            loop {
                                if start.elapsed().as_secs() > MERGE_MAX_WAIT_SECS {
                                    warn!("[BG-MERGE] Market resolved check timeout, proceeding anyway");
                                    break;
                                }
                                
                                info!("[BG-MERGE] Checking market resolved (condition: {})...", &condition_id_inner[..16]);
                                match api_clone.check_market_resolved(&condition_id_inner).await {
                                    Ok((true, winner, up_wins, down_wins)) => {
                                        info!("[BG-MERGE] ✅ Market resolved! Winner: {:?}, up_wins: {}, down_wins: {}", 
                                            winner, up_wins, down_wins);
                                        market_resolved = true;
                                        break;
                                    }
                                    Ok((false, _, _, _)) => {
                                        info!("[BG-MERGE] Market not yet resolved, waiting...");
                                    }
                                    Err(e) => {
                                        warn!("[BG-MERGE] Check market resolved failed: {}", e);
                                        // 失败时继续等待，不中断
                                    }
                                }
                                
                                tokio::time::sleep(tokio::time::Duration::from_secs(MERGE_CHECK_INTERVAL_SECS)).await;
                            }
                            
                            if market_resolved {
                                let result = api_clone2.merge_shares_with_retry(
                                    &condition_id_inner, 
                                    merge_amount, 
                                    MERGE_MAX_RETRIES, 
                                    MERGE_INITIAL_DELAY_MS
                                ).await;
                                
                                let mut pending = pending_merges_inner.lock().await;
                                if let Some(pm) = pending.get_mut(&condition_id_inner) {
                                    match result {
                                        Ok(tx_hash) => {
                                            info!("[BG-MERGE] Successfully merged {:.2} shares (tx: {})", merge_amount, tx_hash);
                                            pm.status = crate::models::MergeStatus::Succeeded(tx_hash);
                                        }
                                        Err(e) => {
                                            error!("[BG-MERGE] Failed after retries: {}", e);
                                            pm.status = crate::models::MergeStatus::Failed(format!("{}", e));
                                            pm.last_error = Some(format!("{}", e));
                                        }
                                    }
                                }
                            } else {
                                warn!("[BG-MERGE] Market not resolved within timeout, skipping merge");
                            }
                        });
                        
                        info!("[MERGE] Spawned background merge task for condition {} with amount {:.2}", &condition_id_for_display[..condition_id_for_display.len().min(20)], merge_amount);
                    } else {
                        info!("SIMULATION: Would merge {:.2} shares for condition {}", total_shares, &s.condition_id[..s.condition_id.len().min(20)]);
                    }

                    if s.up_mined || s.down_mined {
                        let trade = Self::cycle_trade_from_state(&s, self.config.strategy.shares);
                        let mut t = self.trades.lock().await;
                        t.insert(s.condition_id.clone(), trade);
                        info!("Market expired. Registered position for redemption (condition: {}, up_mined: {}, down_mined: {})",
                            &s.condition_id[..s.condition_id.len().min(20)], s.up_mined, s.down_mined);
                    }

                    if merge_success || self.config.strategy.simulation_mode {
                        *state_guard = None;
                    } else {
                        error!("Merge failed but clearing state to allow new cycles. Position may need manual intervention.");
                        *state_guard = None;
                    }
                    return Ok(());
                }

                self.check_buy_order_matches(&mut s).await?;

                *state_guard = Some(s);
            }
            None => {
                if let Some(market) = self.discover_market("BTC", current_period_et).await? {
                    if current_time_et >= current_period_et && current_time_et < next_period_start {
                        let buy_price = self.config.strategy.buy_price;
                        info!(
                            "5min period started. Placing BUY orders at ${:.2} for BTC",
                            buy_price
                        );
                        let (up_token_id, down_token_id) = self
                            .discovery
                            .get_market_tokens(&market.condition_id)
                            .await?;

                        // Replace CTF split: market-buy next period's UP+DOWN tokens FIRST
                        let next_period = current_period_et + MARKET_DURATION_SECS;
                        match self.discover_market("BTC", next_period).await {
                            Ok(Some(next_market)) => {
                                let (next_up, next_down) = self
                                    .discovery
                                    .get_market_tokens(&next_market.condition_id)
                                    .await?;
                                info!(
                                    "Pre-buying next period tokens ({}) with limit order at 0.51",
                                    &next_market.condition_id[..16]
                                );
                                if let Err(e) = self.place_limit_order(&next_up, "BUY", 0.51).await {
                                    warn!("Next period UP limit buy at 0.51 failed: {}", e);
                                }
                                if let Err(e) = self.place_limit_order(&next_down, "BUY", 0.51).await {
                                    warn!("Next period DOWN limit buy at 0.51 failed: {}", e);
                                }
                            }
                            Ok(None) => {
                                info!("Next period market not yet available, skipping pre-buy");
                            }
                            Err(e) => {
                                warn!("Failed to discover next period market: {}", e);
                            }
                        }

                        // Check for existing orders — if found, restore state from them
                        if !self.config.strategy.simulation_mode {
                            if let Ok(orders) = self.api.get_open_orders(&market.condition_id).await {
                                let existing: Vec<_> = orders.iter().filter(|o| {
                                    o.token_id == up_token_id || o.token_id == down_token_id
                                }).collect();
                                if !existing.is_empty() {
                                    info!(
                                        "Found {} existing orders, restoring state (skipping new placement)",
                                        existing.len()
                                    );
                                    let restored = PreLimitOrderState {
                                        asset: "BTC".to_string(),
                                        condition_id: market.condition_id,
                                        up_token_id: up_token_id.clone(),
                                        down_token_id: down_token_id.clone(),
                                        up_order_id: None,
                                        down_order_id: None,
                                        up_buy_price: buy_price,
                                        down_buy_price: buy_price,
                                        up_matched: false,
                                        down_matched: false,
                                        up_mined: false,
                                        down_mined: false,
                                        up_shares_received: 0.0,
                                        down_shares_received: 0.0,
                                        up_spent_usdc: 0.0,
                                        down_spent_usdc: 0.0,
                                        up_sell_order_id: None,
                                        down_sell_order_id: None,
                                        expiry: next_period_start,
                                        order_placed_at: current_time_et,
                                        market_period_start: current_period_et,
                                        trade_info: std::collections::HashMap::new(),
                                        up_trade_confirmed: false,
                                        down_trade_confirmed: false,
                                        pending_trades: std::collections::VecDeque::new(),
                                        split_tx_hash: None,
                                    };
                                    *state_guard = Some(restored);
                                    return Ok(());
                                }
                            }
                        }

                        let split_tx_hash: Option<String> = None;

                        let up_order = self
                            .place_limit_order(&up_token_id, "BUY", buy_price)
                            .await?;
                        let down_order = self
                            .place_limit_order(&down_token_id, "BUY", buy_price)
                            .await?;

                        // P1: Pre-sign SELL orders immediately after placing BUY orders
                        if !self.config.strategy.simulation_mode {
                            let sell_price = self.config.strategy.sell_price;
                            let shares = self.config.strategy.shares;
                            info!("[PRESIGN] Pre-signing SELL orders ({} shares @ ${:.2})", shares, sell_price);
                            if let Err(e) = self.api.presign_order(&up_token_id, sell_price, shares).await {
                                warn!("[PRESIGN] Failed to pre-sign UP SELL: {}", e);
                            }
                            if let Err(e) = self.api.presign_order(&down_token_id, sell_price, shares).await {
                                warn!("[PRESIGN] Failed to pre-sign DOWN SELL: {}", e);
                            }
                        }

                        let new_state = PreLimitOrderState {
                            asset: "BTC".to_string(),
                            condition_id: market.condition_id,
                            up_token_id: up_token_id.clone(),
                            down_token_id: down_token_id.clone(),
                            up_order_id: up_order.order_id,
                            down_order_id: down_order.order_id,
                            up_buy_price: buy_price,
                            down_buy_price: buy_price,
                            up_matched: false,
                            down_matched: false,
                            up_mined: false,
                            down_mined: false,
                            up_shares_received: 0.0,
                            down_shares_received: 0.0,
                            up_spent_usdc: 0.0,
                            down_spent_usdc: 0.0,
                            up_sell_order_id: None,
                            down_sell_order_id: None,
                            expiry: next_period_start,
                            order_placed_at: current_time_et,
                            market_period_start: current_period_et,
                            trade_info: std::collections::HashMap::new(),
                            up_trade_confirmed: false,
                            down_trade_confirmed: false,
                            pending_trades: std::collections::VecDeque::new(),
                            split_tx_hash,
                        };
                        *state_guard = Some(new_state);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle CLOB subscription and send order updates to the strategy
    /// Now also handles Trade events for event-driven SELL order placement
    pub async fn handle_clob_subscription_direct(
        clob_client: Arc<ClobClient>,
        state: Arc<Mutex<Option<PreLimitOrderState>>>,
        api: Arc<PolymarketApi>,
        config: Config,
        shutdown_token: CancellationToken,
    ) -> Result<()> {
        // Subscribe to user events using empty market list for all events
        let markets = Vec::new();

        // Get the authenticated client
        let client = {
            let auth_client = clob_client.ws_client.read().await;
            auth_client
                .clone()
                .ok_or_else(|| anyhow::anyhow!("No authenticated WS client available"))?
        };

        // Subscribe to user events
        let stream = client.subscribe_user_events(markets)?;
        let mut stream = std::pin::pin!(stream);

        info!("CLOB subscription started, listening for order and trade status updates");

        loop {
            tokio::select! {
                Some(event) = stream.next() => {
                    match event {
                        Ok(user_event) => {
                            match user_event {
                                WsMessage::Order(order) => {
                                    info!("Received order update: {:?}", order);

                                    if let Some(order_status) = &order.status {
                                        match order_status {
                                            polymarket_client_sdk_v2::clob::types::OrderStatusType::Matched => {
                                                if let (Some(size_matched), Some(outcome)) = (&order.size_matched, &order.outcome) {
                                                    // size_matched is already the actual shares (e.g., 3.5), NOT raw value
                                                    // Use directly as-is
                                                    let shares: f64 = size_matched.to_string().parse::<f64>().unwrap_or(0.0);
                                                    let outcome_str = outcome.to_lowercase();
                                                    
                                                    // Update matched state (but NOT mined yet - don't place SELL)
                                                    let mut state_guard = state.lock().await;
                                                    if let Some(mut s) = state_guard.clone() {
                                                        let spent_usdc = shares * s.up_buy_price;
                                                        if outcome_str == "up" {
                                                            s.up_matched = true;
                                                            s.up_shares_received = shares;
                                                            s.up_spent_usdc = spent_usdc;
                                                            info!("Order MATCHED: up_matched = true ({} shares, ${:.2} USDC spent). Placing SELL immediately.", shares, spent_usdc);
                                                        } else if outcome_str == "down" {
                                                            s.down_matched = true;
                                                            s.down_shares_received = shares;
                                                            s.down_spent_usdc = spent_usdc;
                                                            info!("Order MATCHED: down_matched = true ({} shares, ${:.2} USDC spent). Placing SELL immediately.", shares, spent_usdc);
                                                        }
                                                        
                                                        // Store trade_id -> (outcome, shares) mapping for correlation
                                                        // Trade events don't have outcome field, use this map to look it up
                                                        if let Some(associate_trades) = &order.associate_trades {
                                                            for trade_id in associate_trades {
                                                                s.trade_info.insert(trade_id.clone(), (outcome_str.clone(), shares));
                                                                info!("Stored trade mapping: {} -> ({}, {})", trade_id, outcome_str, shares);
                                                            }
                                                        }

                                                        // Process pending trades that arrived before this order
                                                        let pending = std::mem::take(&mut s.pending_trades);
                                                        let trade_info = s.trade_info.clone();
                                                        let up_matched = s.up_matched;
                                                        let down_matched = s.down_matched;
                                                        let up_token_id = s.up_token_id.clone();
                                                        let down_token_id = s.down_token_id.clone();
                                                        let up_sell_order_id = s.up_sell_order_id.clone();
                                                        let down_sell_order_id = s.down_sell_order_id.clone();
                                                        let (new_pending, new_up_sell, new_down_sell) = Self::process_pending_trades(
                                                            pending,
                                                            trade_info,
                                                            up_matched,
                                                            down_matched,
                                                            up_token_id,
                                                            down_token_id,
                                                            up_sell_order_id,
                                                            down_sell_order_id,
                                                            api.clone(),
                                                            config.clone(),
                                                        ).await;
                                                        s.pending_trades = new_pending;
                                                        s.up_sell_order_id = new_up_sell;
                                                        s.down_sell_order_id = new_down_sell;

                                                        *state_guard = Some(s);
                                                    }
                                                }
                                            }
                                            _ => {
                                                debug!("Order status: {:?}", order_status);
                                            }
                                        }
                                    }
                                }
                                WsMessage::Trade(trade) => {
                                    info!("Received trade update: id={}, status={:?}, side={:?}, size={}, price={}",
                                        trade.id, trade.status, trade.side, trade.size, trade.price);

                                    // Handle trade status updates for event-driven SELL placement
                                    // Use Trade Matched (链下撮合) instead of Trade Mined (链上确认) to reduce latency
                                    match trade.status {
                                        TradeMessageStatus::Matched => {
                                            // Trade matched on CLOB (链下撮合引擎成交) - immediate trigger
                                            let match_instant = std::time::Instant::now();

                                            // Trade events don't have outcome field - look up via trade_id from trade_info map
                                            let trade_id = &trade.id;
                                            let is_buy = matches!(trade.side, SdkSide::Buy);

                                            // Only process BUY trades that were matched (we bought tokens)
                                            if is_buy {
                                                let mut state_guard = state.lock().await;
                                                if let Some(mut s) = state_guard.clone() {
                                                    // Look up outcome and shares from trade_info map
                                                    let (outcome, shares) = match s.trade_info.get(trade_id) {
                                                        Some((outcome, shares)) => {
                                                            info!("Found mapping: {} -> ({}, {})", trade_id, outcome, shares);
                                                            (outcome.clone(), *shares)
                                                        },
                                                        None => {
                                                            // trade_info not yet populated - add to pending queue
                                                            info!("Trade {} not found in trade_info, adding to pending queue", trade_id);
                                                            s.pending_trades.push_back(crate::models::PendingTrade {
                                                                trade_id: trade_id.clone(),
                                                                side: format!("{:?}", trade.side),
                                                                size: trade.size.to_string().parse().unwrap_or(0.0),
                                                                price: trade.price.to_string().parse().unwrap_or(0.0),
                                                            });
                                                            *state_guard = Some(s);
                                                            continue;
                                                        }
                                                    };

                                                    // Idempotency check: prevent duplicate SELL orders
                                                    let existing_sell = if outcome.to_lowercase() == "up" {
                                                        s.up_sell_order_id.clone()
                                                    } else {
                                                        s.down_sell_order_id.clone()
                                                    };

                                                    if existing_sell.is_some() {
                                                        info!("SELL order already exists for {}, skipping", outcome);
                                                    } else {
                                                        // Place SELL order immediately
                                                        let should_place_sell = outcome.to_lowercase() == "up" && s.up_matched 
                                                            || outcome.to_lowercase() == "down" && s.down_matched;

                                                        // DEBUG: Log should_place_sell condition
                                                        info!("DEBUG: should_place_sell = {} (outcome: {}, up_matched: {}, down_matched: {})", 
                                                            should_place_sell, outcome, s.up_matched, s.down_matched);

                                                        if should_place_sell {
                                                            let side_name = if outcome.to_lowercase() == "up" { "UP" } else { "DOWN" };
                                                            info!("Placing SELL order for {} with {} shares", side_name, shares);

                                                            let token_id = if outcome.to_lowercase() == "up" {
                                                                s.up_token_id.clone()
                                                            } else {
                                                                s.down_token_id.clone()
                                                            };
                                                            let sell_price = config.strategy.sell_price;
                                                            let expire_after = chrono::Utc::now().timestamp() + GTD_DURATION_SECS;

                                                            // P1: Try pre-signed order first, fall back to SDK place_order
                                                            let sell_result = match api.try_post_presigned(&token_id).await {
                                                                Ok(Some(resp)) => {
                                                                    info!("[PRESIGN] Used pre-signed order for {}, ID: {:?}", side_name, resp.order_id);
                                                                    Some(resp)
                                                                }
                                                                Ok(None) => {
                                                                    // No pre-signed order cached, fall through to normal flow
                                                                    let order = OrderRequest {
                                                                        token_id: token_id.clone(),
                                                                        side: "SELL".to_string(),
                                                                        size: shares.to_string(),
                                                                        price: format!("{:.2}", sell_price),
                                                                        order_type: "LIMIT".to_string(),
                                                                        time_in_force: Some("GTD".to_string()),
                                                                        expire_after: Some(expire_after),
                                                                    };
                                                                    api.place_order(&order).await.ok()
                                                                }
                                                                Err(e) => {
                                                                    warn!("[PRESIGN] Pre-signed order failed: {}. Falling back to SDK place_order.", e);
                                                                    let order = OrderRequest {
                                                                        token_id: token_id.clone(),
                                                                        side: "SELL".to_string(),
                                                                        size: shares.to_string(),
                                                                        price: format!("{:.2}", sell_price),
                                                                        order_type: "LIMIT".to_string(),
                                                                        time_in_force: Some("GTD".to_string()),
                                                                        expire_after: Some(expire_after),
                                                                    };
                                                                    api.place_order(&order).await.ok()
                                                                }
                                                            };

                                                            match sell_result {
                                                                Some(sell_order) => {
                                                                    let order_id = sell_order.order_id.unwrap_or_default();
                                                                    if outcome.to_lowercase() == "up" {
                                                                        s.up_sell_order_id = Some(order_id.clone());
                                                                    } else {
                                                                        s.down_sell_order_id = Some(order_id.clone());
                                                                    }
                                                                    let latency_us = match_instant.elapsed().as_micros();
                                                                    info!("[LATENCY] Match→Sell posted for {}: {}μs (order_id={})", side_name, latency_us, order_id);
                                                                    eprintln!("  ⚡ 从撮合到卖单: {}μs ({}ms)", latency_us, latency_us / 1000);
                                                                }
                                                                None => {
                                                                    error!("Failed to place SELL for {} (both pre-signed and fallback failed)", side_name);
                                                                }
                                                            }
                                                        }
                                                    }
                                            
                                            *state_guard = Some(s);
                                        }
                                    }
                                }
                                TradeMessageStatus::Confirmed => {
                                    // Trade confirmed on-chain (链上确认) - for reconciliation only
                                    // Don't place SELL here, it's already placed at Matched
                                    let trade_id = &trade.id;
                                    let is_buy = matches!(trade.side, SdkSide::Buy);
                                    if is_buy {
                                        let mut state_guard = state.lock().await;
                                        if let Some(mut s) = state_guard.clone() {
                                            if let Some((outcome, _)) = s.trade_info.get(trade_id) {
                                                if outcome.to_lowercase() == "up" {
                                                    s.up_trade_confirmed = true;
                                                    info!("Trade {} confirmed on-chain (UP)", trade_id);
                                                } else if outcome.to_lowercase() == "down" {
                                                    s.down_trade_confirmed = true;
                                                    info!("Trade {} confirmed on-chain (DOWN)", trade_id);
                                                }
                                            }
                                            *state_guard = Some(s);
                                        }
                                    }
                                }
                                TradeMessageStatus::Mined => {
                                    // Legacy: log only, SELL is placed at Matched now
                                    info!("Trade {} mined (链上确认Legacy - SELL already placed at Matched)", trade.id);
                                }
                                _ => {
                                    debug!("Trade {} has unknown status: {:?}", trade.id, trade.status);
                                }
                            }
                        }
                        _ => {
                            debug!("Received other user event");
                        }
                            }
                        }
                        Err(e) => {
                            error!("Error receiving user event: {}", e);
                        }
                    }
                }
                _ = shutdown_token.cancelled() => {
                    info!("Shutdown signal received, stopping CLOB subscription");
                    break;
                }
            }
        }

        info!("CLOB subscription ended");
        Ok(())
    }

    fn get_current_5m_period_et() -> i64 {
        MarketDiscovery::current_5m_period_start_et()
    }

    fn get_current_time_et() -> i64 {
        let now_utc = Utc::now();
        let now_et = now_utc.with_timezone(&New_York);
        now_et.timestamp()
    }

    async fn discover_market(&self, asset_name: &str, period_start: i64) -> Result<Option<Market>> {
        let slug = MarketDiscovery::build_5m_slug(asset_name, period_start);
        match self.api.get_market_by_slug(&slug).await {
            Ok(m) => {
                if m.active && !m.closed {
                    Ok(Some(m))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("Failed to find market with slug {}: {}", slug, e);
                Ok(None)
            }
        }
    }

    pub async fn check_market_closure(&self) -> Result<()> {
        let trades: Vec<(String, CycleTrade)> = {
            let t = self.trades.lock().await;
            t.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        if trades.is_empty() {
            return Ok(());
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for (market_key, trade) in trades {
            let market_end = trade.period_timestamp + trade.market_duration_secs;
            if current_time < market_end {
                continue;
            }

            let checked = self.closure_checked.lock().await;
            if checked.get(&trade.condition_id).copied().unwrap_or(false) {
                drop(checked);
                continue;
            }
            drop(checked);

            let market = match self.api.get_market(&trade.condition_id).await {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "Failed to fetch market {}: {}",
                        &trade.condition_id[..16],
                        e
                    );
                    continue;
                }
            };
            if !market.closed {
                continue;
            }

            let up_wins = trade
                .up_token_id
                .as_ref()
                .map(|id| market.tokens.iter().any(|t| t.token_id == *id && t.winner))
                .unwrap_or(false);
            let down_wins = trade
                .down_token_id
                .as_ref()
                .map(|id| market.tokens.iter().any(|t| t.token_id == *id && t.winner))
                .unwrap_or(false);

            let total_cost =
                (trade.up_shares * trade.up_avg_price) + (trade.down_shares * trade.down_avg_price);
            let payout = if up_wins {
                trade.up_shares * 1.0
            } else if down_wins {
                trade.down_shares * 1.0
            } else {
                0.0
            };
            let pnl = payout - total_cost;

            let winner = if up_wins {
                "Up"
            } else if down_wins {
                "Down"
            } else {
                "Unknown"
            };
            let sim_prefix = if self.config.strategy.simulation_mode {
                "SIMULATION: "
            } else {
                ""
            };
            eprintln!("=== Market resolved {}===", sim_prefix);
            eprintln!(
                "{}Market closed | condition {} | Winner: {} | Up {:.2} @ {:.4} | Down {:.2} @ {:.4} | Cost ${:.2} | Payout ${:.2} | PnL ${:.2}",
                sim_prefix,
                &trade.condition_id[..16],
                winner,
                trade.up_shares,
                trade.up_avg_price,
                trade.down_shares,
                trade.down_avg_price,
                total_cost,
                payout,
                pnl
            );

            if !self.config.strategy.simulation_mode && (up_wins || down_wins) {
                let (token_id, outcome) = if up_wins && trade.up_shares > 0.001 {
                    (trade.up_token_id.as_deref().unwrap_or(""), "Up")
                } else {
                    (trade.down_token_id.as_deref().unwrap_or(""), "Down")
                };
                if let Err(e) = self
                    .api
                    .redeem_tokens(&trade.condition_id, token_id, outcome)
                    .await
                {
                    warn!("Redeem failed: {}", e);
                }
            }

            {
                let mut total = self.total_profit.lock().await;
                *total += pnl;
            }
            let total_actual_pnl = *self.total_profit.lock().await;
            eprintln!(
                "  -> {}PnL this market: ${:.2} | Total PnL: ${:.2}",
                sim_prefix, pnl, total_actual_pnl
            );
            {
                let mut c = self.closure_checked.lock().await;
                c.insert(trade.condition_id.clone(), true);
            }
            let mut t = self.trades.lock().await;
            t.remove(&market_key);
        }
        Ok(())
    }

    async fn place_limit_order(
        &self,
        token_id: &str,
        side: &str,
        price: f64,
    ) -> Result<OrderResponse> {
        let price = Self::round_price(price);
        let expire_after = chrono::Utc::now().timestamp() + GTD_DURATION_SECS;
        
        if self.config.strategy.simulation_mode {
            info!(
                "SIMULATION: Would place {} order for token {}: {} shares @ ${:.2} (GTD: {} seconds)",
                side, token_id, self.config.strategy.shares, price, GTD_DURATION_SECS
            );

            let fake_order_id = format!("SIM-{}-{}", side, chrono::Utc::now().timestamp());

            Ok(OrderResponse {
                order_id: Some(fake_order_id),
                status: "SIMULATED".to_string(),
                message: Some("Order simulated".to_string()),
            })
        } else {
            let order = OrderRequest {
                token_id: token_id.to_string(),
                side: side.to_string(),
                size: self.config.strategy.shares.to_string(),
                price: price.to_string(),
                order_type: "LIMIT".to_string(),
                time_in_force: Some("GTD".to_string()),
                expire_after: Some(expire_after),
            };
            self.api.place_order(&order).await
        }
    }

    /// Place a marketable BUY order that fills immediately by crossing the spread.
    /// Uses price=0.99 to ensure it matches the best available ask (~$0.50 for new markets).
    async fn place_market_order(
        &self,
        token_id: &str,
        side: &str,
    ) -> Result<OrderResponse> {
        let shares = self.config.strategy.shares;

        if self.config.strategy.simulation_mode {
            info!(
                "SIMULATION: Would place {} market order for token {}: {} shares",
                side, token_id, shares
            );
            let fake_order_id = format!("SIM-MARKET-{}-{}", side, chrono::Utc::now().timestamp());
            return Ok(OrderResponse {
                order_id: Some(fake_order_id),
                status: "SIMULATED".to_string(),
                message: Some("Market order simulated".to_string()),
            });
        }

        let order = OrderRequest {
            token_id: token_id.to_string(),
            side: side.to_string(),
            size: shares.to_string(),
            price: "0.99".to_string(),
            order_type: "MARKET".to_string(),
            time_in_force: None,
            expire_after: None,
        };
        self.api.place_order(&order).await
    }

    async fn check_buy_order_matches(&self, state: &mut PreLimitOrderState) -> Result<()> {
        if state.up_matched && state.down_matched {
            return Ok(());
        }

        if !self.config.strategy.simulation_mode {
            if let (Some(up_id), Some(down_id)) = (&state.up_order_id, &state.down_order_id) {
                if !up_id.starts_with("SIM-") && !down_id.starts_with("SIM-") {
                    match self.api.are_both_orders_filled(up_id, down_id).await {
                        Ok((up_filled, down_filled)) => {
                            if up_filled && !state.up_matched {
                                info!("Up buy order filled for BTC (verified via API)");
                                state.up_matched = true;
                            }
                            if down_filled && !state.down_matched {
                                info!("Down buy order filled for BTC (verified via API)");
                                state.down_matched = true;
                            }
                        }
                        Err(e) => {
                            debug!(
                                "API fill check failed, falling back to price inference: {}",
                                e
                            );
                        }
                    }
                }
            }
        }

        let buy_price = self.config.strategy.buy_price;

        if !state.up_matched {
            if let Ok(up_price) = self.api.get_price(&state.up_token_id, "SELL").await {
                let up_price_f64: f64 = up_price.to_string().parse().unwrap_or(0.0);
                if up_price_f64 <= buy_price || (up_price_f64 - buy_price).abs() < 0.001 {
                    info!(
                        "Up buy order matched for BTC (price ${:.4} <= ${:.2})",
                        up_price_f64, buy_price
                    );
                    state.up_matched = true;
                }
            }
        }

        if !state.down_matched {
            if let Ok(down_price) = self.api.get_price(&state.down_token_id, "SELL").await {
                let down_price_f64: f64 = down_price.to_string().parse().unwrap_or(0.0);
                if down_price_f64 <= buy_price || (down_price_f64 - buy_price).abs() < 0.001 {
                    info!(
                        "Down buy order matched for BTC (price ${:.4} <= ${:.2})",
                        down_price_f64, buy_price
                    );
                    state.down_matched = true;
                }
            }
        }

        Ok(())
    }

    fn round_price(price: f64) -> f64 {
        let rounded = (price * 100.0).round() / 100.0;
        rounded.clamp(0.01, 99.0)
    }

    fn cycle_trade_from_state(s: &PreLimitOrderState, shares: f64) -> CycleTrade {
        // Use actual shares received if available, otherwise fall back to config shares
        let up_shares = if s.up_shares_received > 0.0 {
            s.up_shares_received
        } else if s.up_mined {
            shares
        } else {
            0.0
        };
        let down_shares = if s.down_shares_received > 0.0 {
            s.down_shares_received
        } else if s.down_mined {
            shares
        } else {
            0.0
        };

        CycleTrade {
            condition_id: s.condition_id.clone(),
            period_timestamp: s.market_period_start as u64,
            market_duration_secs: MARKET_DURATION_SECS_U64,
            up_token_id: Some(s.up_token_id.clone()),
            down_token_id: Some(s.down_token_id.clone()),
            up_shares,
            down_shares,
            up_avg_price: s.up_buy_price,
            down_avg_price: s.down_buy_price,
            split_tx_hash: s.split_tx_hash.clone(),
        }
    }

    async fn process_pending_trades(
        mut pending_trades: std::collections::VecDeque<crate::models::PendingTrade>,
        trade_info: std::collections::HashMap<String, (String, f64)>,
        up_matched: bool,
        down_matched: bool,
        up_token_id: String,
        down_token_id: String,
        mut up_sell_order_id: Option<String>,
        mut down_sell_order_id: Option<String>,
        api: Arc<PolymarketApi>,
        config: Config,
    ) -> (std::collections::VecDeque<crate::models::PendingTrade>, Option<String>, Option<String>) {
        let mut remaining = std::collections::VecDeque::new();

        while let Some(pending) = pending_trades.pop_front() {
            if let Some((outcome, shares)) = trade_info.get(&pending.trade_id) {
                let outcome = outcome.clone();
                let shares = *shares;

                info!("Processing pending trade: {} -> ({}, {})", pending.trade_id, outcome, shares);

                let existing_sell = if outcome.to_lowercase() == "up" {
                    up_sell_order_id.clone()
                } else {
                    down_sell_order_id.clone()
                };

                if existing_sell.is_some() {
                    info!("SELL order already exists for {}, skipping", outcome);
                    continue;
                }

                let should_place_sell = outcome.to_lowercase() == "up" && up_matched
                    || outcome.to_lowercase() == "down" && down_matched;

                if should_place_sell {
                    let side_name = if outcome.to_lowercase() == "up" { "UP" } else { "DOWN" };
                    let pending_instant = std::time::Instant::now();
                    let token_id = if outcome.to_lowercase() == "up" {
                        up_token_id.clone()
                    } else {
                        down_token_id.clone()
                    };
                    let sell_price = config.strategy.sell_price;
                    info!("Placing SELL order for pending trade {} with {} shares", side_name, shares);
                    let expire_after = chrono::Utc::now().timestamp() + GTD_DURATION_SECS;

                    // P1: Try pre-signed order first, fall back to SDK place_order
                    let sell_result = match api.try_post_presigned(&token_id).await {
                        Ok(Some(resp)) => {
                            info!("[PRESIGN] Used pre-signed order for {} (pending trade), ID: {:?}", side_name, resp.order_id);
                            Some(resp)
                        }
                        Ok(None) => {
                            let order = OrderRequest {
                                token_id: token_id.clone(),
                                side: "SELL".to_string(),
                                size: shares.to_string(),
                                price: format!("{:.2}", sell_price),
                                order_type: "LIMIT".to_string(),
                                time_in_force: Some("GTD".to_string()),
                                expire_after: Some(expire_after),
                            };
                            api.place_order(&order).await.ok()
                        }
                        Err(e) => {
                            warn!("[PRESIGN] Pre-signed order failed (pending trade): {}. Falling back.", e);
                            let order = OrderRequest {
                                token_id: token_id.clone(),
                                side: "SELL".to_string(),
                                size: shares.to_string(),
                                price: format!("{:.2}", sell_price),
                                order_type: "LIMIT".to_string(),
                                time_in_force: Some("GTD".to_string()),
                                expire_after: Some(expire_after),
                            };
                            api.place_order(&order).await.ok()
                        }
                    };

                    if let Some(sell_order) = sell_result {
                        let order_id = sell_order.order_id.unwrap_or_default();
                        if outcome.to_lowercase() == "up" {
                            up_sell_order_id = Some(order_id.clone());
                        } else {
                            down_sell_order_id = Some(order_id.clone());
                        }
                        let latency_us = pending_instant.elapsed().as_micros();
                        info!("SELL order placed for {}: order_id={}", side_name, order_id);
                        info!("[LATENCY] Pending-trade→Sell for {}: {}μs ({}ms)", side_name, latency_us, latency_us / 1000);
                    } else {
                        error!("Failed to place SELL for {} (both pre-signed and fallback failed)", side_name);
                    }
                }
            } else {
                remaining.push_back(pending);
            }
        }

        (remaining, up_sell_order_id, down_sell_order_id)
    }
}
