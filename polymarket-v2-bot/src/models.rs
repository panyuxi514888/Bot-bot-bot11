use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Market {
    #[serde(rename = "conditionId")]
    pub condition_id: String,
    #[serde(rename = "id")]
    pub market_id: Option<String>,
    pub question: String,
    pub slug: String,
    #[serde(rename = "endDateISO")]
    pub end_date_iso: Option<String>,
    pub active: bool,
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketDetails {
    #[serde(rename = "condition_id")]
    pub condition_id: String,
    pub question: String,
    pub tokens: Vec<MarketToken>,
    pub active: bool,
    pub closed: bool,
    #[serde(rename = "end_date_iso")]
    pub end_date_iso: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketToken {
    pub outcome: String,
    #[serde(rename = "token_id")]
    pub token_id: String,
    pub winner: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderRequest {
    pub token_id: String,
    pub side: String,
    pub size: String,
    pub price: String,
    #[serde(rename = "type")]
    pub order_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_in_force: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_after: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderResponse {
    pub order_id: Option<String>,
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OpenOrder {
    #[serde(rename = "orderID")]
    pub order_id: String,
    #[serde(rename = "market")]
    pub market: Option<String>,
    #[serde(rename = "side")]
    pub side: String,
    #[serde(rename = "size")]
    pub size: String,
    #[serde(rename = "price")]
    pub price: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "fillSize")]
    pub fill_size: Option<String>,
    #[serde(rename = "avgFillPrice")]
    pub avg_fill_price: Option<String>,
    #[serde(rename = "tokenID")]
    pub token_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct RedeemResponse {
    pub success: bool,
    pub message: Option<String>,
    pub transaction_hash: Option<String>,
    pub amount_redeemed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PreLimitOrderState {
    pub asset: String,
    pub condition_id: String,
    pub up_token_id: String,
    pub down_token_id: String,
    pub up_order_id: Option<String>,
    pub down_order_id: Option<String>,
    pub up_buy_price: f64,
    pub down_buy_price: f64,
    pub up_matched: bool,
    pub down_matched: bool,
    pub up_mined: bool,
    pub down_mined: bool,
    pub up_shares_received: f64,
    pub down_shares_received: f64,
    pub up_spent_usdc: f64,
    pub down_spent_usdc: f64,
    pub up_sell_order_id: Option<String>,
    pub down_sell_order_id: Option<String>,
    pub expiry: i64,
    pub order_placed_at: i64,
    pub market_period_start: i64,
    pub trade_info: std::collections::HashMap<String, (String, f64)>,
    pub up_trade_confirmed: bool,
    pub down_trade_confirmed: bool,
    pub pending_trades: std::collections::VecDeque<PendingTrade>,
    pub split_tx_hash: Option<String>,
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

#[derive(Debug, Clone)]
pub struct PendingTrade {
    pub trade_id: String,
    pub side: String,
    pub size: f64,
    pub price: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Fill {
    #[serde(rename = "tokenID")]
    pub token_id: Option<String>,
    pub side: String,
    pub size: f64,
    pub price: f64,
    pub timestamp: u64,
    #[serde(rename = "conditionId")]
    pub condition_id: Option<String>,
}

// P1: Pending merge for async background task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMerge {
    pub condition_id: String,
    pub amount: f64,
    pub created_at: i64,
    pub status: MergeStatus,
    pub last_error: Option<String>,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MergeStatus {
    Pending,
    InProgress,
    Succeeded(String), // tx hash
    Failed(String),    // error
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeablePosition {
    pub condition_id: String,
    pub size: f64,
    pub title: String,
}
