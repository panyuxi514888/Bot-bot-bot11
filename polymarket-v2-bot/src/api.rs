use crate::models::*;
use anyhow::{Context, Result};
use log::{error, info, warn};
use reqwest::Client as ReqwestClient;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::dyn_abi::Eip712Domain;
use alloy::hex::ToHexExt;
use alloy::sol_types::{SolStruct, SolValue};
use alloy_sol_types::{sol, SolCall};
use reqwest::header::{HeaderMap, HeaderValue};
use uuid::Uuid;

// L2 HMAC auth
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE as BASE64_URL_SAFE;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use polymarket_client_sdk_v2::auth::ExposeSecret;
use polymarket_client_sdk_v2::clob::types::{
    OrderType, Side, OrderStatusType, SignatureType, OrderPayload,
};
use polymarket_client_sdk_v2::clob::types::request::{OrdersRequest, PriceRequest};
use polymarket_client_sdk_v2::clob::types::response::PostOrderResponse;
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

    /// EIP-712 struct for Polymarket L1 auth (ClobAuthDomain)
    #[allow(missing_docs)]
    struct ClobAuth {
        address address;
        string  timestamp;
        uint256 nonce;
        string  message;
    }

    /// SafeTx — the EIP-712 typed struct that Safe wallets use for relayer signing.
    #[allow(missing_docs)]
    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        uint8 operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address refundReceiver;
        uint256 nonce;
    }
}

/// Credentials needed for L2 HMAC request signing.
#[derive(Clone)]
pub struct L2Credentials {
    pub address: String,
    pub api_key: String,
    pub api_secret: String,
    pub api_passphrase: String,
}

/// Cache for pre-signed order JSON bodies, keyed by token_id.
pub type PresignCache = HashMap<String, Vec<u8>>;

/// Helper struct to deserialize Polymarket API key creation/derivation response.
#[derive(serde::Deserialize)]
struct ApiKeyResponse {
    #[serde(alias = "apiKey")]
    key: Uuid,
    secret: String,
    passphrase: String,
}

/// Generate L1 auth headers with `POLY_ADDRESS` set to `funder` (proxy wallet)
/// instead of the EOA address. This binds the API key to the proxy wallet so
/// that orders using the proxy wallet as `maker` pass the server's permission check.
async fn create_funder_l1_headers(
    signer: &PrivateKeySigner,
    funder: Address,
    chain_id: u64,
    timestamp: i64,
    nonce: Option<u32>,
) -> Result<HeaderMap> {
    let naive_nonce = nonce.unwrap_or(0);

    let auth = ClobAuth {
        address: funder,
        timestamp: timestamp.to_string(),
        nonce: U256::from(naive_nonce),
        message: "This message attests that I control the given wallet".to_owned(),
    };

    let domain = Eip712Domain {
        name: Some(std::borrow::Cow::Borrowed("ClobAuthDomain")),
        version: Some(std::borrow::Cow::Borrowed("1")),
        chain_id: Some(U256::from(chain_id)),
        ..Eip712Domain::default()
    };

    let hash = auth.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&hash).await?;

    let mut map = HeaderMap::new();
    map.insert(
        "POLY_ADDRESS",
        funder.encode_hex_with_prefix().parse().map_err(|e| {
            anyhow::anyhow!("Failed to parse POLY_ADDRESS header: {}", e)
        })?,
    );
    map.insert(
        "POLY_NONCE",
        naive_nonce.to_string().parse().map_err(|e| {
            anyhow::anyhow!("Failed to parse POLY_NONCE header: {}", e)
        })?,
    );
    map.insert(
        "POLY_SIGNATURE",
        signature.to_string().parse().map_err(|e| {
            anyhow::anyhow!("Failed to parse POLY_SIGNATURE header: {}", e)
        })?,
    );
    map.insert(
        "POLY_TIMESTAMP",
        timestamp.to_string().parse().map_err(|e| {
            anyhow::anyhow!("Failed to parse POLY_TIMESTAMP header: {}", e)
        })?,
    );

    Ok(map)
}

pub struct PolymarketApi {
    client: ReqwestClient,
    gamma_url: String,
    clob_url: String,
    private_key: Option<String>,
    safe_addr_address: Option<String>,
    signature_type: Option<u8>,
    rpc_url: Option<String>,
    use_relayer: bool,
    relayer_api_key: Option<String>,
    relayer_api_key_address: Option<String>,
    authenticated_clob: Arc<tokio::sync::RwLock<Option<AuthClobClient>>>,
    signer: Arc<tokio::sync::RwLock<Option<PrivateKeySigner>>>,
    // P0+P1: pre-signed order support
    pub l2_credentials: tokio::sync::RwLock<Option<L2Credentials>>,
    pub presign_cache: tokio::sync::Mutex<PresignCache>,
    warmed_up: AtomicBool,
}

impl PolymarketApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gamma_url: String,
        clob_url: String,
        private_key: Option<String>,
        safe_addr_address: Option<String>,
        signature_type: Option<u8>,
        rpc_url: Option<String>,
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
            private_key,
            safe_addr_address,
            signature_type,
            rpc_url,
            use_relayer,
            relayer_api_key,
            relayer_api_key_address,
            authenticated_clob: Arc::new(tokio::sync::RwLock::new(None)),
            signer: Arc::new(tokio::sync::RwLock::new(None)),
            l2_credentials: tokio::sync::RwLock::new(None),
            presign_cache: tokio::sync::Mutex::new(HashMap::new()),
            warmed_up: AtomicBool::new(false),
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
        let funder = match &self.safe_addr_address {
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

        // Follow the SDK example pattern: authentication_builder with
        // funder + Poly1271. The SDK internally calls create_or_derive_api_key
        // during authenticate() to get fresh credentials bound to the EOA,
        // then sets the funder and signature_type on the inner client.
        let config = ClobConfig::builder().use_server_time(true).build();
        let mut auth_builder = ClobClient::new(&self.clob_url, config)?
            .authentication_builder(&signer);

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

        // Extract L2 credentials for pre-signed order posting
        if let Some(ref clob) = *guard {
            let addr = clob.address().to_checksum(None);
            let key = clob.credentials().key().to_string();
            let secret = clob.credentials().secret().expose_secret().to_string();
            let passphrase = clob.credentials().passphrase().expose_secret().to_string();
            let mut cred_guard = self.l2_credentials.write().await;
            *cred_guard = Some(L2Credentials {
                address: addr,
                api_key: key,
                api_secret: secret,
                api_passphrase: passphrase,
            });
            info!("L2 credentials extracted for pre-signed order support");
        }

        let mut signer_guard = self.signer.write().await;
        *signer_guard = Some(signer);

        eprintln!("   ✓ Successfully authenticated with Polymarket CLOB V2 API");
        eprintln!("   ✓ Signer address: {:?}", address);
        if let Some(proxy_addr) = &self.safe_addr_address {
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

    // ── P0: HTTP connection + SDK cache warmup ──

    /// Warm up HTTP connection and SDK caches. Call once after authenticate().
    pub async fn warmup(&self) -> Result<()> {
        if self.warmed_up.load(Ordering::SeqCst) {
            return Ok(());
        }
        let ts_url = format!("{}time", self.clob_url);
        let _ = self.client.get(&ts_url).send().await?;
        info!("[WARMUP] HTTP connection warmed via GET /time");
        // Warm SDK version cache via a light authenticated call
        if let Some(ref clob) = *self.authenticated_clob.read().await {
            let _ = clob.server_time().await?;
            info!("[WARMUP] SDK server-time cache warmed");
        }
        self.warmed_up.store(true, Ordering::SeqCst);
        Ok(())
    }

    // ── P1: Pre-signed order support ──

    /// Build + sign a SELL limit order (GTD 360s) and cache its serialized JSON.
    pub async fn presign_order(&self, token_id: &str, price: f64, size: f64) -> Result<()> {
        let clob = self.get_clob_client().await?;
        let signer = self.get_signer().await?;

        let tid = U256::from_str(token_id)
            .context(format!("Invalid token_id: {}", token_id))?;
        let price_dec = Decimal::from_str(&format!("{:.2}", price))
            .context("Invalid price")?;
        let size_dec = Decimal::from_str(&format!("{:.2}", size))
            .context("Invalid size")?;

        let expiration = chrono::Utc::now() + chrono::Duration::seconds(360);

        let signable = clob
            .limit_order()
            .token_id(tid)
            .size(size_dec)
            .price(price_dec)
            .side(Side::Sell)
            .order_type(OrderType::GTD)
            .expiration(expiration)
            .build()
            .await?;

        let signed = clob.sign(&signer, signable).await?;
        let json_bytes = serde_json::to_vec(&signed)?;

        let mut cache = self.presign_cache.lock().await;
        cache.insert(token_id.to_string(), json_bytes);
        info!("[PRESIGN] Cached SELL order for token {}", token_id);
        Ok(())
    }

    /// Low-level: POST JSON bytes to /order with fresh L2 HMAC headers.
    /// Returns the raw HTTP status code and response body text.
    async fn post_presigned_body(&self, body: Vec<u8>) -> Result<(u16, String)> {
        let creds = self
            .l2_credentials
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("L2 credentials not available"))?;

        let url = format!("{}/order", self.clob_url.trim_end_matches('/'));
        let body_str = std::str::from_utf8(&body)
            .context("Pre-signed order is not valid UTF-8")?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Clock error: {}", e))?
            .as_secs() as i64;

        // ---- L2 HMAC computation (same algorithm as SDK auth::l2) ----
        let message = format!("{}POST/order{}", timestamp, body_str);
        let decoded_secret = BASE64_URL_SAFE
            .decode(&creds.api_secret)
            .context("Failed to base64-decode API secret")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&decoded_secret)?;
        mac.update(message.as_bytes());
        let signature = BASE64_URL_SAFE.encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("POLY_ADDRESS", HeaderValue::from_str(&creds.address)?);
        headers.insert("POLY_API_KEY", HeaderValue::from_str(&creds.api_key)?);
        headers.insert(
            "POLY_PASSPHRASE",
            HeaderValue::from_str(&creds.api_passphrase)?,
        );
        headers.insert("POLY_SIGNATURE", HeaderValue::from_str(&signature)?);
        headers.insert(
            "POLY_TIMESTAMP",
            HeaderValue::from_str(&timestamp.to_string())?,
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .context("Failed to send pre-signed order")?;

        let status_code = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Ok((status_code.as_u16(), text))
    }

    /// Post a previously pre-signed order via L2 HMAC auth.
    /// Removes the cached entry afterwards (one-shot).
    /// Returns `None` when no pre-signed order exists for this token_id.
    pub async fn try_post_presigned(&self, token_id: &str) -> Result<Option<OrderResponse>> {
        let json_bytes = {
            let mut cache = self.presign_cache.lock().await;
            cache.remove(token_id)
        };
        let body = match json_bytes {
            Some(b) => b,
            None => return Ok(None),
        };

        let (status_code, text) = self.post_presigned_body(body).await?;

        if status_code >= 400 {
            anyhow::bail!(
                "Pre-signed order rejected ({}): {}",
                status_code,
                text
            );
        }

        let post_resp: PostOrderResponse = serde_json::from_str(&text)
            .context("Failed to parse order response")?;

        if !post_resp.success {
            let msg = post_resp
                .error_msg
                .as_deref()
                .unwrap_or("Unknown error");
            anyhow::bail!("Pre-signed order rejected: {}", msg);
        }

        info!(
            "[PRESIGN] Order posted! ID: {}",
            post_resp.order_id
        );
        Ok(Some(OrderResponse {
            order_id: Some(post_resp.order_id.clone()),
            status: post_resp.status.to_string(),
            message: Some(format!("Order ID: {}", post_resp.order_id)),
        }))
    }

    pub async fn clear_presign_cache(&self) {
        let mut cache = self.presign_cache.lock().await;
        cache.clear();
    }

    /// Test pre-signed order with deliberately old timestamp (10 minutes in the past).
    /// Builds + signs and posts with fresh L2 HMAC headers to check server acceptance.
    pub async fn test_presigned_order(
        &self,
        token_id: &str,
        side: Side,
        price: f64,
        size: f64,
    ) -> Result<String> {
        let clob = self.get_clob_client().await?;
        let signer = self.get_signer().await?;

        let tid = U256::from_str(token_id)
            .context(format!("Invalid token_id: {}", token_id))?;
        let price_dec = Decimal::from_str(&format!("{:.2}", price))
            .context("Invalid price")?;
        let size_dec = Decimal::from_str(&format!("{:.2}", size))
            .context("Invalid size")?;

        let expiration = chrono::Utc::now() + chrono::Duration::seconds(360);

        let mut signable = clob
            .limit_order()
            .token_id(tid)
            .size(size_dec)
            .price(price_dec)
            .side(side)
            .order_type(OrderType::GTD)
            .expiration(expiration)
            .build()
            .await?;

        // Override timestamp to 10 minutes ago to test server tolerance
        let old_timestamp_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            .saturating_sub(600_000);

        if let OrderPayload::V2(ref mut v2) = signable.payload {
            v2.order.timestamp = U256::from(old_timestamp_ms);
            info!(
                "[TEST-PRESIGN] Set order timestamp to {} ({} ms ago)",
                old_timestamp_ms, 600_000u64
            );
        }

        let signed = clob.sign(&signer, signable).await?;
        let json_bytes = serde_json::to_vec(&signed)?;

        info!(
            "[TEST-PRESIGN] Signed order JSON ({} bytes), posting with old timestamp...",
            json_bytes.len()
        );
        eprintln!(
            "Sending pre-signed {} order: {} shares @ ${:.2} (10-min-old timestamp)",
            if side == Side::Buy { "BUY" } else { "SELL" },
            size,
            price,
        );

        let (status_code, response_text) = self.post_presigned_body(json_bytes).await?;

        eprintln!("Server response: HTTP {} — {}", status_code, response_text);
        info!("[TEST-PRESIGN] HTTP {} — {}", status_code, response_text);
        Ok(format!("HTTP {} — {}", status_code, response_text))
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
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required for Relayer {}", label))?;
        let relayer_key = self.relayer_api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("relayer_api_key required"))?;
        let relayer_key_addr = self.relayer_api_key_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("relayer_api_key_address required"))?;
        let signer = PrivateKeySigner::from_str(private_key)
            .context("Invalid private key")?;
        let eoa = signer.address();

        // Derive Safe address from EOA (same as deploy_safe.rs / test_split.rs)
        const FACTORY_ADDR: &str = "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b";
        const SAFE_INIT_CODE_HASH: &str =
            "2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf";
        let factory: Address = Address::from_str(FACTORY_ADDR)?;
        let salt = keccak256((eoa,).abi_encode());
        let code_hash = B256::from_str(SAFE_INIT_CODE_HASH)?;
        let safe_addr = factory.create2(salt, code_hash);

        let ctf_exchange: Address = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045".parse()?;

        let client = reqwest::Client::new();
        let base_url = "https://relayer-v2.polymarket.com";

        // Build relayer auth headers manually (polyoxide-relay's HeaderMap uses http 1.x
        // which is incompatible with reqwest 0.11's http 0.2.x HeaderMap).
        fn auth_headers(k: &str, a: &str) -> reqwest::header::HeaderMap {
            let mut h = reqwest::header::HeaderMap::new();
            h.insert(
                reqwest::header::HeaderName::from_static("relayer_api_key"),
                reqwest::header::HeaderValue::from_str(k).expect("RELAYER_API_KEY"),
            );
            h.insert(
                reqwest::header::HeaderName::from_static("relayer_api_key_address"),
                reqwest::header::HeaderValue::from_str(a).expect("RELAYER_API_KEY_ADDRESS"),
            );
            h
        }

        let content_type = reqwest::header::HeaderValue::from_static("application/json");

        // 1 — Fetch nonce from the Safe contract on-chain
        let rpc_url = self.get_rpc_url();
        let nonce_data = "0xaffed0e0"; // keccak256("nonce()") first 4 bytes
        let nonce_params = serde_json::json!([{"to": format!("{:#x}", safe_addr), "data": nonce_data}, "latest"]);
        let nonce_body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": nonce_params});

        let nonce_resp: serde_json::Value = client
            .post(&rpc_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&nonce_body)
            .send()
            .await
            .context("Failed to query on-chain nonce")?
            .json()
            .await
            .context("Failed to parse nonce response")?;

        let nonce_hex = nonce_resp["result"].as_str()
            .ok_or_else(|| anyhow::anyhow!("eth_call nonce failed: {:?}", nonce_resp))?;
        let nonce_bytes = alloy::hex::decode(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex))
            .context("Failed to decode nonce hex")?;
        let nonce = U256::from_be_slice(&nonce_bytes).to::<u64>();

        log::info!("[RELAYER] {} nonce={}", label, nonce);

        // 2 — Build SafeTx and sign with EIP-712 (verifyingContract = safe_addr)

        // Build hex strings before moving calldata
        let data_hex = format!("0x{}", alloy::hex::encode(&calldata));

        let safe_tx = SafeTx {
            to: ctf_exchange,
            value: U256::ZERO,
            data: Bytes::from(calldata),  // move
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::from(nonce),
        };

        let domain = Eip712Domain {
            name: None,
            version: None,
            chain_id: Some(U256::from(137u64)),
            verifying_contract: Some(safe_addr),
            salt: None,
        };

        let struct_hash = safe_tx.eip712_signing_hash(&domain);
        let sig = signer.sign_message(struct_hash.as_slice()).await?;

        // Pack signature: r (32) + s (32) + v (y_parity + 31, for Safe format)
        let v_byte = if sig.v() { 1u8 } else { 0u8 } + 31;
        let mut packed = Vec::with_capacity(65);
        packed.extend_from_slice(&sig.r().to_be_bytes::<32>());
        packed.extend_from_slice(&sig.s().to_be_bytes::<32>());
        packed.push(v_byte);
        let sig_hex = format!("0x{}", alloy::hex::encode(&packed));
        let zero_addr = format!("{:#x}", Address::ZERO);
        let body = serde_json::json!({
            "type": "SAFE",
            "from": format!("{:#x}", eoa),
            "to": format!("{:#x}", ctf_exchange),
            "proxyWallet": format!("{:#x}", safe_addr),
            "data": data_hex,
            "signature": sig_hex,
            "signatureParams": {
                "gasPrice": "0",
                "operation": "0",
                "safeTxnGas": "0",
                "baseGas": "0",
                "gasToken": zero_addr,
                "refundReceiver": zero_addr
            },
            "value": "0",
            "nonce": nonce.to_string(),
        });

        log::debug!("[RELAYER] {} body: {:?}", label, body);

        // 4 — POST to /submit with relayer API key auth
        let submit_resp = client.post(format!("{}/submit", base_url))
            .headers(auth_headers(relayer_key, relayer_key_addr))
            .header(reqwest::header::CONTENT_TYPE, content_type.clone())
            .json(&body)
            .send()
            .await
            .context("Failed to POST to relayer /submit")?;

        let status = submit_resp.status();
        if !status.is_success() {
            let text = submit_resp.text().await.unwrap_or_default();
            anyhow::bail!("Relayer submit failed ({}): {}", status, text);
        }

        let submit_body: serde_json::Value = submit_resp.json().await
            .context("Failed to parse /submit response")?;
        let tx_id = submit_body["transactionID"].as_str()
            .ok_or_else(|| anyhow::anyhow!("No transactionID in /submit response: {:?}", submit_body))?
            .to_string();
        let state = submit_body["state"].as_str().unwrap_or("unknown");

        log::info!("[RELAYER] {} submitted. ID: {}, state: {}", label, tx_id, state);

        // 5 — Poll for confirmation via GET /transaction?id={tx_id}
        let max_polls = 30u32;
        for i in 0..max_polls {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            let tx_url = format!("{}/transaction?id={}", base_url, tx_id);

            let poll_resp = client.get(&tx_url)
                .headers(auth_headers(relayer_key, relayer_key_addr))
                .send()
                .await
                .context("Failed to poll transaction")?;

            if !poll_resp.status().is_success() {
                log::warn!("[RELAYER] Poll failed: {} (retrying)", poll_resp.status());
                continue;
            }

            let tx_data: serde_json::Value = poll_resp.json().await
                .context("Failed to parse poll response")?;
            let poll_state = tx_data["state"].as_str().unwrap_or("unknown");

            log::debug!("[RELAYER] {} poll {}/{} -- state: {}", label, i + 1, max_polls, poll_state);

            if poll_state == "STATE_CONFIRMED" || poll_state == "STATE_MINED" {
                if let Some(tx_hash) = tx_data["transactionHash"].as_str() {
                    if !tx_hash.is_empty() {
                        return Ok(tx_hash.to_string());
                    }
                }
                return Ok(tx_id);
            }
            if poll_state == "STATE_FAILED" {
                anyhow::bail!("Relayer {} failed (state=STATE_FAILED)", label);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Known test key (from alloy test vectors)
    // EOA derived: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_FUNDER: &str = "0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48";

    #[tokio::test]
    async fn test_create_funder_l1_headers_contains_all_keys() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let funder = Address::from_str(TEST_FUNDER).unwrap();
        let headers = create_funder_l1_headers(&signer, funder, 137, 10_000_000, Some(42))
            .await
            .unwrap();

        assert!(headers.contains_key("POLY_ADDRESS"));
        assert!(headers.contains_key("POLY_NONCE"));
        assert!(headers.contains_key("POLY_SIGNATURE"));
        assert!(headers.contains_key("POLY_TIMESTAMP"));
    }

    #[tokio::test]
    async fn test_create_funder_l1_headers_poly_address_is_funder() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let eoa = signer.address();
        let funder = Address::from_str(TEST_FUNDER).unwrap();
        let headers = create_funder_l1_headers(&signer, funder, 137, 10_000_000, Some(42))
            .await
            .unwrap();

        let poly_address = headers.get("POLY_ADDRESS").unwrap().to_str().unwrap();
        assert_eq!(
            poly_address,
            "0x30f6fbe55c1a45bd9fa7cc9823649bf6cc3a2e48"
        );
        assert_ne!(poly_address, &eoa.encode_hex_with_prefix());
    }

    #[tokio::test]
    async fn test_create_funder_l1_headers_nonce_and_timestamp() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let funder = Address::from_str(TEST_FUNDER).unwrap();
        let headers = create_funder_l1_headers(&signer, funder, 137, 9_999_999, Some(0))
            .await
            .unwrap();

        assert_eq!(
            headers.get("POLY_NONCE").unwrap().to_str().unwrap(),
            "0"
        );
        assert_eq!(
            headers.get("POLY_TIMESTAMP").unwrap().to_str().unwrap(),
            "9999999"
        );
    }

    #[tokio::test]
    async fn test_create_funder_l1_headers_signature_is_valid() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let funder = Address::from_str(TEST_FUNDER).unwrap();
        let headers = create_funder_l1_headers(&signer, funder, 137, 10_000_000, Some(0))
            .await
            .unwrap();

        let sig = headers.get("POLY_SIGNATURE").unwrap().to_str().unwrap();
        // Should be a valid hex-encoded signature
        assert!(sig.starts_with("0x"), "Signature should start with 0x, got: {sig}");
        assert!(sig.len() > 130, "Signature should be valid length, got: {}", sig.len());
    }

    #[tokio::test]
    async fn test_create_funder_l1_headers_rejects_invalid_chain_id() {
        let signer = PrivateKeySigner::from_str(TEST_PRIVATE_KEY).unwrap();
        let funder = Address::from_str(TEST_FUNDER).unwrap();
        let result = create_funder_l1_headers(&signer, funder, 999, 10_000_000, None).await;
        // Should succeed (the function doesn't validate chain_id — the server does)
        assert!(result.is_ok());
    }

    #[test]
    fn test_api_key_response_deserialization() {
        let json = r#"{
            "apiKey": "019e4f5f-a080-70df-a93f-34768e702159",
            "secret": "test-secret-value",
            "passphrase": "test-passphrase-value"
        }"#;
        let resp: ApiKeyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            resp.key.to_string(),
            "019e4f5f-a080-70df-a93f-34768e702159"
        );
        assert_eq!(resp.secret, "test-secret-value");
        assert_eq!(resp.passphrase, "test-passphrase-value");
    }

    #[test]
    fn test_api_key_response_deserialization_with_camelcase() {
        // Test the alias: the API might return "apiKey" (camelCase)
        let json = r#"{
            "key": "019e4f5f-a080-70df-a93f-34768e702159",
            "secret": "test-secret-value",
            "passphrase": "test-passphrase-value"
        }"#;
        let resp: ApiKeyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            resp.key.to_string(),
            "019e4f5f-a080-70df-a93f-34768e702159"
        );
        assert_eq!(resp.secret, "test-secret-value");
    }
}

#[cfg(test)]
mod selector_tests {
    use alloy::primitives::keccak256;
    #[test]
    fn print_selectors() {
        let sig = b"computeProxyAddress(address)";
        let hash = keccak256(sig);
        println!("Sig: computeProxyAddress(address)");
        println!("Full hash: {:#x}", hash);
        println!("Selector: {:#02x}{:#02x}{:#02x}{:#02x}", hash[0], hash[1], hash[2], hash[3]);

        // Also check getSalt selector
        let sig2 = b"getSalt(address)";
        let hash2 = keccak256(sig2);
        println!("\nSig: getSalt(address)");
        println!("Selector: {:#02x}{:#02x}{:#02x}{:#02x}", hash2[0], hash2[1], hash2[2], hash2[3]);

        // Also compute abi.encode vs abi.encodePacked
        use alloy::sol_types::SolValue;
        use alloy::hex::ToHexExt;

        let eoa: alloy::primitives::Address = "0x2200709f4eeee905a9f463afc92e215630bc6b62".parse().unwrap();

        // abi.encode = left-padded 32 bytes
        let encoded = (eoa,).abi_encode_params();
        println!("\nKEccak of abi.encode(eoa) (SDK salt):");
        println!("encoded: 0x{}", encoded.encode_hex());
        let salt_abi = keccak256(&encoded);
        println!("salt: {:#x}", salt_abi);

        // abi.encodePacked = raw 20 bytes
        let packed = eoa.abi_encode_packed();
        println!("\nKeccak of abi.encodePacked(eoa) (factory getSalt):");
        println!("packed: 0x{}", packed.encode_hex());
        let salt_packed = keccak256(&packed);
        println!("salt: {:#x}", salt_packed);
    }
}
