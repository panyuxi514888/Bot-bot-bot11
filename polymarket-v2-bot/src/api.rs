use crate::models::*;
use anyhow::{Context, Result};
use log::{error, info, warn};
use reqwest::Client as ReqwestClient;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::dyn_abi::Eip712Domain;
use alloy::hex::ToHexExt;
use alloy::sol_types::SolStruct;
use alloy_sol_types::sol;
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

// Relayer SDK (gasless CTF operations via Builder/Relayer API)
use polymarket_relayer::{
    AuthMethod, RelayClient, RelayerTxType,
};

// ── DepositWallet / Factory Constants ──

/// DepositWalletFactory address on Polygon.
const DEPOSIT_WALLET_FACTORY: &str = "0x00000000000Fb5C9ADea0298D729A0CB3823Cc07";



/// EIP-712 typehash for Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)
/// EIP-712 typehash for Batch with Call dependency appended per EIP-712 encodeType:
/// keccak256("Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)Call(address target,uint256 value,bytes data)")
const BATCH_TYPEHASH: [u8; 32] = [
    0x71, 0x2e, 0xf6, 0x6e, 0x83, 0x62, 0xc3, 0x87,
    0xe8, 0x62, 0xca, 0xbf, 0x09, 0x23, 0xc2, 0x09,
    0xdb, 0x0f, 0xa2, 0x4c, 0xfc, 0x97, 0xd2, 0x5e,
    0xcc, 0xba, 0x7c, 0x86, 0xf3, 0xee, 0x1d, 0xd3,
];

/// EIP-712 typehash for Call(address target,uint256 value,bytes data)
const CALL_TYPEHASH: [u8; 32] = [
    0x84, 0xfa, 0x2c, 0xf0, 0x5c, 0xd8, 0x8e, 0x99,
    0x2e, 0xae, 0x77, 0xe8, 0x51, 0xaf, 0x68, 0xa4,
    0xee, 0x27, 0x8d, 0xcf, 0xf6, 0xef, 0x50, 0x4e,
    0x48, 0x7a, 0x55, 0xb3, 0xba, 0xad, 0xfb, 0xe5,
];

/// Compute the EIP-712 domain separator for a DepositWallet
/// (name="DepositWallet", version="1", chainId=137, verifyingContract=<wallet>).
fn deposit_wallet_domain(wallet: ethers::types::Address) -> [u8; 32] {
    let domain_type = b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    let domain_typehash = ethers::utils::keccak256(domain_type);
    let name_hash = ethers::utils::keccak256(b"DepositWallet");
    let version_hash = ethers::utils::keccak256(b"1");
    ethers::utils::keccak256(&ethers::abi::encode(&[
        ethers::abi::Token::FixedBytes(domain_typehash.to_vec()),
        ethers::abi::Token::FixedBytes(name_hash.to_vec()),
        ethers::abi::Token::FixedBytes(version_hash.to_vec()),
        ethers::abi::Token::Uint(ethers::types::U256::from(137u64)),
        ethers::abi::Token::Address(wallet),
    ]))
}

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
    /// EIP-712 struct for Polymarket L1 auth (ClobAuthDomain)
    #[allow(missing_docs)]
    struct ClobAuth {
        address address;
        string  timestamp;
        uint256 nonce;
        string  message;
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
fn amount_to_u256(amount: f64) -> ethers::types::U256 {
    ethers::types::U256::from((amount * 1_000_000.0) as u64)
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
        let ts_url = format!("{}/time", self.clob_url.trim_end_matches('/'));
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

    /// Setup V2 approvals (pUSD to Adapter, CTF to Adapter)
    /// Only necessary once for V2 wallets
    pub async fn setup_v2_approvals(&self) -> Result<()> {
        if self.signature_type != Some(2) && self.signature_type != Some(3) {
            return Ok(()); // Only needed for Deposit Wallet
        }
        if !self.use_relayer {
            anyhow::bail!("Relayer must be enabled for V2 approvals");
        }
        info!("[SETUP] Sending V2 approvals for DepositWallet...");
        let client = self.get_relay_client().await?;
        let tx1 = polymarket_relayer::approve_pusd_for_ctf_adapter();
        let tx2 = polymarket_relayer::approve_ctf_for_ctf_adapter();
        
        use polymarket_relayer::DepositWalletCall;
        let calls: Vec<DepositWalletCall> = vec![tx1.into(), tx2.into()];
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {e}"))?
            .as_secs() + 240;
            
        let handle = client.execute_deposit_wallet_batch(calls, None, deadline, Some("Approve")).await?;
        let res = handle.wait().await?;
        info!("[SETUP] V2 approvals confirmed: {:?}", res.tx_hash);
        Ok(())
    }

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

    /// Execute a contract call through DepositWalletFactory.proxy().
    ///
    /// Builds an EIP-712 signed Batch, calls factory.proxy() directly from the EOA.
    /// The EOA pays gas.
    async fn factory_proxy_execute(
        &self,
        target: ethers::types::Address,
        call_data: &[u8],
        description: &str,
    ) -> Result<String> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required"))?;
        let wallet_str = self.safe_addr_address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Proxy wallet address required"))?;
        let rpc_url = self.get_rpc_url();

        let wallet: ethers::types::Address = wallet_str.parse()?;
        let factory: ethers::types::Address = ethers::types::Address::from_str(DEPOSIT_WALLET_FACTORY)?;
        let eoa: ethers::signers::LocalWallet = private_key.parse()
            .context("Failed to parse private key")?;

        // ── 1. Query wallet nonce from on-chain ──
        let nonce = self.query_deposit_wallet_nonce(&rpc_url, wallet).await?;
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {e}"))?
            .as_secs() + 3600;

        // ── 2. Compute EIP-712 typed data hash ──
        // call_hash = keccak256(abi.encode(CALL_TYPEHASH, target, value, keccak256(data)))
        let call_data_hash = ethers::utils::keccak256(call_data);
        let call_hash = ethers::utils::keccak256(&ethers::abi::encode(&[
            ethers::abi::Token::FixedBytes(CALL_TYPEHASH.to_vec()),
            ethers::abi::Token::Address(target),
            ethers::abi::Token::Uint(ethers::types::U256::zero()),
            ethers::abi::Token::FixedBytes(call_data_hash.to_vec()),
        ]));

        // struct_hash = keccak256(abi.encode(BATCH_TYPEHASH, wallet, nonce, deadline,
        //     keccak256(abi.encode(call_hash)))
        let calls_root = ethers::utils::keccak256(&call_hash);
        let struct_hash = ethers::utils::keccak256(&ethers::abi::encode(&[
            ethers::abi::Token::FixedBytes(BATCH_TYPEHASH.to_vec()),
            ethers::abi::Token::Address(wallet),
            ethers::abi::Token::Uint(ethers::types::U256::from(nonce)),
            ethers::abi::Token::Uint(ethers::types::U256::from(deadline)),
            ethers::abi::Token::FixedBytes(calls_root.to_vec()),
        ]));

        // Data = "\x19\x01" || domain_separator || struct_hash
        let domain_sep = deposit_wallet_domain(wallet);
        let mut typed_data_input = Vec::with_capacity(2 + 32 + 32);
        typed_data_input.extend_from_slice(&[0x19, 0x01]);
        typed_data_input.extend_from_slice(&domain_sep);
        typed_data_input.extend_from_slice(&struct_hash);
        let typed_data_hash = ethers::utils::keccak256(&typed_data_input);

        // ── 3. Sign with EOA ──
        let sig = eoa.sign_hash(ethers::types::H256::from_slice(&typed_data_hash))
            .context("Failed to sign typed data hash")?;

        // Convert to 65-byte format: r (32) || s (32) || v (27/28)
        let mut sig_65 = Vec::with_capacity(65);
        let mut r_bytes = [0u8; 32];
        sig.r.to_big_endian(&mut r_bytes);
        let mut s_bytes = [0u8; 32];
        sig.s.to_big_endian(&mut s_bytes);
        sig_65.extend_from_slice(&r_bytes);
        sig_65.extend_from_slice(&s_bytes);
        let v_byte = if sig.v >= 27 { sig.v as u8 } else { 27 + sig.v as u8 };
        sig_65.push(v_byte);

        // ── 4. ABI-encode factory.proxy() call ──
        // proxy((address,uint256,uint256,(address,uint256,bytes)[])[],bytes[])
        let proxy_selector = [0x26, 0x9d, 0x7c, 0x39];
        let encoded = ethers::abi::encode(&[
            ethers::abi::Token::Array(vec![
                ethers::abi::Token::Tuple(vec![
                    ethers::abi::Token::Address(wallet),
                    ethers::abi::Token::Uint(ethers::types::U256::from(nonce)),
                    ethers::abi::Token::Uint(ethers::types::U256::from(deadline)),
                    ethers::abi::Token::Array(vec![
                        ethers::abi::Token::Tuple(vec![
                            ethers::abi::Token::Address(target),
                            ethers::abi::Token::Uint(ethers::types::U256::zero()),
                            ethers::abi::Token::Bytes(call_data.to_vec()),
                        ]),
                    ]),
                ]),
            ]),
            ethers::abi::Token::Array(vec![
                ethers::abi::Token::Bytes(sig_65),
            ]),
        ]);
        let mut calldata = Vec::with_capacity(4 + encoded.len());
        calldata.extend_from_slice(&proxy_selector);
        calldata.extend_from_slice(&encoded);

        // ── 5. Get EOA nonce & gas estimate, send raw transaction ──
        let tx_hash = self.send_raw_tx(&rpc_url, factory, &calldata).await?;
        info!("{} executed via factory.proxy(): {}", description, tx_hash);
        Ok(tx_hash)
    }

    /// Query the on-chain nonce of a DepositWallet.
    async fn query_deposit_wallet_nonce(&self, rpc_url: &str, wallet: ethers::types::Address) -> Result<u64> {
        // nonce() -> 0xaffed0e0
        let selector = [0xaf, 0xfe, 0xd0, 0xe0];
        let data = format!("0x{}", hex::encode(selector));

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": format!("{:?}", wallet),
                "data": data,
            }, "latest"],
            "id": 1,
        });

        let resp: serde_json::Value = self.client.post(rpc_url).json(&body).send().await?
            .json().await?;

        let hex_str = resp["result"].as_str()
            .ok_or_else(|| anyhow::anyhow!("No result in nonce response: {:?}", resp))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        u64::from_str_radix(hex_str, 16)
            .context("Failed to parse wallet nonce")
    }

    /// Build, sign, and send a raw transaction from the EOA.
    async fn send_raw_tx(&self, rpc_url: &str, to: ethers::types::Address, data: &[u8]) -> Result<String> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key required"))?;
        let eoa: ethers::signers::LocalWallet = private_key.parse()
            .context("Failed to parse private key")?;

        // Get EOA nonce
        use ethers::signers::Signer;
        let eoa_addr = eoa.address();
        let nonce_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [format!("{:?}", eoa_addr), "latest"],
            "id": 1,
        });
        let resp: serde_json::Value = self.client.post(rpc_url).json(&nonce_body).send().await?
            .json().await?;
        let nonce_hex = resp["result"].as_str()
            .ok_or_else(|| anyhow::anyhow!("No nonce result: {:?}", resp))?;
        let nonce_hex = nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex);
        let eoa_nonce: u64 = u64::from_str_radix(nonce_hex, 16)
            .context("Failed to parse nonce")?;

        // Get gas price
        let gp_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id": 1,
        });
        let gp_resp: serde_json::Value = self.client.post(rpc_url).json(&gp_body).send().await?
            .json().await?;
        let gp_hex = gp_resp["result"].as_str()
            .ok_or_else(|| anyhow::anyhow!("No gas price result: {:?}", gp_resp))?;
        let gas_price: ethers::types::U256 = ethers::types::U256::from_str_radix(
            gp_hex.strip_prefix("0x").unwrap_or(gp_hex), 16,
        )?;

        // Build & sign legacy tx
        let tx = ethers::types::TransactionRequest {
            to: Some(ethers::types::NameOrAddress::Address(to)),
            data: Some(data.to_vec().into()),
            value: Some(0u64.into()),
            gas: Some(ethers::types::U256::from(600_000u64)),
            gas_price: Some(gas_price),
            nonce: Some(ethers::types::U256::from(eoa_nonce)),
            chain_id: Some(ethers::types::U64::from(137)),
            ..Default::default()
        };

        // EIP-155: hash(rlp with chain_id,0,0) → sign → adjust v → rlp_signed
        let rlp_encoded = tx.rlp();
        let tx_hash = ethers::utils::keccak256(&rlp_encoded);
        let mut sig = eoa.sign_hash(ethers::types::H256::from_slice(&tx_hash))
            .context("Failed to sign transaction")?;
        sig.v = 137u64 * 2 + 35 + (sig.v - 27);
        let raw_tx = tx.rlp_signed(&sig);

        let send_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [format!("0x{}", hex::encode(raw_tx))],
            "id": 1,
        });
        let send_resp: serde_json::Value = self.client.post(rpc_url).json(&send_body).send().await?
            .json().await?;

        if let Some(tx_hash) = send_resp["result"].as_str() {
            Ok(tx_hash.to_string())
        } else if let Some(err) = send_resp["error"].as_object() {
            anyhow::bail!("eth_sendRawTransaction failed: {} (data: {:?})",
                err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown"),
                err.get("data"));
        } else {
            anyhow::bail!("Unexpected eth_sendRawTransaction response: {:?}", send_resp)
        }
    }

    /// Split USDC into conditional tokens via relayer (gasless).
    /// Falls back to CTF direct (EOA pays gas) if the relayer rejects.
    async fn split_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
        amount: f64,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let amt = amount_to_u256(amount);
        let tx = polymarket_relayer::split_pusd(cid, &[1, 2], amt);

        // Try relayer first (gasless)
        let handle_res = if self.signature_type == Some(2) || self.signature_type == Some(3) {
            use polymarket_relayer::DepositWalletCall;
            let calls: Vec<DepositWalletCall> = vec![tx.clone().into()];
            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Time error: {e}"))?
                .as_secs() + 240;
            client.execute_deposit_wallet_batch(calls, None, deadline, Some("Split")).await
        } else {
            client.execute(vec![tx.clone()], "Split").await
        };

        match handle_res {
            Ok(handle) => {
                match handle.wait().await {
                    Ok(result) => {
                        info!("SDK relayer split confirmed: {:?}", result.tx_hash);
                        return Ok(format!("{:?}", result.tx_hash));
                    }
                    Err(e) => warn!("Relayer wait failed, falling back to direct execution: {:?}", e),
                }
            }
            Err(e) => warn!("Relayer execute failed, falling back to direct execution: {:?}", e),
        }

        // Fallback: execute via CTF direct (EOA pays gas)
        info!("Falling back to CTF direct for split...");
        self.split_via_ctf_direct(condition_id, amount).await
    }

    /// Merge conditional tokens back to USDC via relayer (gasless).
    /// Falls back to factory.proxy() if the relayer rejects.
    async fn merge_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
        amount: f64,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let amt = amount_to_u256(amount);
        let tx = polymarket_relayer::merge_pusd(cid, &[1, 2], amt);

        // Try relayer first (gasless)
        let handle_res = if self.signature_type == Some(2) || self.signature_type == Some(3) {
            use polymarket_relayer::DepositWalletCall;
            let calls: Vec<DepositWalletCall> = vec![tx.clone().into()];
            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("Time error: {e}"))?
                .as_secs() + 240;
            client.execute_deposit_wallet_batch(calls, None, deadline, Some("Merge")).await
        } else {
            client.execute(vec![tx.clone()], "Merge").await
        };

        match handle_res {
            Ok(handle) => {
                match handle.wait().await {
                    Ok(result) => {
                        info!("SDK relayer merge confirmed: {:?}", result.tx_hash);
                        return Ok(format!("{:?}", result.tx_hash));
                    }
                    Err(e) => warn!("Relayer merge wait failed, falling back: {:?}", e),
                }
            }
            Err(e) => warn!("Relayer merge execute failed, falling back: {:?}", e),
        }

        // Fallback: execute via CTF direct (EOA pays gas)
        info!("Falling back to CTF direct for merge...");
        self.merge_via_ctf_direct(condition_id, amount).await
    }

    /// Redeem winning tokens via relayer (gasless).
    /// Falls back to factory.proxy() if the relayer rejects.
    async fn redeem_via_sdk_relayer(
        &self,
        client: &RelayClient,
        condition_id: &str,
    ) -> Result<String> {
        let cid = parse_condition_id(condition_id)?;
        let tx = polymarket_relayer::operations::redeem_regular(cid, &[1, 2]);

        // Try relayer first (gasless)
        match client.execute(vec![tx.clone()], "Redeem").await {
            Ok(handle) => {
                match handle.wait().await {
                    Ok(result) => {
                        info!("SDK relayer redeem confirmed: {:?}", result.tx_hash);
                        return Ok(format!("{:?}", result.tx_hash));
                    }
                    Err(e) => warn!("Relayer redeem wait failed, falling back: {:?}", e),
                }
            }
            Err(e) => warn!("Relayer redeem execute failed, falling back: {:?}", e),
        }

        // Fallback: execute via CTF direct (EOA pays gas)
        self.redeem_via_ctf_direct(condition_id).await
    }

    // ── CTF Direct Fallbacks ──

    /// Create an Alloy provider + CTF client using the EOA signer.
    async fn create_ctf_client(&self) -> Result<CtfClient<impl alloy::providers::Provider + Clone>> {
        let signer = self.create_signer()?;
        let rpc_url = self.get_rpc_url();
        let provider = alloy::providers::ProviderBuilder::new()
            .wallet(signer)
            .connect(&rpc_url)
            .await
            .context("Failed to create CTF provider")?;
        CtfClient::new(provider, POLYGON)
            .map_err(|e| anyhow::anyhow!("Failed to create CTF client: {e}"))
    }

    /// Fallback: split via CTF direct (EOA pays gas, bypasses DepositWallet).
    async fn split_via_ctf_direct(&self, condition_id: &str, amount: f64) -> Result<String> {
        let ct = self.create_ctf_client().await?;
        let cid = parse_condition_id(condition_id)?;
        let config = polymarket_client_sdk_v2::contract_config(POLYGON, false)
            .ok_or_else(|| anyhow::anyhow!("No contract config for POLYGON"))?;
        let amount_u256 = alloy::primitives::U256::from((amount * 1_000_000.0) as u64);

        let cid_b256: B256 = B256::from(cid);
        let req = SplitPositionRequest::for_binary_market(
            config.collateral,
            cid_b256,
            amount_u256,
        );

        let result = ct.split_position(&req).await
            .context("CTF direct split failed")?;
        let tx_hash = format!("{:?}", result.transaction_hash);
        info!("CTF direct split: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Fallback: merge via CTF direct (EOA pays gas, bypasses DepositWallet).
    async fn merge_via_ctf_direct(&self, condition_id: &str, amount: f64) -> Result<String> {
        let ct = self.create_ctf_client().await?;
        let cid = parse_condition_id(condition_id)?;
        let config = polymarket_client_sdk_v2::contract_config(POLYGON, false)
            .ok_or_else(|| anyhow::anyhow!("No contract config for POLYGON"))?;
        let amount_u256 = alloy::primitives::U256::from((amount * 1_000_000.0) as u64);

        let cid_b256: B256 = B256::from(cid);
        let req = MergePositionsRequest::builder()
            .collateral_token(config.collateral)
            .condition_id(cid_b256)
            .partition(vec![alloy::primitives::U256::from(1)])
            .amount(amount_u256)
            .build();

        let result = match ct.merge_positions(&req).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Merge with partition [1] failed: {}. Trying [2]...", e);
                let req2 = MergePositionsRequest::builder()
                    .collateral_token(config.collateral)
                    .condition_id(cid_b256)
                    .partition(vec![alloy::primitives::U256::from(2)])
                    .amount(amount_u256)
                    .build();
                ct.merge_positions(&req2).await
                    .map_err(|e2| anyhow::anyhow!("CTF direct merge failed: {} / {}", e, e2))?
            }
        };

        let tx_hash = format!("{:?}", result.transaction_hash);
        info!("CTF direct merge: {}", tx_hash);
        Ok(tx_hash)
    }

    /// Fallback: redeem via CTF direct (EOA pays gas, bypasses DepositWallet).
    async fn redeem_via_ctf_direct(&self, condition_id: &str) -> Result<String> {
        let ct = self.create_ctf_client().await?;
        let cid = parse_condition_id(condition_id)?;
        let config = polymarket_client_sdk_v2::contract_config(POLYGON, false)
            .ok_or_else(|| anyhow::anyhow!("No contract config for POLYGON"))?;

        let cid_b256: B256 = B256::from(cid);
        let req = RedeemPositionsRequest::builder()
            .collateral_token(config.collateral)
            .condition_id(cid_b256)
            .index_sets(vec![
                alloy::primitives::U256::from(1),
                alloy::primitives::U256::from(2),
            ])
            .build();

        let result = ct.redeem_positions(&req).await
            .context("CTF direct redeem failed")?;
        let tx_hash = format!("{:?}", result.transaction_hash);
        info!("CTF direct redeem: {}", tx_hash);
        Ok(tx_hash)
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


}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Known test key (from alloy test vectors)
    // EOA derived: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
    const TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_FUNDER: &str = "0x1111111111111111111111111111111111111111";

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
            "0x1111111111111111111111111111111111111111"
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
        println!("Selector: {:#02x}{:#02x}{:#02x}{:#02x}", hash.0[0], hash.0[1], hash.0[2], hash.0[3]);

        // Also check getSalt selector
        let sig2 = b"getSalt(address)";
        let hash2 = keccak256(sig2);
        println!("\nSig: getSalt(address)");
        println!("Selector: {:#02x}{:#02x}{:#02x}{:#02x}", hash2.0[0], hash2.0[1], hash2.0[2], hash2.0[3]);

        // Also compute abi.encode vs abi.encodePacked
        use alloy::sol_types::SolValue;
        use alloy::hex::ToHexExt;

        let eoa: alloy::primitives::Address = "0x2222222222222222222222222222222222222222".parse().unwrap();

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
