use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::str::FromStr;

use anyhow::Result;
use log::{error, info, warn};

use polymarket_client_sdk_v2::auth::state::Authenticated;
use polymarket_client_sdk_v2::auth::Credentials;
use polymarket_client_sdk_v2::auth::Normal;
use polymarket_client_sdk_v2::clob::ws::Client as WsClient;
use polymarket_client_sdk_v2::types::Address;

type AuthWsClient = WsClient<Authenticated<Normal>>;
use uuid::Uuid;

use crate::config::Config;

#[allow(dead_code)]
const RECONNECT_DELAY_SECS: u64 = 5;
#[allow(dead_code)]
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

#[derive(Clone)]
pub struct ClobClient {
    #[allow(dead_code)]
    config: Config,
    pub ws_client: Arc<tokio::sync::RwLock<Option<AuthWsClient>>>,
    #[allow(dead_code)]
    shutdown_token: Arc<AtomicBool>,
}

impl ClobClient {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        info!("Initializing CLOB WebSocket client with config");

        if config.polymarket.private_key.is_some() {
            info!("Private key found in config, will attempt authentication");
        } else {
            info!("No private key found in config, authentication will be skipped");
        }

        let ws_client = match Self::create_authenticated_client(config).await {
            Ok(client) => {
                info!("Successfully created authenticated CLOB client");
                Arc::new(tokio::sync::RwLock::new(Some(client)))
            }
            Err(e) => {
                warn!(
                    "Failed to create authenticated client: {}. User events will not be available.",
                    e
                );
                Arc::new(tokio::sync::RwLock::new(None))
            }
        };

        info!("ClobClient initialization completed");
        Ok(Self {
            config: config.clone(),
            ws_client,
            shutdown_token: Arc::new(AtomicBool::new(false)),
        })
    }

    async fn create_authenticated_client(config: &Config) -> Result<AuthWsClient> {
        let private_key = config
            .polymarket
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("private_key not found in config.polymarket"))?;

        let (api_key, api_secret, api_passphrase) =
            crate::config::derive_api_credentials(private_key).await?;
        let address = crate::config::derive_polymarket_address(private_key)?;

        info!("Address: {}", address);

        let api_key_uuid = Uuid::parse_str(&api_key)?;
        let address = Address::from_str(&address)?;
        let credentials = Credentials::new(api_key_uuid, api_secret, api_passphrase);

        let client = WsClient::default().authenticate(credentials, address)?;

        info!("Connected to authenticated WebSocket (V2)");

        Ok(client)
    }

    #[allow(dead_code)]
    pub fn mark_shutdown(&self) {
        self.shutdown_token.store(true, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_token.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub async fn reconnect(&self) -> Result<()> {
        if self.is_shutdown() {
            info!("Shutdown flag set, skipping reconnection");
            return Ok(());
        }

        info!("Attempting to reconnect CLOB WebSocket client...");

        let mut attempts = 0;

        loop {
            if self.is_shutdown() {
                info!("Shutdown signal received during reconnection attempt");
                return Ok(());
            }

            attempts += 1;

            if attempts > MAX_RECONNECT_ATTEMPTS {
                error!(
                    "Max reconnection attempts ({}) reached. Giving up.",
                    MAX_RECONNECT_ATTEMPTS
                );
                anyhow::bail!(
                    "Failed to reconnect after {} attempts",
                    MAX_RECONNECT_ATTEMPTS
                );
            }

            match Self::create_authenticated_client(&self.config).await {
                Ok(new_client) => {
                    let mut guard = self.ws_client.write().await;
                    *guard = Some(new_client);
                    info!("Successfully reconnected CLOB WebSocket client");
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Reconnection attempt {} failed: {}. Retrying in {} seconds...",
                        attempts, e, RECONNECT_DELAY_SECS
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(RECONNECT_DELAY_SECS)).await;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn run_with_reconnect(
        &self,
        mut handler: impl FnMut(
                Arc<tokio::sync::RwLock<Option<AuthWsClient>>>,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            + Send
            + Clone
            + 'static,
    ) -> Result<()> {
        loop {
            if self.is_shutdown() {
                info!("Shutdown signal received, stopping reconnect loop");
                break;
            }

            let client_guard = self.ws_client.read().await;
            let has_client = client_guard.is_some();
            drop(client_guard);

            if !has_client {
                warn!("No authenticated client available, attempting reconnection...");
                if let Err(e) = self.reconnect().await {
                    error!("Failed to reconnect: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(RECONNECT_DELAY_SECS)).await;
                    continue;
                }
            }

            let result = handler(self.ws_client.clone()).await;

            match result {
                Ok(()) => {
                    info!("Handler completed normally");
                    break;
                }
                Err(e) => {
                    error!("Handler error: {}. Attempting reconnection...", e);

                    {
                        let mut guard = self.ws_client.write().await;
                        *guard = None;
                    }

                    if let Err(reconnect_err) = self.reconnect().await {
                        error!("Reconnection failed: {}. Stopping.", reconnect_err);
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}
