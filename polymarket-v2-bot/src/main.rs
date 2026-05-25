mod api;
mod clob_client;
mod config;
mod discovery;
mod models;
mod strategy;

use anyhow::Result;
use api::PolymarketApi;
use clap::Parser;
use config::{Args, Config};
use discovery::MarketDiscovery;
use log::{info, warn, LevelFilter};
use polymarket_client_sdk_v2::clob::types::Side;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use strategy::PreLimitStrategy;

fn setup_logging(log_file: Option<&Path>) -> Result<()> {
    if let Some(path) = log_file {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .format(|buf, record| {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                writeln!(
                    buf,
                    "[{}] {} - {}",
                    timestamp,
                    record.level(),
                    record.args()
                )
            })
            .target(env_logger::Target::Pipe(Box::new(file)))
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(LevelFilter::Info)
            .format(|buf, record| {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                writeln!(
                    buf,
                    "[{}] {} - {}",
                    timestamp,
                    record.level(),
                    record.args()
                )
            })
            .init();
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    let log_file = std::env::var("LOG_FILE").ok();
    let log_path = log_file.as_ref().map(|s| Path::new(s.as_str()));
    setup_logging(log_path)?;

    let config = Config::load(&args.config)?;
    log::info!("Config loaded from: {:?}", args.config);
    log::info!(
        "Private key present in config: {}",
        config.polymarket.private_key.is_some()
    );

    let shares = config.strategy.shares;
    let buy_price = config.strategy.buy_price;
    let sell_price = config.strategy.sell_price;
    let cost_per_trade = shares * buy_price * 2.0;

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("BTC 5分钟周期限价单策略");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("  买单价格: ${:.2}", buy_price);
    eprintln!("  卖单价格: ${:.2}", sell_price);
    eprintln!("  每边份额: {:.0}", shares);
    eprintln!("  每笔交易成本: ${:.2}", cost_per_trade);
    eprintln!(
        "  每笔交易预期利润: ${:.2}",
        shares * sell_price * 2.0 - cost_per_trade
    );
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if config.strategy.simulation_mode {
        eprintln!("运行模式: 模拟（不实际下单）");
    } else {
        eprintln!("运行模式: 实盘");
    }
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let api = Arc::new(PolymarketApi::new(
        config.polymarket.gamma_api_url.clone(),
        config.polymarket.clob_api_url.clone(),
        config.polymarket.private_key.clone(),
        config.polymarket.proxy_wallet_address.clone(),
        config.polymarket.signature_type,
        config.rpc.clone(),
        config.polymarket.use_relayer,
        config.polymarket.relayer_api_key.clone(),
        config.polymarket.relayer_api_key_address.clone(),
    ));

    if args.redeem {
        run_redeem_only(api.as_ref(), &config, args.condition_id.as_deref()).await?;
        return Ok(());
    }

    if args.test_presign {
        return run_test_presign(api.as_ref(), &config, &args).await;
    }

    if config.polymarket.private_key.is_some() {
        if let Err(e) = api.authenticate().await {
            log::error!("认证失败: {}", e);
            anyhow::bail!("认证失败，请检查凭证。");
        }
        // P0: Warm up HTTP connection pool + SDK caches before trading starts
        if let Err(e) = api.warmup().await {
            log::warn!("预热失败（不影响运行）: {}", e);
        }
    } else {
        log::warn!("未提供私钥，机器人将仅监控市场。");
    }

    let market_closure_interval = config.strategy.market_closure_check_interval_seconds;
    let strategy = Arc::new(PreLimitStrategy::new(api, config).await);
    let strategy_for_closure = Arc::clone(&strategy);

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(market_closure_interval));
        loop {
            interval.tick().await;
            if let Err(e) = strategy_for_closure.check_market_closure().await {
                warn!("检查市场关闭时出错: {}", e);
            }
        }
    });

    strategy.run().await
}

async fn run_redeem_only(
    api: &PolymarketApi,
    config: &Config,
    condition_id: Option<&str>,
) -> Result<()> {
    let proxy = config
        .polymarket
        .proxy_wallet_address
        .as_deref()
        .ok_or_else(|| {
            anyhow::anyhow!("--redeem 需要在 config.json 中设置 proxy_wallet_address")
        })?;

    eprintln!("赎回模式 (proxy: {})", proxy);
    let cids: Vec<String> = if let Some(cid) = condition_id {
        let cid = if cid.starts_with("0x") {
            cid.to_string()
        } else {
            format!("0x{}", cid)
        };
        eprintln!("赎回条件: {}", cid);
        vec![cid]
    } else {
        eprintln!("获取可赎回头寸...");
        let list = api.get_redeemable_positions(proxy).await?;
        if list.is_empty() {
            eprintln!("没有找到可赎回的头寸。");
            return Ok(());
        }
        eprintln!("找到 {} 个条件需要赎回。", list.len());
        list
    };

    let mut ok_count = 0u32;
    let mut fail_count = 0u32;
    for cid in &cids {
        eprintln!("\n--- 赎回条件 {} ---", &cid[..cid.len().min(18)]);
        match api.redeem_tokens(cid, "", "Up").await {
            Ok(_) => {
                eprintln!("成功: {}", cid);
                ok_count += 1;
            }
            Err(e) => {
                eprintln!("失败 {}: {} (跳过)", cid, e);
                fail_count += 1;
            }
        }
    }
    eprintln!("\n赎回完成。成功: {}, 失败: {}", ok_count, fail_count);
    Ok(())
}

async fn run_test_presign(api: &PolymarketApi, config: &Config, args: &Args) -> Result<()> {
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("预签名旧timestamp订单测试");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Authenticate first (required for L2 credentials and CLOB client)
    if let Err(e) = api.authenticate().await {
        log::error!("认证失败: {}", e);
        anyhow::bail!("认证失败，请检查凭证。");
    }
    info!("[TEST-PRESIGN] Authentication successful");

    // Discover market token if not provided
    let token_id = if let Some(ref tid) = args.test_token_id {
        tid.clone()
    } else {
        let period_start = MarketDiscovery::current_5m_period_start_et();
        let slug = MarketDiscovery::build_5m_slug("BTC", period_start);
        info!("[TEST-PRESIGN] Discovering market via slug: {}", slug);
        let market = api.get_market_by_slug(&slug).await
            .map_err(|e| anyhow::anyhow!("Failed to find BTC market: {}", e))?;
        let details = api.get_market(&market.condition_id).await
            .map_err(|e| anyhow::anyhow!("Failed to get market details: {}", e))?;
        let token = details.tokens.first()
            .ok_or_else(|| anyhow::anyhow!("No tokens found in market"))?;
        info!("[TEST-PRESIGN] Using token_id: {} (outcome: {})", token.token_id, token.outcome);
        token.token_id.clone()
    };

    let side = if args.test_side.to_uppercase() == "SELL" {
        Side::Sell
    } else {
        Side::Buy
    };

    let price = config.strategy.buy_price;
    let shares = config.strategy.shares;

    eprintln!("Test parameters:");
    eprintln!("  Token ID: {}", token_id);
    eprintln!("  Side: {}", if side == Side::Buy { "BUY" } else { "SELL" });
    eprintln!("  Price: ${:.2}", price);
    eprintln!("  Shares: {:.0}", shares);
    eprintln!("  Timestamp: 10 minutes in the past");
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let result = api.test_presigned_order(&token_id, side, price, shares).await?;

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    eprintln!("测试结果: {}", result);
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}
