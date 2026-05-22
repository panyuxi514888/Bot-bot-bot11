use crate::api::PolymarketApi;
use anyhow::Result;
use chrono::{Datelike, TimeZone, Timelike};
use chrono_tz::America::New_York;
use std::sync::Arc;

pub struct MarketDiscovery {
    api: Arc<PolymarketApi>,
}

impl MarketDiscovery {
    pub fn new(api: Arc<PolymarketApi>) -> Self {
        Self { api }
    }

    pub fn build_5m_slug(asset_ticker: &str, period_start_et: i64) -> String {
        let asset = asset_ticker.to_lowercase();
        format!("{}-updown-5m-{}", asset, period_start_et)
    }

    pub fn current_5m_period_start_et() -> i64 {
        let now_utc = chrono::Utc::now();
        let now_et = now_utc.with_timezone(&New_York);
        let minute = now_et.minute();

        let minute_floor = (minute / 5) * 5;

        let period_start_et = New_York
            .with_ymd_and_hms(
                now_et.year(),
                now_et.month(),
                now_et.day(),
                now_et.hour(),
                minute_floor,
                0,
            )
            .single()
            .unwrap();

        period_start_et.timestamp()
    }

    pub async fn get_market_tokens(&self, condition_id: &str) -> Result<(String, String)> {
        let details = self.api.get_market(condition_id).await?;
        let mut up_token = None;
        let mut down_token = None;

        for token in details.tokens {
            let outcome = token.outcome.to_uppercase();
            if outcome.contains("UP") || outcome == "1" {
                up_token = Some(token.token_id);
            } else if outcome.contains("DOWN") || outcome == "0" {
                down_token = Some(token.token_id);
            }
        }

        let up = up_token.ok_or_else(|| anyhow::anyhow!("Up token not found"))?;
        let down = down_token.ok_or_else(|| anyhow::anyhow!("Down token not found"))?;

        Ok((up, down))
    }
}
