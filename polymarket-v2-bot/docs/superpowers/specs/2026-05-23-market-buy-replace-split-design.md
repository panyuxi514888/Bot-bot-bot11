# Replace CTF Split with Market Buy of Next Period Tokens

## Summary

Replace the failing on-chain CTF `split_shares_with_retry()` call with CLOB market
BUY orders for the *next* 5-min period's UP and DOWN tokens. This achieves the same
inventory acquisition effect without relayer dependency.

## Design

### Flow Change

At the start of period N (in `process_market()` `None` branch):

1. **NEW**: Discover period N+1 market, market-BUY 5 UP + 5 DOWN (~$0.50 each, fills instantly)
2. **Existing**: Place limit-BUY orders for period N at $0.01
3. **Existing**: CLOB events trigger SELL at $0.02 when fills arrive
4. **Existing**: Period end merge

### New Method: `place_market_order`

- Modeled after existing `place_limit_order()` at `strategy.rs:832`
- Difference: uses `order_type: "MARKET"` and no `price` / `GTD` fields
- Calls `self.api.place_order(&order)` — same API path

### Files Changed

- `src/strategy.rs` only: add `place_market_order()` method, insert market-buy calls

## Self-Review

- No placeholders or TBDs
- Internally consistent: market buy provides tokens that limit buy+sell cycle monetizes
- Single focused change, one file, one new method
- No ambiguity: "next period" = `current_period_et + 300`
