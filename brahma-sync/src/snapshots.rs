//! The money and wealth bridge rows Artha and Samriddhi share, the same
//! versioned JSON as brahma_core's `MoneySnapshot` and `WealthSnapshot`
//! (core/lib/src/db/bridges.dart). Amounts are whole minor units of the
//! snapshot's currency. Reading never fails: a damaged or missing field
//! reads as empty, and fields a newer version adds are ignored. Encoding is
//! stable and byte-identical to Dart's, so a writer can skip a write that
//! changes nothing.

use serde::Serialize;
use serde_json::Value;

pub const MONEY_TABLE: &str = "bridge_money_snapshot";
pub const WEALTH_TABLE: &str = "bridge_wealth_snapshot";
pub const MONEY_ROW: &str = "artha.money";
pub const WEALTH_ROW: &str = "samriddhi.wealth";
pub const CURRENT: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategorySpend {
    pub category: String,
    pub amount: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DebtBalance {
    pub name: String,
    pub balance: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CashForecast {
    pub days: i64,
    pub start: i64,
    pub end: i64,
    pub low: i64,
    pub low_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFreshness {
    pub account: String,
    /// When its last statement ended (`2026-10-31`); empty when never.
    pub last_statement: String,
}

/// What Artha shares: one month of money in and out, cash, debts, the
/// 90-day forecast and how fresh each account's figures are.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoneySnapshot {
    #[serde(skip)]
    pub version: i64,
    pub currency: String,
    pub month: String,
    pub as_of: String,
    pub income: i64,
    pub spend: i64,
    pub spend_by_category: Vec<CategorySpend>,
    pub fixed_costs: i64,
    pub liquid_cash: i64,
    pub debts: Vec<DebtBalance>,
    pub forecast: Option<CashForecast>,
    pub freshness: Vec<AccountFreshness>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassValue {
    pub asset_class: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MonthValue {
    pub month: String,
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Exposure {
    /// `currency`, `country` or `class`.
    pub kind: String,
    pub key: String,
    pub value: i64,
}

/// What Samriddhi shares: holdings in short, net worth by month (oldest
/// first) and exposure totals.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WealthSnapshot {
    pub version: i64,
    pub currency: String,
    pub as_of: String,
    pub holdings_count: i64,
    pub holdings_total: i64,
    pub by_class: Vec<ClassValue>,
    pub net_worth: Vec<MonthValue>,
    pub exposure: Vec<Exposure>,
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Whole numbers only: an amount that is not exact reads as 0.
fn n(v: &Value) -> i64 {
    match v {
        Value::Number(x) if x.is_i64() => x.as_i64().unwrap_or(0),
        _ => 0,
    }
}

fn maps(v: &Value) -> impl Iterator<Item = &serde_json::Map<String, Value>> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn object(text: &str) -> Option<Value> {
    serde_json::from_str::<Value>(text)
        .ok()
        .filter(Value::is_object)
}

impl MoneySnapshot {
    pub fn is_empty(&self) -> bool {
        self.currency.is_empty()
    }

    pub fn debt_total(&self) -> i64 {
        self.debts.iter().map(|d| d.balance).sum()
    }

    pub fn parse(text: &str) -> MoneySnapshot {
        let Some(j) = object(text) else {
            return MoneySnapshot::default();
        };
        let get =
            |m: &serde_json::Map<String, Value>, k: &str| m.get(k).cloned().unwrap_or(Value::Null);
        MoneySnapshot {
            version: n(&j["v"]),
            currency: s(&j["currency"]),
            month: s(&j["month"]),
            as_of: s(&j["asOf"]),
            income: n(&j["income"]),
            spend: n(&j["spend"]),
            spend_by_category: maps(&j["spendByCategory"])
                .filter(|m| !s(&get(m, "category")).is_empty())
                .map(|m| CategorySpend {
                    category: s(&get(m, "category")),
                    amount: n(&get(m, "amount")),
                })
                .collect(),
            fixed_costs: n(&j["fixedCosts"]),
            liquid_cash: n(&j["liquidCash"]),
            debts: maps(&j["debts"])
                .filter(|m| !s(&get(m, "name")).is_empty())
                .map(|m| DebtBalance {
                    name: s(&get(m, "name")),
                    balance: n(&get(m, "balance")),
                })
                .collect(),
            forecast: j["forecast"].as_object().map(|f| CashForecast {
                days: n(&get(f, "days")),
                start: n(&get(f, "start")),
                end: n(&get(f, "end")),
                low: n(&get(f, "low")),
                low_date: s(&get(f, "lowDate")),
            }),
            freshness: maps(&j["freshness"])
                .filter(|m| !s(&get(m, "account")).is_empty())
                .map(|m| AccountFreshness {
                    account: s(&get(m, "account")),
                    last_statement: s(&get(m, "lastStatement")),
                })
                .collect(),
        }
    }

    pub fn encode(&self) -> String {
        #[derive(Serialize)]
        struct Out<'a> {
            v: i64,
            #[serde(flatten)]
            body: &'a MoneySnapshot,
        }
        serde_json::to_string(&Out {
            v: CURRENT,
            body: self,
        })
        .expect("plain data serialises")
    }
}

impl WealthSnapshot {
    pub fn is_empty(&self) -> bool {
        self.currency.is_empty()
    }

    pub fn latest_net_worth(&self) -> Option<&MonthValue> {
        self.net_worth.last()
    }

    pub fn parse(text: &str) -> WealthSnapshot {
        let Some(j) = object(text) else {
            return WealthSnapshot::default();
        };
        let h = &j["holdings"];
        let get =
            |m: &serde_json::Map<String, Value>, k: &str| m.get(k).cloned().unwrap_or(Value::Null);
        WealthSnapshot {
            version: n(&j["v"]),
            currency: s(&j["currency"]),
            as_of: s(&j["asOf"]),
            holdings_count: n(&h["count"]),
            holdings_total: n(&h["total"]),
            by_class: maps(&h["byClass"])
                .filter(|m| !s(&get(m, "assetClass")).is_empty())
                .map(|m| ClassValue {
                    asset_class: s(&get(m, "assetClass")),
                    value: n(&get(m, "value")),
                })
                .collect(),
            net_worth: maps(&j["netWorth"])
                .filter(|m| !s(&get(m, "month")).is_empty())
                .map(|m| MonthValue {
                    month: s(&get(m, "month")),
                    value: n(&get(m, "value")),
                })
                .collect(),
            exposure: maps(&j["exposure"])
                .filter(|m| !s(&get(m, "kind")).is_empty() && !s(&get(m, "key")).is_empty())
                .map(|m| Exposure {
                    kind: s(&get(m, "kind")),
                    key: s(&get(m, "key")),
                    value: n(&get(m, "value")),
                })
                .collect(),
        }
    }

    pub fn encode(&self) -> String {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Holdings<'a> {
            count: i64,
            total: i64,
            by_class: &'a [ClassValue],
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Out<'a> {
            v: i64,
            currency: &'a str,
            as_of: &'a str,
            holdings: Holdings<'a>,
            net_worth: &'a [MonthValue],
            exposure: &'a [Exposure],
        }
        serde_json::to_string(&Out {
            v: CURRENT,
            currency: &self.currency,
            as_of: &self.as_of,
            holdings: Holdings {
                count: self.holdings_count,
                total: self.holdings_total,
                by_class: &self.by_class,
            },
            net_worth: &self.net_worth,
            exposure: &self.exposure,
        })
        .expect("plain data serialises")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_or_newer_snapshots_read_as_far_as_they_can() {
        for text in [
            "",
            "not json",
            "[]",
            r#"{"debts": 3}"#,
            r#"{"spendByCategory": [1, "x", {}]}"#,
        ] {
            let m = MoneySnapshot::parse(text);
            assert!(m.spend_by_category.is_empty() && m.debts.is_empty() && m.freshness.is_empty());
            assert!(m.forecast.is_none());
            let w = WealthSnapshot::parse(text);
            assert!(w.by_class.is_empty() && w.net_worth.is_empty() && w.exposure.is_empty());
        }
        let newer = MoneySnapshot::parse(
            r#"{"v":2,"currency":"GBP","income":10.5,"spend":7,"debts":[{"name":"Loan","balance":"9"}],"pots":[]}"#,
        );
        assert_eq!(newer.version, 2);
        assert_eq!(newer.income, 0, "a non-whole amount is not trusted");
        assert_eq!(newer.spend, 7);
        assert_eq!(newer.debts[0].balance, 0);
        assert!(MoneySnapshot::default().is_empty());
    }
}
