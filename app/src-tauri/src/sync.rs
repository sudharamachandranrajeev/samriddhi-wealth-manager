//! Brahma sync: Settings → Sync signs in to the same Brahma account as the
//! other Brahma apps (or joins through a `brahma://pair` link, or follows a
//! `brahma://moved` link). The session and data key are kept like the AI key:
//! in the OS keyring, or on Android encrypted by their own Keystore key.
//!
//! This first release shares exactly two rows. Samriddhi writes only
//! `bridge_wealth_snapshot` (holdings in short, net worth by month, exposure
//! totals) and reads only `bridge_money_snapshot` from Artha (cash, debts,
//! monthly spend), which the Wealth screen shows with how old it is. Every
//! other app's table is ignored. The synced rows live in `sync.db`, encrypted
//! with the same key as the main database.

use std::sync::Mutex;

use brahma_sync::links::BrahmaLink;
use brahma_sync::pairing::JoinTicket;
use brahma_sync::snapshots::{
    ClassValue, Exposure, MONEY_ROW, MONEY_TABLE, MoneySnapshot, MonthValue, WEALTH_ROW,
    WEALTH_TABLE, WealthSnapshot,
};
use brahma_sync::{Account, SecretStore, SyncError, SyncStore, Tables};
use samriddhi_core::agents::base_currency;
use samriddhi_core::assets::ALL;
use samriddhi_core::money::Currency;
use samriddhi_core::store::{iso, open_encrypted};
use samriddhi_core::wealth::Holding;
use serde::Serialize;
use serde_json::{Map, json};
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_samriddhi_device::DeviceExt;

use crate::{App, CommandResult, LOCKED, err, now};

const SYNC_FILE: &str = "sync.db";
/// Net worth months kept in the snapshot.
const MONTHS_KEPT: usize = 24;

/// The OS keyring / Android Keystore, through the device plugin.
pub struct DeviceSecrets<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SecretStore for DeviceSecrets<R> {
    fn read(&self, key: &str) -> Result<Option<String>, SyncError> {
        self.0.device().sync_secret(key).map_err(msg)
    }
    fn write(&self, key: &str, value: &str) -> Result<(), SyncError> {
        self.0.device().set_sync_secret(key, value).map_err(msg)
    }
    fn delete(&self, key: &str) -> Result<(), SyncError> {
        self.0.device().clear_sync_secret(key).map_err(msg)
    }
}

fn msg(e: impl std::fmt::Display) -> SyncError {
    SyncError::Message(e.to_string())
}

#[derive(Default)]
pub struct Sync {
    inner: Mutex<SyncInner>,
}

#[derive(Default)]
struct SyncInner {
    account: Option<Account<DeviceSecrets<tauri::Wry>>>,
    /// Waiting for the other device to approve a join.
    ticket: Option<JoinTicket>,
    /// Signed in, but the vault needs the recovery key once.
    needs_recovery: bool,
    last_sync: Option<String>,
    last_error: Option<String>,
}

fn platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

#[cfg(target_os = "android")]
fn client() -> Option<reqwest::blocking::Client> {
    // Phones trust the bundled Mozilla roots, as the AI client does.
    reqwest::blocking::Client::builder()
        .tls_certs_only(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok()),
        )
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
}

#[cfg(not(target_os = "android"))]
fn client() -> Option<reqwest::blocking::Client> {
    None
}

fn device_name() -> String {
    format!("Samriddhi ({})", platform())
}

impl SyncInner {
    fn account(&mut self, app: &AppHandle) -> &mut Account<DeviceSecrets<tauri::Wry>> {
        self.account.get_or_insert_with(|| {
            let a = Account::new(DeviceSecrets(app.clone()), "samriddhi", platform());
            match client() {
                Some(c) => a.with_client(c),
                None => a,
            }
        })
    }
}

/// The sync store: Artha's money row in, Samriddhi's wealth row out.
fn tables() -> Tables {
    Tables::new(&[MONEY_TABLE], &[WEALTH_TABLE])
}

fn open_sync_store(app: &AppHandle) -> CommandResult<SyncStore> {
    let state = app.state::<App>();
    let key = {
        let inner = state.lock_inner()?;
        if inner.locked {
            return Err(LOCKED.into());
        }
        inner.key.ok_or("Your data is not open yet.")?
    };
    let conn = open_encrypted(&state.dir.join(SYNC_FILE), &key).map_err(err)?;
    SyncStore::open(conn, tables()).map_err(err)
}

/// The wealth row from the holdings: totals in the base currency, this
/// month's net worth added to (or replacing) the months already shared.
pub fn wealth_snapshot(
    holdings: &[Holding],
    base: Currency,
    prev: &WealthSnapshot,
    today: &str,
) -> WealthSnapshot {
    let counted: Vec<&Holding> = holdings
        .iter()
        .filter(|h| h.amount.currency == base)
        .collect();
    let total: i64 = counted.iter().map(|h| h.amount.minor).sum();
    let by_class: Vec<ClassValue> = ALL
        .iter()
        .map(|c| ClassValue {
            asset_class: c.as_str().into(),
            value: counted
                .iter()
                .filter(|h| h.asset_class == *c)
                .map(|h| h.amount.minor)
                .sum(),
        })
        .filter(|c| c.value != 0)
        .collect();
    let month = today.get(..7).unwrap_or(today).to_string();
    let mut net_worth: Vec<MonthValue> = if prev.currency == base.code() {
        prev.net_worth
            .iter()
            .filter(|m| m.month != month)
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    net_worth.push(MonthValue {
        month,
        value: total,
    });
    net_worth.sort_by(|a, b| a.month.cmp(&b.month));
    let skip = net_worth.len().saturating_sub(MONTHS_KEPT);
    net_worth.drain(..skip);
    let mut exposure: Vec<Exposure> = by_class
        .iter()
        .map(|c| Exposure {
            kind: "class".into(),
            key: c.asset_class.clone(),
            value: c.value,
        })
        .collect();
    if total != 0 {
        exposure.push(Exposure {
            kind: "currency".into(),
            key: base.code().into(),
            value: total,
        });
    }
    WealthSnapshot {
        version: brahma_sync::snapshots::CURRENT,
        currency: base.code().into(),
        as_of: today.into(),
        holdings_count: holdings.len() as i64,
        holdings_total: total,
        by_class,
        net_worth,
        exposure,
    }
}

/// Writes the wealth row only when something other than its date changed.
/// True when it wrote.
pub fn put_wealth(store: &mut SyncStore, next: &WealthSnapshot) -> Result<bool, SyncError> {
    let prev = store
        .get(WEALTH_TABLE, WEALTH_ROW)?
        .filter(|r| !r.deleted)
        .map(|r| WealthSnapshot::parse(r.text("snapshot")));
    if let Some(p) = &prev {
        let same = WealthSnapshot {
            as_of: p.as_of.clone(),
            ..next.clone()
        };
        if same.encode() == p.encode() {
            return Ok(false);
        }
    }
    let mut v = Map::new();
    v.insert("source".into(), json!("samriddhi"));
    v.insert("snapshot".into(), json!(next.encode()));
    v.insert("updated".into(), json!(iso(now())));
    store.put(WEALTH_TABLE, WEALTH_ROW, v)?;
    Ok(true)
}

fn previous_wealth(store: &SyncStore) -> WealthSnapshot {
    store
        .get(WEALTH_TABLE, WEALTH_ROW)
        .ok()
        .flatten()
        .map(|r| WealthSnapshot::parse(r.text("snapshot")))
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncView {
    signed_in: bool,
    server: Option<String>,
    email: Option<String>,
    needs_recovery: bool,
    /// Shown while waiting for the other device to approve a join.
    join_code: Option<String>,
    last_sync: Option<String>,
    last_error: Option<String>,
}

fn view(app: &AppHandle, s: &mut SyncInner) -> SyncView {
    let account = s.account(app);
    let session = account.session().ok().flatten();
    let signed_in = account.signed_in().unwrap_or(false);
    SyncView {
        signed_in,
        server: session.as_ref().map(|x| x.server.clone()),
        email: session.map(|x| x.email),
        needs_recovery: s.needs_recovery,
        join_code: s.ticket.as_ref().map(|t| t.code.clone()),
        last_sync: s.last_sync.clone(),
        last_error: s.last_error.clone(),
    }
}

async fn blocking<T: Send + 'static>(
    app: AppHandle,
    f: impl FnOnce(&AppHandle) -> CommandResult<T> + Send + 'static,
) -> CommandResult<T> {
    tauri::async_runtime::spawn_blocking(move || f(&app))
        .await
        .map_err(err)?
}

fn sync_state(app: &AppHandle) -> CommandResult<std::sync::MutexGuard<'_, SyncInner>> {
    let st: &Sync = tauri::State::inner(&app.state::<Sync>());
    st.inner.lock().map_err(err)
}

#[tauri::command]
pub async fn sync_status(app: AppHandle) -> CommandResult<SyncView> {
    blocking(app, |app| {
        app.state::<App>().with(|_| Ok(()))?;
        let mut s = sync_state(app)?;
        Ok(view(app, &mut s))
    })
    .await
}

#[tauri::command]
pub async fn sync_sign_in(
    app: AppHandle,
    server: String,
    email: String,
    password: String,
) -> CommandResult<SyncView> {
    blocking(app, move |app| {
        app.state::<App>().with(|_| Ok(()))?;
        let store = open_sync_store(app)?;
        let mut s = sync_state(app)?;
        s.ticket = None;
        match s
            .account(app)
            .sign_in(&server, &email, &password, store.device_id())
        {
            Ok(()) => s.needs_recovery = false,
            Err(SyncError::RecoveryKeyNeeded) => s.needs_recovery = true,
            Err(e) => return Err(e.to_string()),
        }
        Ok(view(app, &mut s))
    })
    .await
}

#[tauri::command]
pub async fn sync_recovery(app: AppHandle, recovery_key: String) -> CommandResult<SyncView> {
    blocking(app, move |app| {
        app.state::<App>().with(|_| Ok(()))?;
        let store = open_sync_store(app)?;
        let mut s = sync_state(app)?;
        s.account(app)
            .unlock_with_recovery_key(&recovery_key, store.device_id())
            .map_err(err)?;
        s.needs_recovery = false;
        Ok(view(app, &mut s))
    })
    .await
}

/// A `brahma://` link: `pair` asks to join (show the code), `moved`
/// follows the account to its new server, `setup` only names the server.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkDone {
    kind: &'static str,
    /// For `setup`: the server address to sign in to.
    server: Option<String>,
    view: SyncView,
}

#[tauri::command]
pub async fn sync_link(app: AppHandle, link: String) -> CommandResult<LinkDone> {
    blocking(app, move |app| {
        app.state::<App>().with(|_| Ok(()))?;
        let parsed = BrahmaLink::parse(&link).map_err(err)?;
        let store = open_sync_store(app)?;
        let mut s = sync_state(app)?;
        let (kind, server) = match parsed {
            BrahmaLink::Moved { server } => {
                s.account(app)
                    .move_server(server.as_str(), &[&store])
                    .map_err(err)?;
                ("moved", None)
            }
            BrahmaLink::Pair(p) => {
                let ticket = s
                    .account(app)
                    .request_join(&p, &device_name())
                    .map_err(err)?;
                s.ticket = Some(ticket);
                ("pair", None)
            }
            BrahmaLink::Setup { server, .. } => {
                ("setup", Some(brahma_sync::links::server_text(&server)))
            }
        };
        Ok(LinkDone {
            kind,
            server,
            view: view(app, &mut s),
        })
    })
    .await
}

/// While joining: true once the other device approved and this one is in.
#[tauri::command]
pub async fn sync_join_check(app: AppHandle) -> CommandResult<SyncView> {
    blocking(app, |app| {
        let store = open_sync_store(app)?;
        let mut s = sync_state(app)?;
        let Some(ticket) = s.ticket.take() else {
            return Ok(view(app, &mut s));
        };
        match s.account(app).join_grant(&ticket) {
            Ok(Some(grant)) => {
                s.account(app)
                    .join(&ticket, &grant, store.device_id())
                    .map_err(err)?;
            }
            Ok(None) => s.ticket = Some(ticket),
            Err(e) => return Err(e.to_string()),
        }
        Ok(view(app, &mut s))
    })
    .await
}

#[tauri::command]
pub async fn sync_cancel_join(app: AppHandle) -> CommandResult<()> {
    sync_state(&app)?.ticket = None;
    Ok(())
}

/// Shares the wealth row (when it changed) and fetches Artha's money row.
#[tauri::command]
pub async fn sync_now(app: AppHandle) -> CommandResult<SyncView> {
    blocking(app, |app| {
        let (holdings, base) = app
            .state::<App>()
            .with(|st| Ok((st.holdings()?, base_currency(&st.profile()?))))?;
        let mut store = open_sync_store(app)?;
        let today = now().strftime("%Y-%m-%d").to_string();
        let next = wealth_snapshot(&holdings, base, &previous_wealth(&store), &today);
        put_wealth(&mut store, &next).map_err(err)?;
        let mut s = sync_state(app)?;
        let result = match s.account(app).engine(&mut store) {
            Ok(Some(mut engine)) => engine.run().map(|_| ()),
            Ok(None) => Err(SyncError::Message("Not signed in".into())),
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                s.last_sync = Some(iso(now()));
                s.last_error = None;
            }
            Err(e) => s.last_error = Some(e.to_string()),
        }
        Ok(view(app, &mut s))
    })
    .await
}

#[tauri::command]
pub async fn sync_sign_out(app: AppHandle) -> CommandResult<SyncView> {
    blocking(app, |app| {
        let mut s = sync_state(app)?;
        s.account(app).sign_out().map_err(err)?;
        s.ticket = None;
        s.needs_recovery = false;
        s.last_sync = None;
        s.last_error = None;
        Ok(view(app, &mut s))
    })
    .await
}

/// Artha's money row as the Wealth screen shows it. Read-only here.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoneyView {
    currency: String,
    month: String,
    /// The date Artha's figures run to.
    as_of: String,
    /// When Artha last changed the row (UTC ISO).
    updated: String,
    /// Whole days since `updated`; None when it cannot be read.
    age_days: Option<i64>,
    liquid_cash: i64,
    debt_total: i64,
    monthly_spend: i64,
    /// Liquid cash over a month's spend; None when there is no spend.
    cushion_months: Option<f64>,
    /// Accounts and when their last statement ended.
    freshness: Vec<(String, String)>,
}

pub fn money_view(updated: &str, snap: &MoneySnapshot, now: jiff::Timestamp) -> MoneyView {
    let age_days = updated
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| (now.as_second() - t.as_second()).max(0) / 86_400);
    MoneyView {
        currency: snap.currency.clone(),
        month: snap.month.clone(),
        as_of: snap.as_of.clone(),
        updated: updated.into(),
        age_days,
        liquid_cash: snap.liquid_cash,
        debt_total: snap.debt_total(),
        monthly_spend: snap.spend,
        cushion_months: (snap.spend > 0)
            .then(|| (snap.liquid_cash as f64 / snap.spend as f64 * 10.0).round() / 10.0),
        freshness: snap
            .freshness
            .iter()
            .map(|f| (f.account.clone(), f.last_statement.clone()))
            .collect(),
    }
}

#[tauri::command]
pub async fn money_snapshot(app: AppHandle) -> CommandResult<Option<MoneyView>> {
    blocking(app, |app| {
        if !app.state::<App>().dir.join(SYNC_FILE).exists() {
            return Ok(None);
        }
        let store = open_sync_store(app)?;
        let Some(row) = store
            .get(MONEY_TABLE, MONEY_ROW)
            .map_err(err)?
            .filter(|r| !r.deleted)
        else {
            return Ok(None);
        };
        let snap = MoneySnapshot::parse(row.text("snapshot"));
        if snap.is_empty() {
            return Ok(None);
        }
        Ok(Some(money_view(row.text("updated"), &snap, now())))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use samriddhi_core::assets::AssetClass;
    use samriddhi_core::money::Money;

    fn gbp() -> Currency {
        Currency::new("GBP").unwrap()
    }

    fn h(id: &str, class: AssetClass, minor: i64, cur: Currency) -> Holding {
        Holding {
            id: id.into(),
            account_id: "a".into(),
            name: id.into(),
            asset_class: class,
            amount: Money::new(minor, cur),
        }
    }

    #[test]
    fn wealth_rows_sum_the_base_currency_and_keep_months() {
        let usd = Currency::new("USD").unwrap();
        let hs = [
            h("1", AssetClass::Equity, 1_000_000, gbp()),
            h("2", AssetClass::Cash, 200_000, gbp()),
            h("3", AssetClass::Equity, 500, usd),
        ];
        let prev = WealthSnapshot {
            currency: "GBP".into(),
            net_worth: vec![
                MonthValue {
                    month: "2026-10".into(),
                    value: 1,
                },
                MonthValue {
                    month: "2026-11".into(),
                    value: 2,
                },
            ],
            ..Default::default()
        };
        let w = wealth_snapshot(&hs, gbp(), &prev, "2026-11-19");
        assert_eq!(w.holdings_count, 3);
        assert_eq!(w.holdings_total, 1_200_000);
        assert_eq!(w.by_class.len(), 2);
        assert_eq!(w.net_worth.len(), 2);
        assert_eq!(w.net_worth[1].value, 1_200_000);
        assert_eq!(w.as_of, "2026-11-19");
        let round = WealthSnapshot::parse(&w.encode());
        assert_eq!(round.net_worth, w.net_worth);
        // Another currency starts the history again.
        let fresh = wealth_snapshot(&hs, Currency::new("EUR").unwrap(), &prev, "2026-11-19");
        assert_eq!(fresh.net_worth.len(), 1);
    }

    #[test]
    fn the_wealth_row_is_written_only_when_it_changes() {
        let mut store = SyncStore::memory(tables()).unwrap();
        let hs = [h("1", AssetClass::Bonds, 50_000, gbp())];
        let w = wealth_snapshot(&hs, gbp(), &previous_wealth(&store), "2026-11-18");
        assert!(put_wealth(&mut store, &w).unwrap());
        let again = wealth_snapshot(&hs, gbp(), &previous_wealth(&store), "2026-11-19");
        assert!(
            !put_wealth(&mut store, &again).unwrap(),
            "only the date moved"
        );
        let more = [h("1", AssetClass::Bonds, 60_000, gbp())];
        let changed = wealth_snapshot(&more, gbp(), &previous_wealth(&store), "2026-11-19");
        assert!(put_wealth(&mut store, &changed).unwrap());
        assert_eq!(previous_wealth(&store).holdings_total, 60_000);
    }

    #[test]
    fn other_apps_rows_cannot_be_written() {
        let mut store = SyncStore::memory(tables()).unwrap();
        assert!(store.put(MONEY_TABLE, MONEY_ROW, Map::new()).is_err());
    }

    #[test]
    fn the_money_view_shows_age_and_cushion() {
        let snap = MoneySnapshot::parse(
            r#"{"v":1,"currency":"GBP","month":"2026-10","asOf":"2026-10-31","spend":200000,"liquidCash":700000,"debts":[{"name":"Card","balance":50000}],"freshness":[{"account":"Current","lastStatement":"2026-10-31"}]}"#,
        );
        let now: jiff::Timestamp = "2026-11-19T12:00:00Z".parse().unwrap();
        let v = money_view("2026-11-16T09:00:00Z", &snap, now);
        assert_eq!(v.age_days, Some(3));
        assert_eq!(v.cushion_months, Some(3.5));
        assert_eq!(v.debt_total, 50000);
        assert_eq!(v.freshness, vec![("Current".into(), "2026-10-31".into())]);
        assert_eq!(money_view("bad", &snap, now).age_days, None);
    }
}
