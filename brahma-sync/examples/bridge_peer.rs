//! The Samriddhi side of the Artha <-> Samriddhi end-to-end test (Artha's
//! test/samriddhi_bridge_live_test.dart runs it). Signs in to an existing
//! account, pulls Artha's money row and prints it as one JSON line, then
//! writes a wealth row and pushes it.
//!
//! Usage: bridge_peer <server> <email> <password> <wealth-snapshot-json>

use brahma_sync::snapshots::{MONEY_ROW, MONEY_TABLE, MoneySnapshot, WEALTH_ROW, WEALTH_TABLE};
use brahma_sync::{Account, MemorySecretStore, SyncStore, Tables};
use serde_json::{Map, json};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, email, password, wealth] = args.as_slice() else {
        eprintln!("usage: bridge_peer <server> <email> <password> <wealth-json>");
        std::process::exit(2);
    };
    let mut account = Account::new(MemorySecretStore::default(), "samriddhi", "linux");
    // Read only Artha's money row; write only the wealth row.
    let mut store = SyncStore::memory(Tables::new(&[MONEY_TABLE], &[WEALTH_TABLE])).unwrap();
    account
        .sign_in(server, email, password, store.device_id())
        .expect("sign in");
    let pulled = account.engine(&mut store).unwrap().unwrap().run().unwrap();
    let row = store
        .get(MONEY_TABLE, MONEY_ROW)
        .unwrap()
        .expect("Artha's money row");
    let money = MoneySnapshot::parse(row.text("snapshot"));
    println!(
        "{}",
        json!({
            "pulled": pulled.pulled,
            "source": row.text("source"),
            "currency": money.currency,
            "liquidCash": money.liquid_cash,
            "spend": money.spend,
            "debtTotal": money.debt_total(),
            "encoded": money.encode(),
        })
    );
    let mut v = Map::new();
    v.insert("source".into(), json!("samriddhi"));
    v.insert("snapshot".into(), json!(wealth));
    v.insert("updated".into(), json!("2026-11-19T09:00:00Z"));
    store.put(WEALTH_TABLE, WEALTH_ROW, v).unwrap();
    assert!(
        store.put(MONEY_TABLE, MONEY_ROW, Map::new()).is_err(),
        "money is read-only"
    );
    let pushed = account.engine(&mut store).unwrap().unwrap().run().unwrap();
    assert_eq!(pushed.pushed, 1);
}
