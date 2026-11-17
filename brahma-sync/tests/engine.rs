//! The sync engine against an in-memory server log: ordering, newest-wins,
//! kept clashing edits, slot reuse after a restore, and the read-only rule.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use brahma_sync::api::{Remote, RemoteChange};
use brahma_sync::{SyncError, SyncStore, Tables};
use serde_json::{Map, Value, json};

#[derive(Default)]
struct Log(BTreeMap<String, BTreeMap<i64, String>>);

#[derive(Clone, Default)]
struct Mem(Rc<RefCell<Log>>);

impl Remote for Mem {
    fn push(&mut self, device: &str, seq: i64, payload: &str) -> Result<bool, SyncError> {
        let mut log = self.0.borrow_mut();
        let d = log.0.entry(device.into()).or_default();
        if d.contains_key(&seq) {
            return Ok(false);
        }
        d.insert(seq, payload.into());
        Ok(true)
    }
    fn fetch(&mut self, device: &str, seq: i64) -> Result<Option<String>, SyncError> {
        Ok(self
            .0
            .borrow()
            .0
            .get(device)
            .and_then(|d| d.get(&seq))
            .cloned())
    }
    fn last_seq(&mut self, device: &str) -> Result<i64, SyncError> {
        Ok(self
            .0
            .borrow()
            .0
            .get(device)
            .and_then(|d| d.keys().last().copied())
            .unwrap_or(0))
    }
    fn devices(&mut self) -> Result<Vec<String>, SyncError> {
        Ok(self.0.borrow().0.keys().cloned().collect())
    }
    fn pull(&mut self, device: &str, after: i64) -> Result<Vec<RemoteChange>, SyncError> {
        Ok(self
            .0
            .borrow()
            .0
            .get(device)
            .map(|d| {
                d.range(after + 1..)
                    .take(50)
                    .map(|(s, p)| RemoteChange {
                        seq: *s,
                        payload: p.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

const DEK: [u8; 32] = [9; 32];
const OWNER: &str = "owner1";
const WEALTH: &str = "bridge_wealth_snapshot";
const MONEY: &str = "bridge_money_snapshot";

fn store(write: &[&str]) -> SyncStore {
    SyncStore::memory(Tables::new(&[MONEY, WEALTH], write)).unwrap()
}

fn sync(s: &mut SyncStore, server: &Mem) -> brahma_sync::SyncResult {
    brahma_sync::SyncEngine::new(s, server.clone(), DEK, OWNER)
        .run()
        .unwrap()
}

fn vals(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn rows_travel_between_two_stores_and_the_newest_wins() {
    let server = Mem::default();
    let (mut a, mut b) = (store(&[WEALTH]), store(&[WEALTH]));
    a.put(
        WEALTH,
        "samriddhi.wealth",
        vals(json!({"source": "samriddhi", "snapshot": "{}", "updated": "1"})),
    )
    .unwrap();
    assert_eq!(a.pending().unwrap(), 1);
    assert_eq!(sync(&mut a, &server).pushed, 1);
    assert_eq!(a.pending().unwrap(), 0);
    assert_eq!(sync(&mut b, &server).pulled, 1);
    let row = b.get(WEALTH, "samriddhi.wealth").unwrap().unwrap();
    assert_eq!(row.text("updated"), "1");
    assert_eq!(row.values["deleted"], json!(0));
    // b edits, a pulls it.
    b.put(
        WEALTH,
        "samriddhi.wealth",
        vals(json!({"source": "samriddhi", "snapshot": "{}", "updated": "2"})),
    )
    .unwrap();
    sync(&mut b, &server);
    sync(&mut a, &server);
    assert_eq!(a.rows(WEALTH).unwrap()[0].text("updated"), "2");
    // A tombstone syncs like an edit.
    a.remove(WEALTH, "samriddhi.wealth").unwrap();
    sync(&mut a, &server);
    sync(&mut b, &server);
    assert!(b.rows(WEALTH).unwrap().is_empty());
    assert!(b.get(WEALTH, "samriddhi.wealth").unwrap().unwrap().deleted);
}

#[test]
fn a_reader_cannot_write_and_ignores_tables_it_does_not_keep() {
    let server = Mem::default();
    let mut reader = store(&[WEALTH]);
    assert!(reader.put(MONEY, "artha.money", Map::new()).is_err());
    // Another device writes a money row and a ledger row; only the money row is kept.
    let mut writer = SyncStore::memory(Tables::new(&[], &[MONEY, "entries"])).unwrap();
    writer
        .put(
            MONEY,
            "artha.money",
            vals(json!({"source": "artha", "snapshot": "{}", "updated": "1"})),
        )
        .unwrap();
    writer
        .put("entries", "e1", vals(json!({"memo": "x"})))
        .unwrap();
    assert_eq!(sync(&mut writer, &server).pushed, 2);
    sync(&mut reader, &server);
    assert_eq!(reader.rows(MONEY).unwrap().len(), 1);
    assert!(reader.rows("entries").unwrap().is_empty());
}

#[test]
fn edits_made_on_two_devices_at_once_keep_the_loser() {
    let server = Mem::default();
    let (mut a, mut b) = (store(&[WEALTH]), store(&[WEALTH]));
    a.set_clock(Box::new(|| 1_000));
    b.set_clock(Box::new(|| 2_000));
    a.put(WEALTH, "w", vals(json!({"updated": "base"})))
        .unwrap();
    sync(&mut a, &server);
    sync(&mut b, &server);
    // Both edit offline; b's edit is newer.
    a.put(WEALTH, "w", vals(json!({"updated": "from a"})))
        .unwrap();
    b.put(WEALTH, "w", vals(json!({"updated": "from b"})))
        .unwrap();
    sync(&mut b, &server);
    sync(&mut a, &server);
    // a pulled b's newer edit before pushing: b's wins, a's is kept.
    assert_eq!(
        a.get(WEALTH, "w").unwrap().unwrap().text("updated"),
        "from b"
    );
    let kept = a.kept_edits().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].row["updated"], json!("from a"));
    // Bringing it back makes it the newest edit everywhere.
    a.restore_kept(&kept[0]).unwrap();
    assert!(a.kept_edits().unwrap().is_empty());
    sync(&mut a, &server);
    sync(&mut b, &server);
    assert_eq!(
        b.get(WEALTH, "w").unwrap().unwrap().text("updated"),
        "from a"
    );
}

#[test]
fn a_restored_copy_never_reuses_a_slot_the_server_holds() {
    let server = Mem::default();
    let mut a = store(&[WEALTH]);
    a.put(WEALTH, "w", vals(json!({"updated": "1"}))).unwrap();
    sync(&mut a, &server);
    // As if restored from a backup taken before that push: the counters are gone.
    a.set_local_setting("sync.seq", "0").unwrap();
    a.set_local_setting("sync.sent", "0").unwrap();
    a.put(WEALTH, "w", vals(json!({"updated": "2"}))).unwrap();
    sync(&mut a, &server);
    let mut b = store(&[WEALTH]);
    sync(&mut b, &server);
    assert_eq!(b.get(WEALTH, "w").unwrap().unwrap().text("updated"), "2");
    assert_eq!(server.clone().last_seq(a.device_id()).unwrap(), 2);
}

#[test]
fn a_change_sealed_for_another_place_is_refused() {
    let server = Mem::default();
    let mut a = store(&[WEALTH]);
    a.put(WEALTH, "w", vals(json!({"updated": "1"}))).unwrap();
    sync(&mut a, &server);
    // The server moves a's change 1 into another device's log.
    let payload = server.clone().fetch(a.device_id(), 1).unwrap().unwrap();
    server
        .clone()
        .push("0123456789abcdef0123456789abcdef", 1, &payload)
        .unwrap();
    let mut b = store(&[WEALTH]);
    let err = brahma_sync::SyncEngine::new(&mut b, server.clone(), DEK, OWNER).pull();
    assert!(err.unwrap_err().to_string().contains("integrity"));
}

#[test]
fn a_new_table_to_keep_pulls_everything_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.db");
    let server = Mem::default();
    let mut w = SyncStore::memory(Tables::new(&[], &[MONEY, WEALTH])).unwrap();
    w.put(MONEY, "m", vals(json!({"updated": "1"}))).unwrap();
    w.put(WEALTH, "w", vals(json!({"updated": "1"}))).unwrap();
    sync(&mut w, &server);
    let mut old = SyncStore::open(
        rusqlite::Connection::open(&path).unwrap(),
        Tables::new(&[WEALTH], &[]),
    )
    .unwrap();
    sync(&mut old, &server);
    assert!(old.rows(MONEY).unwrap().is_empty());
    let device = old.device_id().to_string();
    drop(old);
    let mut newer = SyncStore::open(
        rusqlite::Connection::open(&path).unwrap(),
        Tables::new(&[WEALTH, MONEY], &[]),
    )
    .unwrap();
    assert_eq!(newer.device_id(), device);
    sync(&mut newer, &server);
    assert_eq!(newer.rows(MONEY).unwrap().len(), 1);
}
