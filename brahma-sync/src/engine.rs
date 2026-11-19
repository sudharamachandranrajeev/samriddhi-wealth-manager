//! Moves encrypted changes between this device and the server, as
//! brahma_core's `SyncEngine`.
//!
//! Push: outbox rows go out in numbered batches, strictly in order; a batch
//! leaves the outbox only once the server holds it. Pull: each other
//! device's batches are applied in order, the newest write (by HLC) winning
//! per row; the cursor moves in the same transaction. Sync pulls before it
//! pushes, so an edit still waiting here meets other devices' edits of the
//! same row first: the newest wins and the other version is kept
//! ([`KeptEdit`]).

use std::collections::HashSet;

use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::SyncError;
use crate::api::Remote;
use crate::crypto::{self, Key, VERSION};
use crate::hlc::is_stamp;
use crate::store::{SyncStore, local, plain, set_local};

pub const BATCH_SIZE: i64 = 200;
const ASSIGNED: &str = "sync.seq";
const SENT: &str = "sync.sent";
const KEPT: &str = "kept.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncResult {
    pub pushed: usize,
    pub pulled: usize,
}

pub struct SyncEngine<'a, R: Remote> {
    pub store: &'a mut SyncStore,
    pub remote: R,
    data_key: Key,
    owner: String,
}

fn malformed() -> SyncError {
    SyncError::Message("A change from another device is malformed".into())
}

impl<'a, R: Remote> SyncEngine<'a, R> {
    pub fn new(store: &'a mut SyncStore, remote: R, data_key: Key, owner: &str) -> Self {
        SyncEngine {
            store,
            remote,
            data_key,
            owner: owner.to_string(),
        }
    }

    fn aad(&self, device: &str, seq: i64) -> String {
        format!("{VERSION}|{}|{device}|{seq}", self.owner)
    }

    /// Pulls first, then pushes.
    pub fn run(&mut self) -> Result<SyncResult, SyncError> {
        let pulled = self.pull()?;
        Ok(SyncResult {
            pushed: self.push()?,
            pulled,
        })
    }

    pub fn push(&mut self) -> Result<usize, SyncError> {
        let me = self.store.device_id().to_string();
        // A restored backup may hold an older counter than the server: never reuse a slot.
        let server_last = self.remote.last_seq(&me)?;
        if server_last > self.store.int_setting(ASSIGNED)? {
            let sent = self.store.int_setting(SENT)?;
            let tx = self.store.conn.transaction()?;
            tx.execute("UPDATE brahma_outbox SET seq = NULL WHERE seq > ?", [sent])?;
            set_local(&tx, ASSIGNED, &server_last.to_string())?;
            set_local(&tx, SENT, &server_last.to_string())?;
            tx.commit()?;
        }
        let mut pushed = 0;
        loop {
            let Some(seq) = self.next_batch()? else {
                return Ok(pushed);
            };
            let rows = self.collect(seq)?;
            let payload = crypto::seal(
                &json!({"v": 1, "rows": rows}),
                &self.data_key,
                &self.aad(&me, seq),
            );
            if !self.remote.push(&me, seq, &payload)? && !self.same_as_server(seq, &rows)? {
                // The slot holds something else (e.g. from a since-restored
                // copy of this device): move the batch to a fresh number.
                let fresh = self.store.int_setting(ASSIGNED)? + 1;
                let tx = self.store.conn.transaction()?;
                tx.execute(
                    "UPDATE brahma_outbox SET seq = ? WHERE seq = ?",
                    [fresh, seq],
                )?;
                set_local(&tx, ASSIGNED, &fresh.to_string())?;
                set_local(&tx, SENT, &seq.to_string())?;
                tx.commit()?;
                continue;
            }
            let tx = self.store.conn.transaction()?;
            tx.execute("DELETE FROM brahma_outbox WHERE seq = ?", [seq])?;
            set_local(&tx, SENT, &seq.to_string())?;
            tx.commit()?;
            pushed += rows.len();
        }
    }

    /// The batch to send next: an unconfirmed one first, else a new one.
    fn next_batch(&mut self) -> Result<Option<i64>, SyncError> {
        let tx = self.store.conn.transaction()?;
        let num = |k: &str| -> Result<i64, SyncError> {
            Ok(local(&tx, k)?.and_then(|v| v.parse().ok()).unwrap_or(0))
        };
        let (assigned, sent) = (num(ASSIGNED)?, num(SENT)?);
        if sent < assigned {
            return Ok(Some(sent + 1));
        }
        let waiting: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM brahma_outbox WHERE seq IS NULL LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if waiting.is_none() {
            return Ok(None);
        }
        let seq = assigned + 1;
        tx.execute(
            &format!(
                "UPDATE brahma_outbox SET seq = ?1 WHERE rowid IN
                 (SELECT rowid FROM brahma_outbox WHERE seq IS NULL LIMIT {BATCH_SIZE})"
            ),
            [seq],
        )?;
        set_local(&tx, ASSIGNED, &seq.to_string())?;
        tx.commit()?;
        Ok(Some(seq))
    }

    fn collect(&self, seq: i64) -> Result<Vec<Value>, SyncError> {
        let mut st = self
            .store
            .conn
            .prepare("SELECT tbl, id FROM brahma_outbox WHERE seq = ?")?;
        let items: Vec<(String, String)> = st
            .query_map([seq], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut rows = Vec::new();
        for (table, id) in items {
            if !self.store.tables.write.contains(&table) {
                continue;
            }
            let Some(row) = self.store.get(&table, &id)? else {
                continue;
            };
            let mut change = json!({"t": table, "r": Value::Object(row.values)});
            if let Some(children) = row.children {
                change["p"] = Value::Array(children);
            }
            rows.push(change);
        }
        Ok(rows)
    }

    /// Whether the server's copy of `seq` already carries these row versions.
    fn same_as_server(&mut self, seq: i64, rows: &[Value]) -> Result<bool, SyncError> {
        let me = self.store.device_id().to_string();
        let Some(stored) = self.remote.fetch(&me, seq)? else {
            return Ok(false);
        };
        let Ok(data) = crypto::open(&stored, &self.data_key, &self.aad(&me, seq)) else {
            return Ok(false);
        };
        let key = |r: &Value| format!("{}/{}/{}", r["t"], r["r"]["id"], r["r"]["hlc"]);
        let theirs: HashSet<String> = data["rows"]
            .as_array()
            .map(|a| a.iter().map(key).collect())
            .unwrap_or_default();
        Ok(rows.iter().all(|r| theirs.contains(&key(r))))
    }

    pub fn pull(&mut self) -> Result<usize, SyncError> {
        let mut applied = 0;
        let me = self.store.device_id().to_string();
        for device in self.remote.devices()? {
            if device == me {
                continue;
            }
            let mut cursor = self.cursor(&device)?;
            'stream: loop {
                let batch = self.remote.pull(&device, cursor)?;
                if batch.is_empty() {
                    break;
                }
                for change in batch {
                    // A gap means the server is still catching up: stop here.
                    if change.seq != cursor + 1 {
                        break 'stream;
                    }
                    let data = crypto::open(
                        &change.payload,
                        &self.data_key,
                        &self.aad(&device, change.seq),
                    )
                    .map_err(|e| SyncError::Message(e.0))?;
                    let rows = data["rows"].as_array().ok_or_else(malformed)?;
                    let tx = self.store.conn.transaction()?;
                    for r in rows {
                        apply(&tx, &mut self.store.clock, &self.store.tables.read, r)?;
                    }
                    tx.execute(
                        "INSERT INTO brahma_cursors (device, seq) VALUES (?1, ?2)
                         ON CONFLICT(device) DO UPDATE SET seq = ?2",
                        params![device, change.seq],
                    )?;
                    tx.commit()?;
                    cursor = change.seq;
                    applied += rows.len();
                }
            }
        }
        Ok(applied)
    }

    fn cursor(&self, device: &str) -> Result<i64, SyncError> {
        Ok(self
            .store
            .conn
            .query_row(
                "SELECT seq FROM brahma_cursors WHERE device = ?",
                [device],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
}

/// Writes one remote row if it is newer than the local copy.
fn apply(
    tx: &rusqlite::Transaction,
    clock: &mut crate::hlc::HlcClock,
    keep: &std::collections::BTreeSet<String>,
    change: &Value,
) -> Result<(), SyncError> {
    let (Some(table), Some(row)) = (change["t"].as_str(), change["r"].as_object()) else {
        return Err(malformed());
    };
    if !keep.contains(table) {
        return Ok(());
    }
    let (Some(id), Some(hlc)) = (
        row.get("id").and_then(Value::as_str),
        row.get("hlc").and_then(Value::as_str),
    ) else {
        return Err(malformed());
    };
    if !is_stamp(hlc) {
        return Err(malformed());
    }
    let row = plain(row);
    if row.len() < 2 {
        return Err(SyncError::Message("A synced row is incomplete".into()));
    }
    let local_row: Option<(String, String)> = tx
        .query_row(
            "SELECT hlc, row_json FROM brahma_rows WHERE tbl = ? AND id = ?",
            params![table, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    clock.receive(hlc);
    // A local edit still waiting to go out was never seen by the device that
    // wrote this one: both edited the same row at once. The newest still
    // wins, but the other version is kept so it can be brought back.
    let unsent: bool = tx
        .query_row(
            "SELECT 1 FROM brahma_outbox WHERE tbl = ? AND id = ?",
            params![table, id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    let clash = local_row.is_some() && unsent;
    if let Some((mine, mine_json)) = &local_row {
        if mine.as_str() >= hlc {
            if clash && mine != hlc {
                keep_edit(tx, table, &row)?;
            }
            return Ok(());
        }
        if clash {
            let mine: Map<String, Value> = match serde_json::from_str(mine_json)? {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            keep_edit(tx, table, &mine)?;
        }
    }
    let deleted = match row.get("deleted") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        _ => false,
    };
    let children = match change.get("p") {
        Some(Value::Array(a)) => Some(Value::Array(a.clone()).to_string()),
        _ => None,
    };
    tx.execute(
        "INSERT INTO brahma_rows (tbl, id, hlc, deleted, row_json, children_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(tbl, id) DO UPDATE SET hlc = ?3, deleted = ?4, row_json = ?5, children_json = ?6",
        params![table, id, hlc, deleted, Value::Object(row.clone()).to_string(), children],
    )?;
    Ok(())
}

/// An edit made here that a newer edit from another device replaced before
/// this one was sent. Kept on this device only (`kept.<table>.<id>` in the
/// local settings, the same form as core), until restored or dismissed.
#[derive(Debug, Clone, PartialEq)]
pub struct KeptEdit {
    pub table: String,
    pub id: String,
    pub row: Map<String, Value>,
    /// When it was replaced (UTC, ISO 8601).
    pub at: String,
}

fn keep_edit(
    tx: &rusqlite::Transaction,
    table: &str,
    row: &Map<String, Value>,
) -> Result<(), SyncError> {
    let id = match row.get("id") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    let at = now_iso();
    set_local(
        tx,
        &format!("{KEPT}{table}.{id}"),
        &json!({"t": table, "r": Value::Object(plain(row)), "at": at}).to_string(),
    )
}

fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

impl SyncStore {
    /// Every kept edit, newest first. A damaged entry is skipped.
    pub fn kept_edits(&self) -> Result<Vec<KeptEdit>, SyncError> {
        let mut st = self
            .conn
            .prepare("SELECT value FROM brahma_local WHERE key LIKE 'kept.%'")?;
        let mut out: Vec<KeptEdit> = st
            .query_map([], |r| r.get::<_, String>(0))?
            .filter_map(|v| {
                let v: Value = serde_json::from_str(&v.ok()?).ok()?;
                let row = v["r"].as_object()?.clone();
                Some(KeptEdit {
                    table: v["t"].as_str()?.to_string(),
                    id: match row.get("id")? {
                        Value::String(s) => s.clone(),
                        v => v.to_string(),
                    },
                    row,
                    at: v["at"].as_str()?.to_string(),
                })
            })
            .collect();
        out.sort_by(|a, b| b.at.cmp(&a.at));
        Ok(out)
    }

    /// Puts a kept version back as a new edit, so it syncs and wins from now on.
    pub fn restore_kept(&mut self, edit: &KeptEdit) -> Result<(), SyncError> {
        let mut values = edit.row.clone();
        values.remove("hlc");
        self.put(&edit.table, &edit.id, values)?;
        self.dismiss_kept(edit)
    }

    /// Forgets it: the newer edit from the other device stays.
    pub fn dismiss_kept(&self, edit: &KeptEdit) -> Result<(), SyncError> {
        self.conn.execute(
            "DELETE FROM brahma_local WHERE key = ?",
            [format!("{KEPT}{}.{}", edit.table, edit.id)],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_dates_are_civil() {
        let s = super::now_iso();
        assert_eq!(s.len(), 20);
        assert!(s.starts_with("20"));
        assert!(s.ends_with('Z'));
    }
}
