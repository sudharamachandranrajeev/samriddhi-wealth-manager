//! The device's side of sync: rows of the synced tables this app uses, the
//! outbox of local writes not yet sent, the cursor per other device, and
//! device-local settings. All `brahma_*` tables, so they can live in an
//! app's own (encrypted) database file.
//!
//! Unlike the Dart apps, rows are kept whole as JSON: this client stores
//! only what it is told to ([`Tables`]), and never needs their columns.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value};

use crate::SyncError;
use crate::hlc::HlcClock;

/// Which synced tables this app keeps, and which of them it may write.
/// Rows of any other table are ignored, as an app without the table would.
#[derive(Debug, Clone)]
pub struct Tables {
    pub read: BTreeSet<String>,
    pub write: BTreeSet<String>,
}

impl Tables {
    pub fn new(read: &[&str], write: &[&str]) -> Tables {
        let mut t = Tables {
            read: read.iter().map(|s| s.to_string()).collect(),
            write: write.iter().map(|s| s.to_string()).collect(),
        };
        // What it writes it also keeps.
        t.read.extend(t.write.iter().cloned());
        t
    }
}

/// A synced row as kept here.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub table: String,
    pub id: String,
    pub hlc: String,
    pub deleted: bool,
    /// Every plain column, including `id`, `hlc` and `deleted`.
    pub values: Map<String, Value>,
    /// Child rows that travel with it (an entry's postings), if any.
    pub children: Option<Vec<Value>>,
}

impl Row {
    pub fn text(&self, column: &str) -> &str {
        self.values
            .get(column)
            .and_then(Value::as_str)
            .unwrap_or("")
    }
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS brahma_rows (
        tbl TEXT NOT NULL,
        id TEXT NOT NULL,
        hlc TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        row_json TEXT NOT NULL,
        children_json TEXT,
        PRIMARY KEY (tbl, id)
    );
    CREATE TABLE IF NOT EXISTS brahma_outbox (
        tbl TEXT NOT NULL,
        id TEXT NOT NULL,
        seq INTEGER,
        PRIMARY KEY (tbl, id)
    );
    CREATE TABLE IF NOT EXISTS brahma_cursors (device TEXT PRIMARY KEY, seq INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS brahma_local (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

pub struct SyncStore {
    pub(crate) conn: Connection,
    pub(crate) clock: HlcClock,
    pub tables: Tables,
}

/// Only plain values sync (as in core): text, numbers, booleans and null.
pub(crate) fn plain(row: &Map<String, Value>) -> Map<String, Value> {
    row.iter()
        .filter(|(_, v)| {
            matches!(
                v,
                Value::Null | Value::String(_) | Value::Number(_) | Value::Bool(_)
            )
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

impl SyncStore {
    /// Opens the sync tables in `conn`, creating them and a device id on
    /// first use. When `tables.read` gained a table since the last run, every
    /// cursor is cleared so the next sync pulls its rows again from the start
    /// (applying a change twice is harmless: the newer row wins).
    pub fn open(conn: Connection, tables: Tables) -> Result<SyncStore, SyncError> {
        conn.execute_batch(SCHEMA)?;
        let device = match local(&conn, "device.id")? {
            Some(d) => d,
            None => {
                let d = crate::crypto::hex(&crate::crypto::random_bytes::<16>());
                set_local(&conn, "device.id", &d)?;
                d
            }
        };
        let kept: BTreeSet<String> = local(&conn, "tables.read")?
            .map(|s| {
                s.split(',')
                    .filter(|t| !t.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !tables.read.is_subset(&kept) {
            conn.execute("DELETE FROM brahma_cursors", [])?;
            let list: Vec<&str> = tables.read.iter().map(String::as_str).collect();
            set_local(&conn, "tables.read", &list.join(","))?;
        }
        let mut clock = HlcClock::new(&device);
        // Never stamp below what this store already holds.
        let latest: Option<String> =
            conn.query_row("SELECT MAX(hlc) FROM brahma_rows", [], |r| r.get(0))?;
        if let Some(h) = latest.filter(|h| !h.is_empty()) {
            clock.receive(&h);
        }
        Ok(SyncStore {
            conn,
            clock,
            tables,
        })
    }

    /// An in-memory store, for tests.
    pub fn memory(tables: Tables) -> Result<SyncStore, SyncError> {
        SyncStore::open(Connection::open_in_memory()?, tables)
    }

    /// This database's id in the account's change logs (32 hex digits).
    pub fn device_id(&self) -> &str {
        self.clock.node()
    }

    /// For tests: a clock that reads `now` instead of the wall clock.
    pub fn set_clock(&mut self, now: Box<dyn Fn() -> i64 + Send>) {
        self.clock = HlcClock::with_clock(self.device_id(), now);
    }

    pub fn local_setting(&self, key: &str) -> Result<Option<String>, SyncError> {
        local(&self.conn, key)
    }

    pub fn set_local_setting(&self, key: &str, value: &str) -> Result<(), SyncError> {
        set_local(&self.conn, key, value)
    }

    pub(crate) fn int_setting(&self, key: &str) -> Result<i64, SyncError> {
        Ok(self
            .local_setting(key)?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    /// Writes `values` as row `id` of `table` (a table this app may write),
    /// stamps it and queues it to send. `id`, `hlc` and `deleted` are set here.
    pub fn put(
        &mut self,
        table: &str,
        id: &str,
        values: Map<String, Value>,
    ) -> Result<(), SyncError> {
        self.write(table, id, values, false)
    }

    /// Tombstones a row: deletions sync like edits.
    pub fn remove(&mut self, table: &str, id: &str) -> Result<(), SyncError> {
        let values = self.get(table, id)?.map(|r| r.values).unwrap_or_default();
        self.write(table, id, values, true)
    }

    fn write(
        &mut self,
        table: &str,
        id: &str,
        values: Map<String, Value>,
        deleted: bool,
    ) -> Result<(), SyncError> {
        if !self.tables.write.contains(table) {
            return Err(SyncError::Message(format!(
                "This app only reads {table}; another app writes it"
            )));
        }
        let hlc = self.clock.tick();
        let mut values = plain(&values);
        values.insert("id".into(), Value::String(id.into()));
        values.insert("hlc".into(), Value::String(hlc.clone()));
        values.insert("deleted".into(), Value::from(deleted as i64));
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO brahma_rows (tbl, id, hlc, deleted, row_json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(tbl, id) DO UPDATE SET hlc = ?3, deleted = ?4, row_json = ?5",
            params![table, id, hlc, deleted, Value::Object(values).to_string()],
        )?;
        tx.execute(
            "INSERT INTO brahma_outbox (tbl, id, seq) VALUES (?1, ?2, NULL)
             ON CONFLICT(tbl, id) DO UPDATE SET seq = NULL",
            params![table, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// One row, tombstoned or not.
    pub fn get(&self, table: &str, id: &str) -> Result<Option<Row>, SyncError> {
        self.conn
            .query_row(
                "SELECT tbl, id, hlc, deleted, row_json, children_json FROM brahma_rows WHERE tbl = ? AND id = ?",
                params![table, id],
                read_row,
            )
            .optional()?
            .transpose()
    }

    /// The live (not deleted) rows of `table`.
    pub fn rows(&self, table: &str) -> Result<Vec<Row>, SyncError> {
        let mut st = self.conn.prepare(
            "SELECT tbl, id, hlc, deleted, row_json, children_json FROM brahma_rows
             WHERE tbl = ? AND deleted = 0 ORDER BY id",
        )?;
        let rows = st.query_map([table], read_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Local writes not yet on the server.
    pub fn pending(&self) -> Result<i64, SyncError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM brahma_outbox", [], |r| r.get(0))?)
    }

    /// Forgets every synced row, cursor and counter (after signing out), but
    /// keeps the device id.
    pub fn reset(&mut self) -> Result<(), SyncError> {
        self.conn.execute_batch(
            "DELETE FROM brahma_rows; DELETE FROM brahma_outbox; DELETE FROM brahma_cursors;
             DELETE FROM brahma_local WHERE key NOT IN ('device.id', 'tables.read');",
        )?;
        Ok(())
    }
}

type RowResult = Result<Row, SyncError>;

fn read_row(r: &rusqlite::Row) -> rusqlite::Result<RowResult> {
    let row_json: String = r.get(4)?;
    let children: Option<String> = r.get(5)?;
    let parsed = (|| {
        let values = match serde_json::from_str(&row_json)? {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let children = children
            .map(|c| serde_json::from_str::<Vec<Value>>(&c))
            .transpose()?;
        Ok::<_, serde_json::Error>((values, children))
    })();
    Ok(match parsed {
        Ok((values, children)) => Ok(Row {
            table: r.get(0)?,
            id: r.get(1)?,
            hlc: r.get(2)?,
            deleted: r.get(3)?,
            values,
            children,
        }),
        Err(e) => Err(e.into()),
    })
}

pub(crate) fn local(conn: &Connection, key: &str) -> Result<Option<String>, SyncError> {
    Ok(conn
        .query_row("SELECT value FROM brahma_local WHERE key = ?", [key], |r| {
            r.get(0)
        })
        .optional()?)
}

pub(crate) fn set_local(conn: &Connection, key: &str, value: &str) -> Result<(), SyncError> {
    conn.execute(
        "INSERT INTO brahma_local (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
        params![key, value],
    )?;
    Ok(())
}
