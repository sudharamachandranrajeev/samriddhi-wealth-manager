//! A Rust client for Brahma sync, the same end-to-end encrypted protocol as
//! brahma_core (Dart): Argon2id and HKDF keys, a wrapped data key,
//! XChaCha20-Poly1305 per change, hybrid logical clocks, an outbox with
//! numbered batches, a cursor per device, kept clashing edits, pairing and
//! moved-server links. Cross-language test vectors keep the two in step
//! (tests/vectors.rs and brahma core's test/sync_vectors_test.dart).
//!
//! The server only ever sees ciphertext.

pub mod account;
pub mod api;
pub mod crypto;
pub mod engine;
pub mod hlc;
pub mod links;
pub mod pairing;
pub mod snapshots;
pub mod store;

pub use account::{Account, MemorySecretStore, SecretStore, Session};
pub use api::{Remote, RemoteChange, WorkerApi};
pub use engine::{KeptEdit, SyncEngine, SyncResult};
pub use links::{BrahmaLink, PairingLink};
pub use store::{Row, SyncStore, Tables};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// A message fit to show a person.
    #[error("{0}")]
    Message(String),
    #[error("{}", account::RECOVERY_KEY_NEEDED)]
    RecoveryKeyNeeded,
    #[error("sync database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("sync data: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<crypto::CryptoError> for SyncError {
    fn from(e: crypto::CryptoError) -> SyncError {
        SyncError::Message(e.0)
    }
}
