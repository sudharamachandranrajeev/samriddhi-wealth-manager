//! Device pairing, the same as brahma_core's `PairingCrypto`. A signed-in
//! device shows a [`PairingLink`]; the new device writes its name and an
//! X25519 public key into the record, sealed under a key from the link
//! secret; both show a 6-digit code; the old device seals the account keys
//! to the new device's public key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError, Key, VERSION};
use crate::links::PairingLink;

/// What a new device sends: who it is and the public key to answer to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub name: String,
    pub platform: String,
    pub public_key: [u8; 32],
}

/// What the old device answers with: everything a signed-in device keeps.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingGrant {
    pub email: String,
    pub user_id: String,
    /// The server login secret derived from the password (never the password).
    pub secret: String,
    pub data_key: Zeroizing<Key>,
}

impl std::fmt::Debug for PairingGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingGrant")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// The new device's side of a pairing in progress.
pub struct JoinTicket {
    pub link: PairingLink,
    pub secret: StaticSecret,
    /// Must match the code on the other device.
    pub code: String,
}

pub fn new_secret() -> StaticSecret {
    StaticSecret::from(crypto::random_bytes::<32>())
}

fn request_key(link: &PairingLink) -> Zeroizing<Key> {
    crypto::derive_key(
        &link.secret,
        &format!("{VERSION}|pair|request-key|{}", link.id),
        &[],
    )
}

pub fn seal_request(link: &PairingLink, r: &JoinRequest) -> String {
    crypto::seal_json(
        &json!({"name": r.name, "platform": r.platform, "key": B64.encode(r.public_key)}),
        &request_key(link),
        &format!("{VERSION}|pair|request|{}", link.id),
    )
}

pub fn open_request(link: &PairingLink, sealed: &str) -> Result<JoinRequest, CryptoError> {
    const ERROR: &str = "The join request did not come from this pairing code";
    let v = crypto::open_json(
        sealed,
        &request_key(link),
        &format!("{VERSION}|pair|request|{}", link.id),
        ERROR,
    )?;
    let key = v["key"]
        .as_str()
        .and_then(|k| B64.decode(k).ok())
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(|| CryptoError(ERROR.into()))?;
    let clip = |s: &serde_json::Value| s.as_str().unwrap_or("").chars().take(60).collect();
    Ok(JoinRequest {
        name: clip(&v["name"]),
        platform: clip(&v["platform"]),
        public_key: key,
    })
}

/// Six digits both devices show, e.g. "482 913".
pub fn code(link: &PairingLink, public_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(format!("{VERSION}|pair|code|").as_bytes());
    h.update(link.secret);
    h.update(public_key);
    let h = h.finalize();
    let n = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % 1_000_000;
    let s = format!("{n:06}");
    format!("{} {}", &s[..3], &s[3..])
}

fn grant_key(
    link: &PairingLink,
    own: &StaticSecret,
    other: &[u8; 32],
    from: &[u8; 32],
    to: &[u8; 32],
) -> Result<Zeroizing<Key>, CryptoError> {
    let shared = own.diffie_hellman(&PublicKey::from(*other));
    // A low-order public key gives an all-zero secret anyone can compute.
    if shared.as_bytes().iter().all(|b| *b == 0) {
        return Err(CryptoError("The other device sent an invalid key".into()));
    }
    Ok(crypto::derive_key(
        shared.as_bytes(),
        &format!(
            "{VERSION}|pair|grant-key|{}|{}|{}",
            link.id,
            B64.encode(from),
            B64.encode(to)
        ),
        &link.secret,
    ))
}

pub fn seal_grant(
    link: &PairingLink,
    recipient: &[u8; 32],
    g: &PairingGrant,
) -> Result<String, CryptoError> {
    let mine = new_secret();
    let mine_key = PublicKey::from(&mine).to_bytes();
    let key = grant_key(link, &mine, recipient, &mine_key, recipient)?;
    let sealed = crypto::seal_json(
        &json!({"email": g.email, "userId": g.user_id, "secret": g.secret, "dek": B64.encode(*g.data_key)}),
        &key,
        &format!("{VERSION}|pair|grant|{}", link.id),
    );
    Ok(json!({"key": B64.encode(mine_key), "box": sealed}).to_string())
}

pub fn open_grant(
    link: &PairingLink,
    own: &StaticSecret,
    sealed: &str,
) -> Result<PairingGrant, CryptoError> {
    const ERROR: &str = "The keys from the other device could not be opened";
    let bad = || CryptoError(ERROR.into());
    let outer: serde_json::Value = serde_json::from_str(sealed).map_err(|_| bad())?;
    let sender = outer["key"]
        .as_str()
        .and_then(|k| B64.decode(k).ok())
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(bad)?;
    let mine = PublicKey::from(own).to_bytes();
    let key = grant_key(link, own, &sender, &sender, &mine)?;
    let m = crypto::open_json(
        outer["box"].as_str().ok_or_else(bad)?,
        &key,
        &format!("{VERSION}|pair|grant|{}", link.id),
        ERROR,
    )?;
    let dek = m["dek"]
        .as_str()
        .and_then(|k| B64.decode(k).ok())
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(bad)?;
    let s = |k: &str| m[k].as_str().map(str::to_string).ok_or_else(bad);
    Ok(PairingGrant {
        email: s("email")?,
        user_id: s("userId")?,
        secret: s("secret")?,
        data_key: Zeroizing::new(dek),
    })
}

/// The public key for a secret.
pub fn public_key(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}
