//! End-to-end encryption, byte for byte the same as brahma_core's
//! `VaultCrypto` (core/lib/src/security/crypto.dart):
//!
//! ```text
//! password --Argon2id--> master --HKDF--> auth secret (server login)
//!                                    \--> KEK, which wraps a random data key
//! ```
//!
//! The data key (DEK) encrypts every change with XChaCha20-Poly1305. A
//! recovery key wraps the same DEK so a forgotten password loses nothing.
//! A sealed value is base64(nonce 24 ‖ ciphertext ‖ tag 16).

use std::io::{Read, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Protocol label bound into every key derivation and ciphertext. It names
/// the first Brahma app, which created the format, and never changes.
pub const VERSION: &str = "artha/v1";

/// Shortest password accepted for a sync account.
pub const MIN_PASSWORD: usize = 12;

pub type Key = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

fn err(s: &str) -> CryptoError {
    CryptoError(s.to_string())
}

/// What a password turns into. The server only ever sees `auth_secret` (as
/// the account password); `kek` never leaves the device.
pub struct PasswordKeys {
    pub auth_secret: String,
    pub kek: Zeroizing<Key>,
}

/// The per-account salt: SHA-256 of `artha/v1/<e-mail, trimmed, lower case>`.
pub fn salt(email: &str) -> [u8; 32] {
    Sha256::digest(format!("{VERSION}/{}", email.trim().to_lowercase()).as_bytes()).into()
}

/// OWASP's minimum Argon2id profile (19 MiB, 2 passes, 1 lane), as core uses.
pub fn from_password(email: &str, password: &str) -> Result<PasswordKeys, CryptoError> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(CryptoError(format!(
            "Use a password of at least {MIN_PASSWORD} characters"
        )));
    }
    let params = Params::new(19456, 2, 1, Some(32)).expect("fixed Argon2 parameters are valid");
    let mut master = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt(email), master.as_mut())
        .map_err(|e| CryptoError(e.to_string()))?;
    let auth = derive_key(master.as_ref(), "artha auth v1", &[]);
    let kek = derive_key(master.as_ref(), "artha kek v1", &[]);
    Ok(PasswordKeys {
        auth_secret: hex(auth.as_ref()),
        kek,
    })
}

/// HKDF-SHA256, 32 bytes, for `info`; an empty `salt` is HKDF's default.
pub fn derive_key(secret: &[u8], info: &str, salt: &[u8]) -> Zeroizing<Key> {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, secret);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut())
        .expect("32 bytes is a valid HKDF length");
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the operating system has no random source");
    b
}

/// A new recovery key, e.g. "7KQ2-M9XD-...": 256 bits in Crockford base32.
pub fn new_recovery_key() -> String {
    let s = base32(&random_bytes::<32>());
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn recovery_kek(recovery_key: &str) -> Result<Zeroizing<Key>, CryptoError> {
    match unbase32(recovery_key) {
        Some(b) if b.len() == 32 => Ok(derive_key(&b, "artha recovery v1", &[])),
        _ => Err(err("That recovery key is not valid")),
    }
}

/// Encrypts `key` under `kek`; `purpose` ("password" or "recovery") is bound
/// in, so one wrap cannot be passed off as the other.
pub fn wrap_key(key: &[u8], kek: &Key, purpose: &str) -> String {
    encrypt(key, kek, format!("{VERSION}|wrap|{purpose}").as_bytes())
}

pub fn unwrap_key(wrapped: &str, kek: &Key, purpose: &str) -> Result<Zeroizing<Key>, CryptoError> {
    let clear = decrypt(
        wrapped,
        kek,
        format!("{VERSION}|wrap|{purpose}").as_bytes(),
        "Wrong password or recovery key",
    )?;
    let key: Key = clear
        .as_slice()
        .try_into()
        .map_err(|_| err("Wrong password or recovery key"))?;
    Ok(Zeroizing::new(key))
}

/// Compresses (gzip) and encrypts a JSON value. `aad` ties the ciphertext to
/// its place (owner, device, sequence), so the server cannot move it around.
pub fn seal(json: &serde_json::Value, data_key: &Key, aad: &str) -> String {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(json.to_string().as_bytes())
        .and_then(|_| gz.finish())
        .map(|bytes| encrypt(&bytes, data_key, aad.as_bytes()))
        .expect("gzip into memory cannot fail")
}

pub fn open(sealed: &str, data_key: &Key, aad: &str) -> Result<serde_json::Value, CryptoError> {
    const BAD: &str = "A synced change failed its integrity check";
    let clear = decrypt(sealed, data_key, aad.as_bytes(), BAD)?;
    let mut text = Vec::new();
    flate2::read::GzDecoder::new(clear.as_slice())
        .read_to_end(&mut text)
        .map_err(|_| err(BAD))?;
    serde_json::from_slice(&text).map_err(|_| err(BAD))
}

/// Encrypts a small JSON value (no compression) under `key`, bound to `aad`.
pub fn seal_json(json: &serde_json::Value, key: &Key, aad: &str) -> String {
    encrypt(json.to_string().as_bytes(), key, aad.as_bytes())
}

pub fn open_json(
    sealed: &str,
    key: &Key,
    aad: &str,
    error: &str,
) -> Result<serde_json::Value, CryptoError> {
    let clear = decrypt(sealed, key, aad.as_bytes(), error)?;
    serde_json::from_slice(&clear).map_err(|_| err(error))
}

fn encrypt(clear: &[u8], key: &Key, aad: &[u8]) -> String {
    let nonce = random_bytes::<24>();
    let boxed = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: clear, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail");
    let mut out = Vec::with_capacity(24 + boxed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&boxed);
    B64.encode(out)
}

fn decrypt(
    data: &str,
    key: &Key,
    aad: &[u8],
    error: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let bytes = B64.decode(data).map_err(|_| err(error))?;
    if bytes.len() < 24 + 16 {
        return Err(err(error));
    }
    let (nonce, boxed) = bytes.split_at(24);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: boxed, aad })
        .map(Zeroizing::new)
        .map_err(|_| err(error))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Accepts lower case, spaces and dashes, and the usual misreadings
/// (O for 0, I/L for 1).
fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for ch in text.chars() {
        if ch.is_whitespace() || ch == '-' {
            continue;
        }
        let ch = match ch.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        let v = ALPHABET.iter().position(|&a| a as char == ch)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 255) as u8);
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_passwords_are_refused() {
        assert!(from_password("a@example.com", "short").is_err());
    }

    #[test]
    fn wrap_and_seal_round_trip_and_refuse_tampering() {
        let kek = random_bytes::<32>();
        let dek = random_bytes::<32>();
        let w = wrap_key(&dek, &kek, "password");
        assert_eq!(*unwrap_key(&w, &kek, "password").unwrap(), dek);
        assert!(unwrap_key(&w, &kek, "recovery").is_err());
        let v = serde_json::json!({"v": 1, "rows": [{"t": "x", "r": {"id": "a"}}]});
        let s = seal(&v, &dek, "artha/v1|o|d|1");
        assert_eq!(open(&s, &dek, "artha/v1|o|d|1").unwrap(), v);
        assert!(open(&s, &dek, "artha/v1|o|d|2").is_err());
        assert!(open("not base64!", &dek, "x").is_err());
    }

    #[test]
    fn recovery_keys_read_back_however_they_are_typed() {
        let k = new_recovery_key();
        assert_eq!(k.len(), 52 + 12);
        let a = recovery_kek(&k).unwrap();
        let typed = k.to_lowercase().replace('-', " ").replace('0', "o");
        assert_eq!(*recovery_kek(&typed).unwrap(), *a);
        assert!(recovery_kek("ABC").is_err());
        assert!(recovery_kek("!!!!").is_err());
    }
}
