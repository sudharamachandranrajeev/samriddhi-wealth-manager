//! The HTTP API of the Brahma sync server (brahma/server: at home on Node,
//! or the Cloudflare Worker), as brahma_core's `WorkerApi`.

use std::time::Duration;

use serde_json::{Value, json};
use url::Url;

use crate::SyncError;
use crate::links::validate_server_url;

/// A wrapped data key, as the server keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRecord {
    pub wrapped_password: String,
    pub wrapped_recovery: String,
}

/// One stored change of a device's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteChange {
    pub seq: i64,
    pub payload: String,
}

/// The server side of sync, reduced to an append-only log per device.
pub trait Remote {
    /// Stores change `seq` of `device`. False when that slot already exists.
    fn push(&mut self, device: &str, seq: i64, payload: &str) -> Result<bool, SyncError>;
    /// The stored payload of one change, or None.
    fn fetch(&mut self, device: &str, seq: i64) -> Result<Option<String>, SyncError>;
    /// Highest stored seq of `device` (0 if none).
    fn last_seq(&mut self, device: &str) -> Result<i64, SyncError>;
    /// Every registered device of this account.
    fn devices(&mut self) -> Result<Vec<String>, SyncError>;
    /// Changes of `device` after `after`, oldest first.
    fn pull(&mut self, device: &str, after: i64) -> Result<Vec<RemoteChange>, SyncError>;
}

/// What a sync server says about itself (`/api/health`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub needs_setup: bool,
    pub home: bool,
    pub name: String,
    pub version: String,
}

pub struct WorkerApi {
    pub server: Url,
    pub info: ServerInfo,
    client: reqwest::blocking::Client,
    token: Option<String>,
}

/// A blocking HTTP client with rustls (ring) and the platform's roots.
pub fn default_client() -> Result<reqwest::blocking::Client, SyncError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SyncError::Message(format!("Could not start the network client ({e})")))
}

fn unreachable() -> SyncError {
    SyncError::Message("Sync server unreachable".into())
}

impl WorkerApi {
    /// Asks the server at `server` what it is. Only Brahma sync servers are
    /// spoken to (PocketBase is not supported in Rust).
    pub fn connect(
        server: &str,
        client: Option<reqwest::blocking::Client>,
    ) -> Result<WorkerApi, SyncError> {
        let url = validate_server_url(server)?;
        let client = match client {
            Some(c) => c,
            None => default_client()?,
        };
        let res = client
            .get(url.join("/api/health").map_err(|_| unreachable())?)
            .timeout(Duration::from_secs(20))
            .send()
            .map_err(|_| unreachable())?;
        let body: Value = if res.status().as_u16() == 200 {
            serde_json::from_str(&res.text().unwrap_or_default()).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        if body["service"] != "brahma-sync" {
            return Err(SyncError::Message(
                "That address is not a Brahma sync server".into(),
            ));
        }
        let text = |k: &str| match &body[k] {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            v => v.to_string(),
        };
        Ok(WorkerApi {
            info: ServerInfo {
                needs_setup: body["needsSetup"] == true,
                home: body["kind"] == "home",
                name: text("name"),
                version: text("version"),
            },
            server: url,
            client,
            token: None,
        })
    }

    /// Whether a login is held and good for at least another minute.
    pub fn signed_in(&self) -> bool {
        let exp = self
            .token
            .as_deref()
            .and_then(|t| t.split('.').nth(1))
            .and_then(|e| e.parse::<i64>().ok());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        exp.is_some_and(|e| e > now + 60)
    }

    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        query: &[(&str, String)],
        auth: bool,
        allow: &[u16],
    ) -> Result<(u16, Value), SyncError> {
        let mut url = self.server.join(path).map_err(|_| unreachable())?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let mut req = self
            .client
            .request(method, url)
            .header("content-type", "application/json");
        if auth && let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let res = req.send().map_err(|_| unreachable())?;
        let status = res.status().as_u16();
        let text = res.text().unwrap_or_default();
        let data: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status >= 400 && !allow.contains(&status) {
            return Err(SyncError::Message(match data["message"].as_str() {
                Some(m) => m.to_string(),
                None => format!("Sync server error {status}"),
            }));
        }
        Ok((status, data))
    }

    fn session(&mut self, r: (u16, Value)) -> Result<String, SyncError> {
        let (token, user) = (r.1["token"].as_str(), r.1["userId"].as_str());
        match (token, user) {
            (Some(t), Some(u)) => {
                self.token = Some(t.to_string());
                Ok(u.to_string())
            }
            _ => Err(SyncError::Message("The sync server sent no session".into())),
        }
    }

    /// Creates the account (or finishes one that stopped half way). Returns
    /// the user id.
    pub fn register(
        &mut self,
        email: &str,
        secret: &str,
        invite: &str,
    ) -> Result<String, SyncError> {
        let r = self.call(
            reqwest::Method::POST,
            "/api/register",
            Some(json!({"email": email, "secret": secret, "invite": invite})),
            &[],
            false,
            &[],
        )?;
        self.session(r)
    }

    /// Signs in. Returns the user id.
    pub fn login(&mut self, email: &str, secret: &str) -> Result<String, SyncError> {
        let r = self.call(
            reqwest::Method::POST,
            "/api/login",
            Some(json!({"email": email, "secret": secret})),
            &[],
            false,
            &[],
        )?;
        self.session(r)
    }

    pub fn vault(&self) -> Result<Option<VaultRecord>, SyncError> {
        let (status, r) = self.call(reqwest::Method::GET, "/api/vault", None, &[], true, &[404])?;
        if status == 404 {
            return Ok(None);
        }
        match (r["wrappedPassword"].as_str(), r["wrappedRecovery"].as_str()) {
            (Some(p), Some(q)) => Ok(Some(VaultRecord {
                wrapped_password: p.into(),
                wrapped_recovery: q.into(),
            })),
            _ => Err(SyncError::Message(
                "The sync server sent a damaged vault".into(),
            )),
        }
    }

    pub fn create_vault(&self, v: &VaultRecord) -> Result<(), SyncError> {
        self.call(
            reqwest::Method::POST,
            "/api/vault",
            Some(json!({"wrappedPassword": v.wrapped_password, "wrappedRecovery": v.wrapped_recovery})),
            &[],
            true,
            &[],
        )
        .map(drop)
    }

    pub fn rewrap_vault(&self, wrapped_password: &str) -> Result<(), SyncError> {
        self.call(
            reqwest::Method::PUT,
            "/api/vault",
            Some(json!({"wrappedPassword": wrapped_password})),
            &[],
            true,
            &[],
        )
        .map(drop)
    }

    pub fn add_device(&self, device: &str, platform: &str) -> Result<(), SyncError> {
        self.call(
            reqwest::Method::POST,
            "/api/devices",
            Some(json!({"device": device, "platform": platform})),
            &[],
            true,
            &[],
        )
        .map(drop)
    }

    /// The pairing record: (request, response), each empty until written;
    /// None when it is gone (expired, used or cancelled).
    pub fn pairing(&self, id: &str) -> Result<Option<(String, String)>, SyncError> {
        let (status, r) = self.call(
            reqwest::Method::GET,
            &format!("/api/pairings/{id}"),
            None,
            &[],
            false,
            &[404],
        )?;
        if status == 404 {
            return Ok(None);
        }
        let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
        Ok(Some((s("request"), s("response"))))
    }

    /// False when the record is gone.
    pub fn write_request(&self, id: &str, sealed: &str) -> Result<bool, SyncError> {
        let (status, _) = self.call(
            reqwest::Method::PUT,
            &format!("/api/pairings/{id}/request"),
            Some(json!({"request": sealed})),
            &[],
            false,
            &[404],
        )?;
        Ok(status != 404)
    }

    pub fn open_pairing(&self) -> Result<String, SyncError> {
        let (_, r) = self.call(reqwest::Method::POST, "/api/pairings", None, &[], true, &[])?;
        r["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| SyncError::Message("The sync server sent no pairing id".into()))
    }

    pub fn write_response(&self, id: &str, sealed: &str) -> Result<bool, SyncError> {
        let (status, _) = self.call(
            reqwest::Method::PUT,
            &format!("/api/pairings/{id}/response"),
            Some(json!({"response": sealed})),
            &[],
            true,
            &[404],
        )?;
        Ok(status != 404)
    }

    pub fn close_pairing(&self, id: &str) -> Result<(), SyncError> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/api/pairings/{id}"),
            None,
            &[],
            true,
            &[404],
        )
        .map(drop)
    }
}

impl Remote for WorkerApi {
    fn push(&mut self, device: &str, seq: i64, payload: &str) -> Result<bool, SyncError> {
        let (status, _) = self.call(
            reqwest::Method::POST,
            "/api/changes",
            Some(json!({"device": device, "seq": seq, "payload": payload})),
            &[],
            true,
            &[409],
        )?;
        Ok(status != 409)
    }

    fn fetch(&mut self, device: &str, seq: i64) -> Result<Option<String>, SyncError> {
        let (status, r) = self.call(
            reqwest::Method::GET,
            "/api/changes/one",
            None,
            &[("device", device.into()), ("seq", seq.to_string())],
            true,
            &[404],
        )?;
        Ok(if status == 404 {
            None
        } else {
            r["payload"].as_str().map(str::to_string)
        })
    }

    fn last_seq(&mut self, device: &str) -> Result<i64, SyncError> {
        let (_, r) = self.call(
            reqwest::Method::GET,
            "/api/changes/last",
            None,
            &[("device", device.into())],
            true,
            &[],
        )?;
        r["seq"]
            .as_i64()
            .ok_or_else(|| SyncError::Message("The sync server sent a damaged reply".into()))
    }

    fn devices(&mut self) -> Result<Vec<String>, SyncError> {
        let (_, r) = self.call(reqwest::Method::GET, "/api/devices", None, &[], true, &[])?;
        Ok(r["devices"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn pull(&mut self, device: &str, after: i64) -> Result<Vec<RemoteChange>, SyncError> {
        let (_, r) = self.call(
            reqwest::Method::GET,
            "/api/changes",
            None,
            &[
                ("device", device.into()),
                ("after", after.to_string()),
                ("limit", "50".into()),
            ],
            true,
            &[],
        )?;
        let items = r["items"]
            .as_array()
            .ok_or_else(|| SyncError::Message("The sync server sent a damaged reply".into()))?;
        items
            .iter()
            .map(|x| match (x["seq"].as_i64(), x["payload"].as_str()) {
                (Some(seq), Some(p)) => Ok(RemoteChange {
                    seq,
                    payload: p.to_string(),
                }),
                _ => Err(SyncError::Message(
                    "The sync server sent a damaged reply".into(),
                )),
            })
            .collect()
    }
}
