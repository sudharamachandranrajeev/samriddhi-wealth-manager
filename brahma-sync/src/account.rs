//! The sync account on this device, as brahma_core's `AccountService` and
//! `KeyVault`. The password never leaves this module: the server gets a
//! derived login secret, and the data key is only stored wrapped (on the
//! server) or in the device's secret store (here).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::SyncError;
use crate::api::{Remote, VaultRecord, WorkerApi};
use crate::crypto::{self, Key};
use crate::engine::SyncEngine;
use crate::links::{PairingLink, server_text};
use crate::pairing::{self, JoinRequest, JoinTicket, PairingGrant};
use crate::store::SyncStore;

/// Where secrets live: the OS keyring or Android Keystore in the app,
/// memory in tests.
pub trait SecretStore {
    fn read(&self, key: &str) -> Result<Option<String>, SyncError>;
    fn write(&self, key: &str, value: &str) -> Result<(), SyncError>;
    fn delete(&self, key: &str) -> Result<(), SyncError>;
}

#[derive(Default)]
pub struct MemorySecretStore(pub std::sync::Mutex<std::collections::HashMap<String, String>>);

impl SecretStore for MemorySecretStore {
    fn read(&self, key: &str) -> Result<Option<String>, SyncError> {
        Ok(self.0.lock().expect("not poisoned").get(key).cloned())
    }
    fn write(&self, key: &str, value: &str) -> Result<(), SyncError> {
        self.0
            .lock()
            .expect("not poisoned")
            .insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), SyncError> {
        self.0.lock().expect("not poisoned").remove(key);
        Ok(())
    }
}

/// Server, account and login secret of the signed-in account.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    pub server: String,
    pub email: String,
    pub user_id: String,
    pub secret: String,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server", &self.server)
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// Signed in, but the password no longer opens the vault (it was reset):
/// the recovery key is needed once to re-wrap the data key.
pub const RECOVERY_KEY_NEEDED: &str = "Enter your recovery key to unlock your synced data";

struct Pending {
    api: WorkerApi,
    kek: Zeroizing<Key>,
    email: String,
    secret: String,
    owner: String,
}

pub struct Account<S: SecretStore> {
    pub secrets: S,
    /// Prefix of this app's secrets (`samriddhi` → `samriddhi.sync.dek`).
    pub app: String,
    pub platform: String,
    client: Option<reqwest::blocking::Client>,
    api: Option<WorkerApi>,
    pending: Option<Pending>,
}

const PASSWORD: &str = "password";
const RECOVERY: &str = "recovery";

impl<S: SecretStore> Account<S> {
    pub fn new(secrets: S, app: &str, platform: &str) -> Self {
        Account {
            secrets,
            app: app.into(),
            platform: platform.into(),
            client: None,
            api: None,
            pending: None,
        }
    }

    /// Use this HTTP client (e.g. one that trusts bundled roots on Android).
    pub fn with_client(mut self, client: reqwest::blocking::Client) -> Self {
        self.client = Some(client);
        self
    }

    fn connect(&self, server: &str) -> Result<WorkerApi, SyncError> {
        WorkerApi::connect(server, self.client.clone())
    }

    fn dek_key(&self) -> String {
        format!("{}.sync.dek", self.app)
    }
    fn session_key(&self) -> String {
        format!("{}.sync.session", self.app)
    }

    pub fn session(&self) -> Result<Option<Session>, SyncError> {
        let Some(v) = self.secrets.read(&self.session_key())? else {
            return Ok(None);
        };
        let v: Value = serde_json::from_str(&v)?;
        let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
        Ok(Some(Session {
            server: s("server"),
            email: s("email"),
            user_id: s("userId"),
            secret: s("secret"),
        }))
    }

    fn set_session(&self, s: &Session) -> Result<(), SyncError> {
        self.secrets.write(
            &self.session_key(),
            &json!({"server": s.server, "email": s.email, "userId": s.user_id, "secret": s.secret})
                .to_string(),
        )
    }

    pub fn data_key(&self) -> Result<Option<Zeroizing<Key>>, SyncError> {
        Ok(self
            .secrets
            .read(&self.dek_key())?
            .and_then(|v| B64.decode(v).ok())
            .and_then(|v| <Key>::try_from(v).ok())
            .map(Zeroizing::new))
    }

    pub fn signed_in(&self) -> Result<bool, SyncError> {
        Ok(self.session()?.is_some() && self.data_key()?.is_some())
    }

    /// Creates the account and its vault; returns the recovery key, shown
    /// once. (Samriddhi signs in to an account another app made; this is
    /// here for tests and parity with core.)
    pub fn sign_up(
        &mut self,
        server: &str,
        email: &str,
        password: &str,
        invite: &str,
        device: &str,
    ) -> Result<String, SyncError> {
        let keys = crypto::from_password(email, password)?;
        let mail = email.trim().to_lowercase();
        let mut api = self.connect(server)?;
        let owner = api.register(&mail, &keys.auth_secret, invite)?;
        if api.vault()?.is_some() {
            return Err(SyncError::Message(
                "This e-mail already has an account: sign in instead".into(),
            ));
        }
        let dek = Zeroizing::new(crypto::random_bytes::<32>());
        let recovery = crypto::new_recovery_key();
        api.create_vault(&VaultRecord {
            wrapped_password: crypto::wrap_key(dek.as_ref(), &keys.kek, PASSWORD),
            wrapped_recovery: crypto::wrap_key(
                dek.as_ref(),
                &*crypto::recovery_kek(&recovery)?,
                RECOVERY,
            ),
        })?;
        self.finish(api, &mail, &keys.auth_secret, &owner, &dek, device)?;
        Ok(recovery)
    }

    /// Signs in with the account's e-mail and password. Fails with
    /// [`RECOVERY_KEY_NEEDED`] when the vault was wrapped under an older
    /// password; then call [`Account::unlock_with_recovery_key`].
    pub fn sign_in(
        &mut self,
        server: &str,
        email: &str,
        password: &str,
        device: &str,
    ) -> Result<(), SyncError> {
        let keys = crypto::from_password(email, password)?;
        let mail = email.trim().to_lowercase();
        let mut api = self.connect(server)?;
        let owner = api.login(&mail, &keys.auth_secret)?;
        let Some(v) = api.vault()? else {
            return Err(SyncError::Message(
                "Account setup did not finish: sign up again in the app that made it".into(),
            ));
        };
        match crypto::unwrap_key(&v.wrapped_password, &keys.kek, PASSWORD) {
            Ok(dek) => self.finish(api, &mail, &keys.auth_secret, &owner, &dek, device),
            Err(_) => {
                self.pending = Some(Pending {
                    api,
                    kek: keys.kek,
                    email: mail,
                    secret: keys.auth_secret,
                    owner,
                });
                Err(SyncError::RecoveryKeyNeeded)
            }
        }
    }

    /// After [`SyncError::RecoveryKeyNeeded`]: opens the vault with the
    /// recovery key and re-wraps the data key under the current password.
    pub fn unlock_with_recovery_key(
        &mut self,
        recovery_key: &str,
        device: &str,
    ) -> Result<(), SyncError> {
        let Some(p) = self.pending.take() else {
            return Err(SyncError::Message("Sign in first".into()));
        };
        let v = p
            .api
            .vault()?
            .ok_or_else(|| SyncError::Message("The account has no vault".into()))?;
        let dek = match crypto::recovery_kek(recovery_key)
            .and_then(|k| crypto::unwrap_key(&v.wrapped_recovery, &k, RECOVERY))
        {
            Ok(d) => d,
            Err(e) => {
                self.pending = Some(p);
                return Err(e.into());
            }
        };
        p.api
            .rewrap_vault(&crypto::wrap_key(dek.as_ref(), &p.kek, PASSWORD))?;
        self.finish(p.api, &p.email, &p.secret, &p.owner, &dek, device)
    }

    /// On the signed-in device: opens a pairing record and returns the link
    /// to show as a QR code.
    pub fn offer_pairing(&mut self, scheme: &str) -> Result<PairingLink, SyncError> {
        let s = self
            .session()?
            .ok_or_else(|| SyncError::Message("Not signed in".into()))?;
        let api = self.signed_in_api(&s)?;
        Ok(PairingLink {
            id: api.open_pairing()?,
            server: api.server.clone(),
            secret: crypto::random_bytes::<32>(),
            scheme: scheme.into(),
        })
    }

    /// The request waiting on `link`, or None while there is none.
    pub fn pairing_request(
        &mut self,
        link: &PairingLink,
    ) -> Result<Option<JoinRequest>, SyncError> {
        let s = self
            .session()?
            .ok_or_else(|| SyncError::Message("Not signed in".into()))?;
        match self.signed_in_api(&s)?.pairing(&link.id)? {
            None => Err(SyncError::Message(
                "This code has expired. Make a new one.".into(),
            )),
            Some((request, _)) if request.is_empty() => Ok(None),
            Some((request, _)) => Ok(Some(pairing::open_request(link, &request)?)),
        }
    }

    /// Sends this account's keys to the device that made `request`.
    pub fn approve_pairing(
        &mut self,
        link: &PairingLink,
        request: &JoinRequest,
    ) -> Result<(), SyncError> {
        let (Some(s), Some(dek)) = (self.session()?, self.data_key()?) else {
            return Err(SyncError::Message("Not signed in".into()));
        };
        let grant = PairingGrant {
            email: s.email.clone(),
            user_id: s.user_id.clone(),
            secret: s.secret.clone(),
            data_key: dek,
        };
        let sealed = pairing::seal_grant(link, &request.public_key, &grant)?;
        if !self.signed_in_api(&s)?.write_response(&link.id, &sealed)? {
            return Err(SyncError::Message(
                "This code has expired. Make a new one.".into(),
            ));
        }
        Ok(())
    }

    /// On a new device: asks to join through `link`. Show the ticket's code;
    /// it must match the one on the other device.
    pub fn request_join(
        &mut self,
        link: &PairingLink,
        name: &str,
    ) -> Result<JoinTicket, SyncError> {
        if self.session()?.is_some() {
            return Err(SyncError::Message(
                "This device already syncs. Sign out first.".into(),
            ));
        }
        let secret = pairing::new_secret();
        let public_key = pairing::public_key(&secret);
        let sealed = pairing::seal_request(
            link,
            &JoinRequest {
                name: name.into(),
                platform: self.platform.clone(),
                public_key,
            },
        );
        let api = self.connect(&server_text(&link.server))?;
        if !api.write_request(&link.id, &sealed)? {
            return Err(SyncError::Message(
                "This code has expired or was already used. Make a new one on your other device."
                    .into(),
            ));
        }
        Ok(JoinTicket {
            link: link.clone(),
            code: pairing::code(link, &public_key),
            secret,
        })
    }

    /// The account the other device sent, once it approved; None while waiting.
    pub fn join_grant(&self, ticket: &JoinTicket) -> Result<Option<PairingGrant>, SyncError> {
        let api = self.connect(&server_text(&ticket.link.server))?;
        match api.pairing(&ticket.link.id)? {
            None => Err(SyncError::Message(
                "The other device declined, or the code expired.".into(),
            )),
            Some((_, response)) if response.is_empty() => Ok(None),
            Some((_, response)) => Ok(Some(pairing::open_grant(
                &ticket.link,
                &ticket.secret,
                &response,
            )?)),
        }
    }

    /// Signs this device in with `grant` and closes the pairing.
    pub fn join(
        &mut self,
        ticket: &JoinTicket,
        grant: &PairingGrant,
        device: &str,
    ) -> Result<(), SyncError> {
        let mut api = self.connect(&server_text(&ticket.link.server))?;
        let owner = api.login(&grant.email, &grant.secret)?;
        if owner != grant.user_id || api.vault()?.is_none() {
            return Err(SyncError::Message(
                "The other device sent keys for an account this server does not know".into(),
            ));
        }
        let _ = api.close_pairing(&ticket.link.id);
        self.finish(
            api,
            &grant.email,
            &grant.secret,
            &owner,
            &grant.data_key,
            device,
        )
    }

    /// A sync engine for `store`, or None when signed out. Ask for one per
    /// sync run: it signs in again when the server token expired. Each
    /// database registers its own change log once per server.
    pub fn engine<'a>(
        &mut self,
        store: &'a mut SyncStore,
    ) -> Result<Option<SyncEngine<'a, WorkerApi>>, SyncError> {
        let (Some(s), Some(dek)) = (self.session()?, self.data_key()?) else {
            return Ok(None);
        };
        let platform = self.platform.clone();
        let api = self.signed_in_api(&s)?;
        if store.local_setting("sync.registered")?.as_deref() != Some(s.server.as_str()) {
            api.add_device(store.device_id(), &platform)?;
            store.set_local_setting("sync.registered", &s.server)?;
        }
        let api = self.api.take().expect("signed_in_api kept it");
        // The engine owns this connection; the next run makes a new one.
        Ok(Some(SyncEngine::new(store, api, *dek, &s.user_id)))
    }

    /// Follows the account to a server that moved, staying signed in. The
    /// new server must hold this same account and every change `stores`
    /// already sent, so a wrong or stale address changes nothing.
    pub fn move_server(&mut self, server: &str, stores: &[&SyncStore]) -> Result<(), SyncError> {
        let (Some(s), Some(_)) = (self.session()?, self.data_key()?) else {
            return Err(SyncError::Message("Not signed in".into()));
        };
        let mut api = self.connect(server)?;
        let new_server = server_text(&api.server);
        if new_server == s.server {
            return Err(SyncError::Message(
                "This device already uses that server".into(),
            ));
        }
        let owner = api.login(&s.email, &s.secret).map_err(|_| {
            SyncError::Message(
                "That server doesn't know your account. Check the address, or move the server again".into(),
            )
        })?;
        if owner != s.user_id || api.vault()?.is_none() {
            return Err(SyncError::Message(
                "That server has a different account with your e-mail, not the one that moved"
                    .into(),
            ));
        }
        for store in stores {
            let sent = store.int_setting("sync.sent")?;
            if api.last_seq(store.device_id())? < sent {
                return Err(SyncError::Message(
                    "That server is missing changes this device already sent: it may have come from an older \
                     backup. Move it again with move-out, so nothing is lost"
                        .into(),
                ));
            }
        }
        self.set_session(&Session {
            server: new_server,
            ..s
        })?;
        self.api = Some(api);
        Ok(())
    }

    pub fn sign_out(&mut self) -> Result<(), SyncError> {
        self.api = None;
        self.pending = None;
        self.secrets.delete(&self.dek_key())?;
        self.secrets.delete(&self.session_key())
    }

    fn signed_in_api(&mut self, s: &Session) -> Result<&mut WorkerApi, SyncError> {
        if self
            .api
            .as_ref()
            .is_none_or(|a| server_text(&a.server) != s.server)
        {
            self.api = Some(self.connect(&s.server)?);
        }
        let api = self.api.as_mut().expect("just set");
        if !api.signed_in() {
            api.login(&s.email, &s.secret)?;
        }
        Ok(api)
    }

    fn finish(
        &mut self,
        api: WorkerApi,
        mail: &str,
        secret: &str,
        owner: &str,
        dek: &Key,
        device: &str,
    ) -> Result<(), SyncError> {
        api.add_device(device, &self.platform)?;
        self.secrets.write(&self.dek_key(), &B64.encode(dek))?;
        self.set_session(&Session {
            server: server_text(&api.server),
            email: mail.into(),
            user_id: owner.into(),
            secret: secret.into(),
        })?;
        self.api = Some(api);
        self.pending = None;
        Ok(())
    }
}
