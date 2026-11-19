//! Live: the real Brahma sync server (brahma/server/src/home.ts, Node 24+)
//! on loopback. Skipped (with a note) when Node or the server is missing.
//! The server is found at $BRAHMA_SERVER_TS, else at ../brahma/server/src/home.ts
//! next to this workspace.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use brahma_sync::api::Remote;
use brahma_sync::crypto;
use brahma_sync::links::{BrahmaLink, moved_link};
use brahma_sync::{Account, MemorySecretStore, SyncError, SyncStore, Tables, WorkerApi};
use serde_json::{Map, Value, json};

const WEALTH: &str = "bridge_wealth_snapshot";
const MONEY: &str = "bridge_money_snapshot";
const EMAIL: &str = "me@example.com";
const PASSWORD: &str = "correct horse battery";

struct Server {
    dir: tempfile::TempDir,
    child: Child,
    url: String,
    setup: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn home_ts() -> Option<PathBuf> {
    let p = std::env::var_os("BRAHMA_SERVER_TS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../brahma/server/src/home.ts")
        });
    let node = Command::new("node").arg("--version").output().ok()?;
    let v = String::from_utf8_lossy(&node.stdout);
    let major: u32 = v
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()?;
    (major >= 24 && p.exists()).then_some(p)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts a server on `dir` (set up there first when `init`).
fn start(home: &Path, dir: tempfile::TempDir, init: bool) -> Server {
    let port = free_port();
    if init {
        let ok = Command::new("node")
            .args([home.to_str().unwrap(), "init", &port.to_string()])
            .env("BRAHMA_SERVER_HOME", dir.path())
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(ok.success());
    }
    // Loopback only, on a fresh port.
    let env_file = dir.path().join("server.env");
    let text = std::fs::read_to_string(&env_file).unwrap();
    let text: String = text
        .lines()
        .map(|l| {
            if l.starts_with("HOST=") {
                "HOST=127.0.0.1".to_string()
            } else if l.starts_with("PORT=") {
                format!("PORT={port}")
            } else {
                l.to_string()
            }
        })
        .filter(|l| !l.starts_with("RATE_LIMIT_SCALE="))
        .collect::<Vec<_>>()
        .join("\n");
    // Lift the rate limits for this throwaway server only, as Artha's live
    // tests do; the server's own defaults are unchanged.
    let text = text + "\nRATE_LIMIT_SCALE=1000";
    std::fs::write(&env_file, text.clone() + "\n").unwrap();
    let setup = text
        .lines()
        .find_map(|l| l.strip_prefix("SETUP_CODE="))
        .unwrap_or("")
        .to_string();
    let mut child = Command::new("node")
        .args([home.to_str().unwrap(), "serve"])
        .env("BRAHMA_SERVER_HOME", dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let started = Instant::now();
    let mut line = String::new();
    while !line.contains("listening") {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "the server stopped");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the server did not start"
        );
    }
    std::thread::spawn(move || for _ in out.lines() {});
    Server {
        dir,
        child,
        url: format!("http://127.0.0.1:{port}"),
        setup,
    }
}

fn store(write: &[&str]) -> SyncStore {
    SyncStore::memory(Tables::new(&[MONEY, WEALTH], write)).unwrap()
}

fn account() -> Account<MemorySecretStore> {
    Account::new(MemorySecretStore::default(), "samriddhi", "linux")
}

fn sync(a: &mut Account<MemorySecretStore>, s: &mut SyncStore) -> brahma_sync::SyncResult {
    a.engine(s).unwrap().expect("signed in").run().unwrap()
}

fn vals(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

/// Ignored by default: an application firewall (OpenSnitch here) can hold
/// loopback connections from freshly built test binaries until allowed. Run
/// with `cargo test -p brahma-sync --test live -- --ignored`.
#[test]
#[ignore = "needs loopback allowed for test binaries; run with --ignored"]
fn rust_devices_sync_pair_recover_and_follow_a_moved_server() {
    let Some(home) = home_ts() else {
        eprintln!("skipped: needs Node 24+ and the Brahma server (set BRAHMA_SERVER_TS)");
        return;
    };
    let s1 = start(&home, tempfile::tempdir().unwrap(), true);

    // A makes the account; B signs in to it with the same e-mail and password.
    let (mut a, mut a_store) = (account(), store(&[WEALTH]));
    let recovery = a
        .sign_up(
            &s1.url,
            "Me@Example.com ",
            PASSWORD,
            &s1.setup,
            a_store.device_id(),
        )
        .unwrap();
    let (mut b, mut b_store) = (account(), store(&[MONEY]));
    b.sign_in(&s1.url, EMAIL, PASSWORD, b_store.device_id())
        .unwrap();
    assert!(b.signed_in().unwrap());

    a_store
        .put(
            WEALTH,
            "samriddhi.wealth",
            vals(json!({"source": "samriddhi", "snapshot": "{\"v\":1}", "updated": "t1"})),
        )
        .unwrap();
    assert_eq!(sync(&mut a, &mut a_store).pushed, 1);
    b_store
        .put(
            MONEY,
            "artha.money",
            vals(json!({"source": "artha", "snapshot": "{\"v\":1}", "updated": "t1"})),
        )
        .unwrap();
    let r = sync(&mut b, &mut b_store);
    assert_eq!((r.pulled, r.pushed), (1, 1));
    assert_eq!(sync(&mut a, &mut a_store).pulled, 1);
    assert_eq!(a_store.rows(MONEY).unwrap()[0].text("source"), "artha");
    assert_eq!(b_store.rows(WEALTH).unwrap()[0].text("updated"), "t1");

    // C joins by pairing with A: no password typed, the codes match.
    let link = a.offer_pairing("samriddhi").unwrap();
    let BrahmaLink::Pair(parsed) = BrahmaLink::parse(&link.to_string()).unwrap() else {
        panic!("not a pairing link")
    };
    let (mut c, mut c_store) = (account(), store(&[]));
    let ticket = c.request_join(&parsed, "Test tablet").unwrap();
    let request = a.pairing_request(&link).unwrap().expect("a request");
    assert_eq!(request.name, "Test tablet");
    assert_eq!(
        brahma_sync::pairing::code(&link, &request.public_key),
        ticket.code
    );
    assert!(c.join_grant(&ticket).unwrap().is_none(), "not approved yet");
    a.approve_pairing(&link, &request).unwrap();
    let grant = c.join_grant(&ticket).unwrap().expect("approved");
    c.join(&ticket, &grant, c_store.device_id()).unwrap();
    assert_eq!(sync(&mut c, &mut c_store).pulled, 2);

    // After a password reset the vault no longer opens with the password:
    // the recovery key unlocks it once and re-wraps the data key.
    {
        let keys = crypto::from_password(EMAIL, PASSWORD).unwrap();
        let mut api = WorkerApi::connect(&s1.url, None).unwrap();
        api.login(EMAIL, &keys.auth_secret).unwrap();
        let other = crypto::random_bytes::<32>();
        let dek = a.data_key().unwrap().unwrap();
        api.rewrap_vault(&crypto::wrap_key(dek.as_ref(), &other, "password"))
            .unwrap();
    }
    let (mut d, d_store) = (account(), store(&[]));
    assert!(matches!(
        d.sign_in(&s1.url, EMAIL, PASSWORD, d_store.device_id()),
        Err(SyncError::RecoveryKeyNeeded)
    ));
    assert!(
        d.unlock_with_recovery_key("0000-0000", d_store.device_id())
            .is_err()
    );
    d.unlock_with_recovery_key(&recovery.to_lowercase(), d_store.device_id())
        .unwrap();
    let (mut e, e_store) = (account(), store(&[]));
    e.sign_in(&s1.url, EMAIL, PASSWORD, e_store.device_id())
        .unwrap();
    assert!(matches!(
        e.sign_in(&s1.url, EMAIL, "a wrong password!", e_store.device_id()),
        Err(SyncError::Message(m)) if m.contains("Wrong")
    ));

    // The server moves (its data and signing key copied, as Adisthanam's
    // move-out does). A follows the moved link and keeps syncing; a server
    // that does not hold this account is refused.
    let mut s1 = s1;
    let _ = s1.child.kill();
    let _ = s1.child.wait();
    let dir2 = tempfile::tempdir().unwrap();
    for f in ["server.env", "brahma.db", "brahma.db-wal", "brahma.db-shm"] {
        if s1.dir.path().join(f).exists() {
            std::fs::copy(s1.dir.path().join(f), dir2.path().join(f)).unwrap();
        }
    }
    let s2 = start(&home, dir2, false);
    let stranger = start(&home, tempfile::tempdir().unwrap(), true);
    let err = a.move_server(&stranger.url, &[&a_store]).unwrap_err();
    assert!(
        err.to_string().contains("doesn't know your account"),
        "{err}"
    );
    let BrahmaLink::Moved { server } =
        BrahmaLink::parse(&moved_link(&url::Url::parse(&s2.url).unwrap())).unwrap()
    else {
        panic!("not a moved link")
    };
    a.move_server(server.as_str(), &[&a_store]).unwrap();
    assert_eq!(a.session().unwrap().unwrap().server, s2.url);
    a_store
        .put(
            WEALTH,
            "samriddhi.wealth",
            vals(json!({"source": "samriddhi", "snapshot": "{\"v\":1}", "updated": "t2"})),
        )
        .unwrap();
    assert_eq!(sync(&mut a, &mut a_store).pushed, 1);
    b.move_server(&s2.url, &[&b_store]).unwrap();
    sync(&mut b, &mut b_store);
    assert_eq!(b_store.rows(WEALTH).unwrap()[0].text("updated"), "t2");
    let mut api = WorkerApi::connect(&s2.url, None).unwrap();
    let keys = crypto::from_password(EMAIL, PASSWORD).unwrap();
    api.login(EMAIL, &keys.auth_secret).unwrap();
    assert_eq!(api.last_seq(a_store.device_id()).unwrap(), 2);
}
