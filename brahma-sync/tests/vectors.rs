//! Cross-language test vectors. brahma core's test/sync_vectors_test.dart
//! writes `sync-vectors-dart.json` (read here); this test writes
//! `sync-vectors-rust.json`, which that Dart test reads. Copy each file to
//! the other repo when it changes (`UPDATE_FIXTURES=1 cargo test`).
//! Every value is synthetic.

use std::path::PathBuf;

use brahma_sync::crypto::{self, hex, unhex};
use brahma_sync::hlc::HlcClock;
use brahma_sync::links::{BrahmaLink, moved_link};
use brahma_sync::pairing::{self, JoinRequest, PairingGrant};
use brahma_sync::snapshots::{MoneySnapshot, WealthSnapshot};
use serde_json::{Value, json};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn dart() -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture("sync-vectors-dart.json")).unwrap())
        .unwrap()
}

fn key(v: &Value) -> [u8; 32] {
    unhex(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

/// Replays the HLC steps of a vector file on this clock.
fn hlc_steps(steps: &Value) -> Vec<Value> {
    let now = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let n = now.clone();
    let mut clock = HlcClock::with_clock(
        "abc",
        Box::new(move || n.load(std::sync::atomic::Ordering::SeqCst)),
    );
    steps
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let (op, arg, at) = (
                s[0].as_str().unwrap(),
                s[1].as_str().unwrap(),
                s[2].as_i64().unwrap(),
            );
            now.store(at, std::sync::atomic::Ordering::SeqCst);
            if op == "tick" {
                json!(["tick", "", at, clock.tick()])
            } else {
                clock.receive(arg);
                json!(["receive", arg, at, ""])
            }
        })
        .collect()
}

#[test]
fn rust_reads_the_vectors_dart_wrote() {
    let v = dart();
    // Argon2id + HKDF give the same login secret and KEK.
    let keys =
        crypto::from_password(v["email"].as_str().unwrap(), v["pw"].as_str().unwrap()).unwrap();
    assert_eq!(keys.auth_secret, v["login"].as_str().unwrap());
    assert_eq!(hex(keys.kek.as_ref()), v["kek"].as_str().unwrap());
    let rk = crypto::recovery_kek(v["recoveryText"].as_str().unwrap()).unwrap();
    assert_eq!(hex(rk.as_ref()), v["recoveryKek"].as_str().unwrap());
    // The wrapped data key opens with both the password and recovery keys.
    let dek = key(&v["dek"]);
    assert_eq!(
        *crypto::unwrap_key(v["wrappedPw"].as_str().unwrap(), &keys.kek, "password").unwrap(),
        dek
    );
    assert_eq!(
        *crypto::unwrap_key(v["wrappedRecovery"].as_str().unwrap(), &rk, "recovery").unwrap(),
        dek
    );
    assert!(crypto::unwrap_key(v["wrappedPw"].as_str().unwrap(), &keys.kek, "recovery").is_err());
    // A change Dart sealed (gzip + XChaCha20-Poly1305) opens row for row, but
    // not at another place in the log.
    let aad = v["aad"].as_str().unwrap();
    assert_eq!(
        aad,
        format!(
            "artha/v1|{}|{}|{}",
            v["owner"].as_str().unwrap(),
            v["device"].as_str().unwrap(),
            v["seq"]
        )
    );
    let opened = crypto::open(v["payload"].as_str().unwrap(), &dek, aad).unwrap();
    assert_eq!(opened, json!({"v": 1, "rows": v["rows"]}));
    assert!(crypto::open(v["payload"].as_str().unwrap(), &dek, &format!("{aad}9")).is_err());
    // The same HLC steps give the same stamps.
    assert_eq!(Value::Array(hlc_steps(&v["hlc"])), v["hlc"]);
    // Pairing: the link reads, Dart's request opens, the codes agree, and
    // Dart's grant (sealed to a key whose seed both know) opens here.
    let p = &v["pairing"];
    let BrahmaLink::Pair(link) = BrahmaLink::parse(p["link"].as_str().unwrap()).unwrap() else {
        panic!("not a pairing link");
    };
    assert_eq!(link.to_string(), p["link"].as_str().unwrap());
    assert_eq!(hex(&link.secret), p["linkBytes"].as_str().unwrap());
    let request = pairing::open_request(&link, v["pairRequest"].as_str().unwrap()).unwrap();
    assert_eq!(request.name, "Vector phone");
    assert_eq!(
        hex(&request.public_key),
        p["requesterPub"].as_str().unwrap()
    );
    assert_eq!(
        hex(&pairing::public_key(&StaticSecret::from(key(
            &p["requesterSeed"]
        )))),
        p["requesterPub"].as_str().unwrap()
    );
    assert_eq!(
        pairing::code(&link, &request.public_key),
        p["code"].as_str().unwrap()
    );
    let recipient = StaticSecret::from(key(&p["recipientSeed"]));
    assert_eq!(
        hex(&pairing::public_key(&recipient)),
        p["recipientPub"].as_str().unwrap()
    );
    let grant = pairing::open_grant(&link, &recipient, v["pairGrant"].as_str().unwrap()).unwrap();
    let g = &p["grant"];
    assert_eq!(grant.email, g["email"].as_str().unwrap());
    assert_eq!(grant.user_id, g["userId"].as_str().unwrap());
    assert_eq!(grant.secret, g["login"].as_str().unwrap());
    assert_eq!(hex(grant.data_key.as_ref()), g["dek"].as_str().unwrap());
    // The moved link reads and prints the same.
    let BrahmaLink::Moved { server } =
        BrahmaLink::parse(v["moved"]["link"].as_str().unwrap()).unwrap()
    else {
        panic!("not a moved link");
    };
    assert_eq!(moved_link(&server), v["moved"]["link"].as_str().unwrap());
}

#[test]
fn rust_writes_vectors_dart_must_read() {
    let d = dart();
    let (email, password) = (d["email"].as_str().unwrap(), d["pw"].as_str().unwrap());
    let keys = crypto::from_password(email, password).unwrap();
    let dek: [u8; 32] = std::array::from_fn(|i| (i * 11 + 3) as u8);
    let recovery = "7KQ2-M9XD-0000-1111-2222-3333-4444-5555-6666-7777-8888-9999-AAAA";
    let rk = crypto::recovery_kek(recovery).unwrap();
    let owner = "u00000000000rust";
    let device = "f00df00df00df00df00df00df00df00d";
    let aad = format!("artha/v1|{owner}|{device}|3");
    let rows = json!([
        {"t": "bridge_wealth_snapshot", "r": {
            "id": "samriddhi.wealth", "hlc": format!("001763290000000-000000-{device}"), "deleted": 0,
            "source": "samriddhi", "snapshot": r#"{"v":1,"currency":"GBP"}"#, "updated": "2026-11-16T10:00:00Z"}},
        {"t": "entries", "r": {"id": "e2", "hlc": format!("001763290000001-000000-{device}"), "deleted": 0, "memo": "Chai ₹40 ✓"},
         "p": [{"id": "p2", "entry_id": "e2", "position": 0, "amount": 4000}]}
    ]);
    let BrahmaLink::Pair(link) = BrahmaLink::parse(d["pairing"]["link"].as_str().unwrap()).unwrap()
    else {
        panic!("not a pairing link");
    };
    let requester = StaticSecret::from(key(&d["pairing"]["requesterSeed"]));
    let requester_key = pairing::public_key(&requester);
    let recipient = StaticSecret::from(key(&d["pairing"]["recipientSeed"]));
    let grant = PairingGrant {
        email: "vector.person@example.com".into(),
        user_id: owner.into(),
        secret: keys.auth_secret.clone(),
        data_key: Zeroizing::new(dek),
    };
    let out = json!({
        "email": email,
        "pw": password,
        "login": keys.auth_secret,
        "kek": hex(keys.kek.as_ref()),
        "recoveryText": recovery,
        "recoveryKek": hex(rk.as_ref()),
        "dek": hex(&dek),
        "owner": owner,
        "device": device,
        "aad": aad,
        "rows": rows,
        "hlc": hlc_steps(&d["hlc"]),
        "pairing": {
            "link": link.to_string(),
            "id": link.id,
            "linkBytes": hex(&link.secret),
            "requesterPub": hex(&requester_key),
            "code": pairing::code(&link, &requester_key),
            "recipientSeed": d["pairing"]["recipientSeed"],
            "grant": {"email": grant.email, "userId": grant.user_id, "login": grant.secret, "dek": hex(&dek)},
        },
        "moved": {"link": moved_link(&url::Url::parse("https://sync.example.com").unwrap())},
        "wrappedPw": crypto::wrap_key(&dek, &keys.kek, "password"),
        "wrappedRecovery": crypto::wrap_key(&dek, &rk, "recovery"),
        "payload": crypto::seal(&json!({"v": 1, "rows": rows}), &dek, &aad),
        "pairRequest": pairing::seal_request(&link, &JoinRequest {
            name: "Vector laptop".into(), platform: "linux".into(), public_key: requester_key }),
        "pairGrant": pairing::seal_grant(&link, &pairing::public_key(&recipient), &grant).unwrap(),
    });
    let file = fixture("sync-vectors-rust.json");
    if std::env::var("UPDATE_FIXTURES").as_deref() == Ok("1") || !file.exists() {
        std::fs::write(&file, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
    // The file on disk still matches this code, and its ciphertexts open.
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    for k in [
        "login",
        "kek",
        "recoveryKek",
        "dek",
        "aad",
        "rows",
        "hlc",
        "pairing",
        "moved",
    ] {
        assert_eq!(saved[k], out[k], "{k}");
    }
    assert_eq!(
        *crypto::unwrap_key(saved["wrappedRecovery"].as_str().unwrap(), &rk, "recovery").unwrap(),
        dek
    );
    assert_eq!(
        crypto::open(saved["payload"].as_str().unwrap(), &dek, &aad).unwrap(),
        json!({"v": 1, "rows": rows})
    );
    let g = pairing::open_grant(&link, &recipient, saved["pairGrant"].as_str().unwrap()).unwrap();
    assert_eq!(*g.data_key, dek);
}

#[test]
fn snapshot_fixtures_read_and_encode_byte_for_byte_like_dart() {
    for name in ["money-snapshot.json", "wealth-snapshot.json"] {
        let text = std::fs::read_to_string(fixture(name)).unwrap();
        let text = text.trim();
        let again = if name.starts_with("money") {
            MoneySnapshot::parse(text).encode()
        } else {
            WealthSnapshot::parse(text).encode()
        };
        assert_eq!(again, text, "{name}");
    }
    let m = MoneySnapshot::parse(&std::fs::read_to_string(fixture("money-snapshot.json")).unwrap());
    assert_eq!(m.currency, "GBP");
    assert_eq!(m.debt_total(), 64520);
    assert_eq!(m.forecast.as_ref().unwrap().low_date, "2026-12-29");
    let w =
        WealthSnapshot::parse(&std::fs::read_to_string(fixture("wealth-snapshot.json")).unwrap());
    assert_eq!(w.latest_net_worth().unwrap().value, 1712345);
}
