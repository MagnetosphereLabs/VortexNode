//! The service only handles ciphertext. Signing keys are verification-only.
use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path as RoutePath, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use chrono::{Months, Utc};
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

const BLOCK: usize = 1024 * 1024;
const MAX_BLOCK: usize = BLOCK + 32;
const MAX_MANIFEST: usize = 8 * 1024 * 1024;
const MAX_VAULT: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_SHARE: u64 = 100 * 1024 * 1024 * 1024;
const FLOOR: u64 = 10_000_000_000;
const CONTROL_HEADROOM: u64 = 256 * 1024 * 1024;
const CLAIM_SECONDS: i64 = 15 * 60;
const RECEIVE_SECONDS: i64 = 7 * 60 * 60;
const UPLOAD_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Serialize, Deserialize)]
struct Config {
    listen: String,
    data_dir: PathBuf,
    vault_html: PathBuf,
    node_id: String,
    bridge: String,
    #[serde(default = "default_floor")]
    reserve_bytes: u64,
}
fn default_floor() -> u64 {
    FLOOR
}
struct Inner {
    cfg: Config,
    db: Mutex<Connection>,
    rates: Mutex<HashMap<String, (Instant, u32)>>,
    auth_slots: Arc<tokio::sync::Semaphore>,
}
type App = Arc<Inner>;
#[derive(Clone)]
struct Session {
    owner: i64,
    hash: String,
    expires: i64,
    ip: String,
}
#[derive(Debug)]
struct Fault(StatusCode, &'static str);
type Api<T> = std::result::Result<T, Fault>;
impl IntoResponse for Fault {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<rusqlite::Error> for Fault {
    fn from(_: rusqlite::Error) -> Self {
        Fault(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage operation failed",
        )
    }
}
impl From<io::Error> for Fault {
    fn from(_: io::Error) -> Self {
        Fault(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage operation failed",
        )
    }
}
fn bad(s: &'static str) -> Fault {
    Fault(StatusCode::BAD_REQUEST, s)
}
fn now() -> i64 {
    Utc::now().timestamp()
}
fn random(n: usize) -> String {
    let mut b = vec![0; n];
    OsRng.fill_bytes(&mut b);
    B64.encode(b)
}
fn hash(b: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(b.as_ref()))
}
fn valid_id(s: &str) -> bool {
    (16..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}
fn bounded(s: &str, min: usize, max: usize) -> bool {
    let n = s.chars().count();
    n >= min && n <= max && !s.chars().any(char::is_control)
}
fn normalize_name(s: &str) -> String {
    s.nfc().collect()
}
fn db(app: &App) -> Api<std::sync::MutexGuard<'_, Connection>> {
    app.db.lock().map_err(|_| {
        Fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage temporarily unavailable",
        )
    })
}
fn block_path(app: &App, owner: i64, digest: &str) -> PathBuf {
    app.cfg
        .data_dir
        .join("blocks")
        .join(owner.to_string())
        .join(digest)
}
fn share_path(app: &App, id: &str) -> PathBuf {
    app.cfg.data_dir.join("shares").join(id)
}
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}
fn audit(
    c: &Connection,
    s: Option<&Session>,
    owner: Option<i64>,
    kind: &str,
    verified: bool,
    vault: &str,
    bytes: u64,
    ip: &str,
) {
    let _=c.execute("INSERT INTO activity(owner,at,kind,session,ip,verified,vault,bytes) VALUES(?,?,?,?,?,?,?,?)",params![s.map(|s|s.owner).or(owner),now(),kind,s.map(|s|s.hash.as_str()).unwrap_or(""),ip,verified as i32,vault,bytes as i64]);
}
fn ip(h: &HeaderMap, peer: SocketAddr) -> String {
    // Nginx overwrites this header; only loopback can reach this service.
    if peer.ip().is_loopback() {
        if let Some(v) = h.get("x-real-ip").and_then(|x| x.to_str().ok()) {
            if let Ok(a) = v.parse::<std::net::IpAddr>() {
                return a.to_string();
            }
        }
    }
    peer.ip().to_string()
}
fn rate(app: &App, key: String, limit: u32) -> Api<()> {
    let mut r = app
        .rates
        .lock()
        .map_err(|_| Fault(StatusCode::SERVICE_UNAVAILABLE, "Try again shortly"))?;
    if r.len() > 10000 {
        r.retain(|_, v| v.0.elapsed() < Duration::from_secs(60));
        if r.len() > 10000 {
            return Err(Fault(StatusCode::TOO_MANY_REQUESTS, "Try again shortly"));
        }
    }
    let e = r.entry(key).or_insert((Instant::now(), 0));
    if e.0.elapsed() > Duration::from_secs(60) {
        *e = (Instant::now(), 0)
    }
    e.1 += 1;
    if e.1 > limit {
        Err(Fault(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts; try again in a minute",
        ))
    } else {
        Ok(())
    }
}
fn session(app: &App, h: &HeaderMap, peer: SocketAddr) -> Api<Session> {
    let token = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Fault(StatusCode::UNAUTHORIZED, "Sign in to your Node"))?;
    if token.len() != 43 {
        return Err(Fault(StatusCode::UNAUTHORIZED, "Sign in to your Node"));
    }
    let sh = hash(token);
    let row = db(app)?
        .query_row(
            "SELECT owner,expires FROM sessions WHERE hash=? AND expires>?",
            params![sh, now()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((owner, expires)) => Ok(Session {
            owner,
            hash: sh,
            expires,
            ip: ip(h, peer),
        }),
        None => Err(Fault(
            StatusCode::UNAUTHORIZED,
            "Your Node login has expired",
        )),
    }
}
fn owned(c: &Connection, s: &Session, id: &str) -> Api<(i64, String)> {
    if !valid_id(id) {
        return Err(bad("Invalid vault"));
    }
    c.query_row(
        "SELECT revision,public_key FROM vaults WHERE id=? AND owner=?",
        params![id, s.owner],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or(Fault(StatusCode::NOT_FOUND, "Vault unavailable"))
}
fn safety_floor(app: &App) -> u64 {
    app.cfg
        .reserve_bytes
        .saturating_add(if app.cfg.reserve_bytes >= FLOOR {
            CONTROL_HEADROOM
        } else {
            0
        })
}
fn free_bytes(path: &Path) -> Api<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let p =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| bad("Invalid storage path"))?;
        let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(p.as_ptr(), v.as_mut_ptr()) } != 0 {
            return Err(Fault(
                StatusCode::SERVICE_UNAVAILABLE,
                "Cannot check storage capacity",
            ));
        }
        let v = unsafe { v.assume_init() };
        Ok((v.f_bavail as u64).saturating_mul(v.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Fault(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unsupported storage platform",
        ))
    }
}
fn reserve(c: &Connection, app: &App, additional: u64) -> Api<()> {
    let a: i64 = c.query_row("SELECT COALESCE(SUM(remaining),0) FROM uploads", [], |r| {
        r.get(0)
    })?;
    let b: i64 = c.query_row(
        "SELECT COALESCE(SUM(MAX(0,budget-stored)+8388608),0) FROM shares WHERE state='uploading'",
        [],
        |r| r.get(0),
    )?;
    if free_bytes(&app.cfg.data_dir)?
        .saturating_sub((a.max(0) as u64).saturating_add(b.max(0) as u64))
        .saturating_sub(additional)
        < safety_floor(app)
    {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "The Node is preserving its 10 GB free-space buffer",
        ));
    }
    Ok(())
}

fn initialize(path: &Path) -> Result<Connection> {
    fs::create_dir_all(path.join("blocks"))?;
    fs::create_dir_all(path.join("shares"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let c = Connection::open(path.join("node.sqlite"))?;
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password TEXT NOT NULL,totp TEXT NOT NULL DEFAULT '',last_totp INTEGER NOT NULL DEFAULT -1);
 CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,owner INTEGER NOT NULL,expires INTEGER NOT NULL,created INTEGER NOT NULL,device TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY,owner INTEGER NOT NULL,label TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 0,public_key TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS revisions(vault TEXT NOT NULL,number INTEGER NOT NULL,manifest TEXT NOT NULL,bytes INTEGER NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(vault,number));
 CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,owner INTEGER NOT NULL,vault TEXT NOT NULL,base INTEGER NOT NULL,manifest TEXT NOT NULL,remaining INTEGER NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,session TEXT NOT NULL,vault TEXT NOT NULL,purpose TEXT NOT NULL,message TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY,owner INTEGER NOT NULL,vault TEXT NOT NULL,state TEXT NOT NULL,budget INTEGER NOT NULL,stored INTEGER NOT NULL DEFAULT 0,pieces INTEGER NOT NULL,created INTEGER NOT NULL,ready INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL DEFAULT 0,claim_hash TEXT NOT NULL DEFAULT '',recipient TEXT NOT NULL DEFAULT '',deadline INTEGER NOT NULL DEFAULT 0);
 CREATE UNIQUE INDEX IF NOT EXISTS one_active_share ON shares((1)) WHERE state IN ('uploading','ready','receiving');
 CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY,owner INTEGER,at INTEGER NOT NULL,kind TEXT NOT NULL,session TEXT NOT NULL,ip TEXT NOT NULL,verified INTEGER NOT NULL,vault TEXT NOT NULL,bytes INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS activity_time ON activity(at);
 CREATE TABLE IF NOT EXISTS account_policy(owner INTEGER PRIMARY KEY,months INTEGER NOT NULL CHECK(months BETWEEN 1 AND 12));
 CREATE TABLE IF NOT EXISTS vault_epochs(vault TEXT PRIMARY KEY,epoch TEXT NOT NULL,issued INTEGER NOT NULL,expires INTEGER NOT NULL,seconds INTEGER NOT NULL CHECK(seconds BETWEEN 0 AND 604800));
 CREATE TABLE IF NOT EXISTS vault_epoch_history(vault TEXT NOT NULL,epoch TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(vault,epoch));
 CREATE TABLE IF NOT EXISTS vault_leases(hash TEXT PRIMARY KEY,vault TEXT NOT NULL,session TEXT NOT NULL,epoch TEXT NOT NULL,secret TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS lease_session ON vault_leases(session);

 CREATE TABLE IF NOT EXISTS revision_parts(vault TEXT NOT NULL,revision INTEGER NOT NULL,number INTEGER NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(vault,revision,number));
 CREATE TABLE IF NOT EXISTS upload_parts(upload TEXT NOT NULL,number INTEGER NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(upload,number));
 CREATE TRIGGER IF NOT EXISTS delete_revision_parts AFTER DELETE ON revisions BEGIN DELETE FROM revision_parts WHERE vault=old.vault AND revision=old.number; END;
 CREATE TRIGGER IF NOT EXISTS delete_upload_parts AFTER DELETE ON uploads BEGIN DELETE FROM upload_parts WHERE upload=old.id; END;")?;
    // Index pre-existing layouts once; normal piece reads never parse a whole manifest.
    for (sql,is_revision) in [("SELECT r.vault,r.number,r.manifest FROM revisions r WHERE NOT EXISTS(SELECT 1 FROM revision_parts p WHERE p.vault=r.vault AND p.revision=r.number)",true),("SELECT u.id,0,u.manifest FROM uploads u WHERE NOT EXISTS(SELECT 1 FROM upload_parts p WHERE p.upload=u.id)",false)] {
  let mut q=c.prepare(sql)?;let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;drop(q);
  let tx=c.unchecked_transaction()?;for(id,revision,raw)in rows{let value:Value=serde_json::from_str(&raw)?;if let Some(parts)=value["blocks"].as_array(){for(n,part)in parts.iter().enumerate(){let p:Part=serde_json::from_value(part.clone())?;if is_revision{tx.execute("INSERT INTO revision_parts VALUES(?,?,?,?,?)",params![id,revision,n as i64,p.hash,p.size as i64])?;}else{tx.execute("INSERT INTO upload_parts VALUES(?,?,?,?)",params![id,n as i64,p.hash,p.size as i64])?;}}}}tx.commit()?;
 }
    Ok(c)
}

async fn info(State(a): State<App>) -> Json<Value> {
    Json(
        json!({"node":a.cfg.node_id,"gate":format!("/gate/{}",a.cfg.bridge),"release":"2.3","chunk":BLOCK,"maxShare":MAX_SHARE}),
    )
}
async fn health() -> Json<Value> {
    Json(json!({"ok":true}))
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
    #[serde(default)]
    otp: String,
    #[serde(default)]
    device: String,
}
async fn login(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(mut v): Json<Login>,
) -> Api<Json<Value>> {
    let addr = ip(&h, p);
    rate(&a, format!("login:{addr}"), 10)?;
    rate(&a, "login-global".into(), 60)?;
    if !bounded(&v.username, 8, 128)
        || v.password.chars().count() < 15
        || v.password.chars().count() > 128
        || v.password.len() > 512
    {
        return Err(bad("Invalid credentials"));
    }
    let username = normalize_name(&v.username);
    rate(&a, format!("account:{}", hash(&username)), 15)?;
    let row = db(&a)?
        .query_row(
            "SELECT id,password,totp,last_totp FROM accounts WHERE username=?",
            [&username],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let permit = a
        .auth_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Fault(StatusCode::TOO_MANY_REQUESTS, "Try again shortly"))?;
    let password = std::mem::take(&mut v.password);
    let ph=row.as_ref().map(|r|r.1.clone()).unwrap_or_else(||"$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$8xN7ia6YQhN5fIxRLcEyb3TWeY8d4dIF0VzrJg1o6xA".into());
    let ok = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut password = password;
        let ok = PasswordHash::new(&ph)
            .map(|p| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &p)
                    .is_ok()
            })
            .unwrap_or(false);
        password.zeroize();
        ok
    })
    .await
    .map_err(|_| {
        Fault(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authentication unavailable",
        )
    })?;
    let mut c = db(&a)?;
    if !ok || row.is_none() {
        audit(
            &c,
            None,
            row.as_ref().map(|r| r.0),
            "login_failed",
            false,
            "",
            0,
            &addr,
        );
        return Err(Fault(StatusCode::UNAUTHORIZED, "Sign-in failed"));
    }
    let (owner, _, seed, last) = row.unwrap();
    if !seed.is_empty() {
        let step = verify_totp(&seed, &v.otp, last).ok_or_else(|| {
            audit(&c, None, Some(owner), "login_failed", false, "", 0, &addr);
            Fault(
                StatusCode::UNAUTHORIZED,
                "Sign-in failed; check your authenticator code",
            )
        })?;
        if c.execute(
            "UPDATE accounts SET last_totp=? WHERE id=? AND last_totp<?",
            params![step, owner, step],
        )? != 1
        {
            return Err(Fault(StatusCode::UNAUTHORIZED, "Sign-in failed"));
        }
    }
    let token = random(32);
    let sh = hash(&token);
    let months: i64 = c
        .query_row(
            "SELECT months FROM account_policy WHERE owner=?",
            [owner],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(12);
    let expires = Utc::now()
        .checked_add_months(Months::new(months as u32))
        .ok_or(bad("Clock unavailable"))?
        .timestamp();
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO sessions VALUES(?,?,?,?,?)",
        params![
            sh,
            owner,
            expires,
            now(),
            v.device.chars().take(80).collect::<String>()
        ],
    )?;
    tx.commit()?;
    let s = Session {
        owner,
        hash: sh,
        expires,
        ip: addr.clone(),
    };
    audit(&c, Some(&s), None, "login_success", false, "", 0, &addr);
    Ok(Json(
        json!({"token":token,"expires":expires,"username":username,"months":months}),
    ))
}
async fn current(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let name: String = c.query_row("SELECT username FROM accounts WHERE id=?", [s.owner], |r| {
        r.get(0)
    })?;
    let free = free_bytes(&a.cfg.data_dir)?.saturating_sub(safety_floor(&a));
    Ok(Json(
        json!({"username":name,"expires":s.expires,"available":free,"node":a.cfg.node_id,"months":c.query_row("SELECT months FROM account_policy WHERE owner=?",[s.owner],|r|r.get::<_,i64>(0)).optional()?.unwrap_or(12)}),
    ))
}
async fn forget(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    c.execute("DELETE FROM vault_leases WHERE session=?", [&s.hash])?;
    c.execute("DELETE FROM sessions WHERE hash=?", [&s.hash])?;
    audit(&c, Some(&s), None, "logout", false, "", 0, &s.ip);
    Ok(Json(json!({"ok":true})))
}
// A remembered unlock has two independently held factors. This random server factor
// alone cannot unwrap or decrypt a vault. The matching client factor never leaves its browser.
fn check_epoch(c: &Connection, id: &str) -> Api<()> {
    let expires: Option<i64> = c
        .query_row(
            "SELECT expires FROM vault_epochs WHERE vault=?",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    if expires.map(|x| x <= now()).unwrap_or(false) {
        return Err(Fault(
            StatusCode::LOCKED,
            "Vault session expired. Enter your full passphrase",
        ));
    }
    Ok(())
}
fn key_epoch(header: &[u8]) -> Option<String> {
    if header.len() >= 192 && &header[..4] == b"AVLT" && header[4] == 3 {
        let mut b = header[..12].to_vec();
        b.extend_from_slice(&header[16..144]);
        Some(hash(b))
    } else if header.len() >= 64 && &header[..4] == b"AVLT" && header[4] == 2 {
        Some(hash(&header[..28]))
    } else {
        None
    }
}
async fn preferences(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let months = v["months"]
        .as_u64()
        .filter(|n| (1..=12).contains(n))
        .ok_or(bad("Choose one to twelve months"))?;
    let mut c = db(&a)?;
    let created: i64 = c.query_row(
        "SELECT created FROM sessions WHERE hash=?",
        [&s.hash],
        |r| r.get(0),
    )?;
    let expires = chrono::DateTime::from_timestamp(created, 0)
        .and_then(|d| d.checked_add_months(Months::new(months as u32)))
        .ok_or(bad("Clock unavailable"))?
        .timestamp();
    let tx = c.transaction()?;
    tx.execute("INSERT INTO account_policy VALUES(?,?) ON CONFLICT(owner) DO UPDATE SET months=excluded.months",params![s.owner,months])?;
    tx.execute(
        "UPDATE sessions SET expires=? WHERE hash=?",
        params![expires, s.hash],
    )?;
    tx.commit()?;
    audit(
        &c,
        Some(&s),
        None,
        "login_duration_changed",
        false,
        "",
        0,
        &s.ip,
    );
    Ok(Json(json!({"months":months,"expires":expires})))
}
async fn panic_logout(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    tx.execute("DELETE FROM vault_leases WHERE session=?", [&s.hash])?;
    tx.execute("DELETE FROM challenges WHERE session=?", [&s.hash])?;
    tx.execute("UPDATE shares SET state='revoked',recipient='' WHERE owner=? AND state IN('uploading','ready','receiving')",[s.owner])?;
    tx.execute("DELETE FROM sessions WHERE hash=?", [&s.hash])?;
    tx.commit()?;
    audit(&c, Some(&s), None, "panic_logout", false, "", 0, &s.ip);
    Ok(Json(json!({"ok":true})))
}
async fn remember_vault(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    rate(&a, format!("remember:{}", s.hash), 30)?;
    let c = db(&a)?;
    prove(&c, &s, &id, "remember", &v)?;
    let (epoch, expires, seconds): (String, i64, i64) = c
        .query_row(
            "SELECT epoch,expires,seconds FROM vault_epochs WHERE vault=?",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or(bad("Save the new vault key epoch first"))?;
    if expires <= now() {
        return Err(Fault(
            StatusCode::LOCKED,
            "Vault session expired. Enter your full passphrase",
        ));
    }
    if seconds == 0 {
        return Err(bad("Immediate locking does not keep a remembered unlock"));
    }
    if text(&v, "epoch") != epoch {
        return Err(Fault(StatusCode::CONFLICT, "The vault key epoch changed"));
    }
    let expires = expires.min(s.expires);
    let token = random(32);
    let share = random(32);
    c.execute(
        "DELETE FROM vault_leases WHERE vault=? AND session=?",
        params![id, s.hash],
    )?;
    c.execute(
        "INSERT INTO vault_leases VALUES(?,?,?,?,?,?)",
        params![hash(&token), id, s.hash, epoch, share, expires],
    )?;
    Ok(Json(
        json!({"token":token,"share":share,"epoch":epoch,"expires":expires,"lease_expires":expires,"server_now":now()}),
    ))
}
async fn resume_vault(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    rate(&a, format!("remember:{}", s.hash), 60)?;
    let c = db(&a)?;
    owned(&c, &s, &id)?;
    let row:Option<(String,String,i64,i64)>=c.query_row("SELECT l.secret,l.epoch,l.expires,e.expires FROM vault_leases l JOIN vault_epochs e ON e.vault=l.vault AND e.epoch=l.epoch WHERE l.hash=? AND l.vault=? AND l.session=? AND l.expires>? AND e.expires>? AND e.seconds>0",params![hash(text(&v,"token")),id,s.hash,now(),now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (share, epoch, lease_expires, until) = row.ok_or(Fault(
        StatusCode::UNAUTHORIZED,
        "Vault unlock has expired. Enter your full passphrase",
    ))?;
    Ok(Json(
        json!({"share":share,"epoch":epoch,"expires":until.min(lease_expires).min(s.expires),"lease_expires":lease_expires,"server_now":now()}),
    ))
}
async fn forget_vault(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    owned(&c, &s, &id)?;
    c.execute(
        "DELETE FROM vault_leases WHERE vault=? AND session=?",
        params![id, s.hash],
    )?;
    Ok(Json(json!({"ok":true})))
}

async fn activity(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let mut q=c.prepare("SELECT at,kind,session,ip,verified,vault,bytes FROM activity WHERE at>? AND (owner=? OR owner IS NULL) ORDER BY id DESC LIMIT 500")?;
    let rows=q.query_map(params![now()-86400,s.owner],|r|Ok(json!({"at":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"current":r.get::<_,String>(2)?==s.hash,"ip":r.get::<_,String>(3)?,"verified":r.get::<_,bool>(4)?,"vault":r.get::<_,String>(5)?,"bytes":r.get::<_,i64>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!({"events":rows,"hours":24})))
}
async fn vaults(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let mut q=c.prepare("SELECT v.id,v.label,v.revision,COALESCE(r.bytes,0),COALESCE(r.created,0) FROM vaults v LEFT JOIN revisions r ON r.vault=v.id AND r.number=v.revision WHERE owner=? ORDER BY label,id LIMIT 1000")?;
    let rows=q.query_map([s.owner],|r|Ok(json!({"id":r.get::<_,String>(0)?,"label":r.get::<_,String>(1)?,"revision":r.get::<_,i64>(2)?,"bytes":r.get::<_,i64>(3)?,"updated":r.get::<_,i64>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!({"vaults":rows})))
}
async fn create_vault(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let id = random(18);
    let label = text(&v, "label");
    if !bounded(&label, 1, 100) {
        return Err(bad("Use a vault label of 1-100 characters"));
    }
    let c = db(&a)?;
    let count: i64 = c.query_row(
        "SELECT COUNT(*) FROM vaults WHERE owner=?",
        [s.owner],
        |r| r.get(0),
    )?;
    if count >= 1000 {
        return Err(bad("Vault catalog limit reached"));
    }
    reserve(&c, &a, 4096)?;
    c.execute(
        "INSERT INTO vaults(id,owner,label) VALUES(?,?,?)",
        params![id, s.owner, label],
    )?;
    audit(&c, Some(&s), None, "vault_created", false, &id, 0, &s.ip);
    Ok(Json(json!({"id":id,"revision":0})))
}

#[derive(Clone, Serialize, Deserialize)]
struct Part {
    hash: String,
    size: u64,
}
#[derive(Deserialize)]
struct Stage {
    base: i64,
    #[serde(default)]
    blocks: Vec<Part>,
    #[serde(default)]
    catalog: Vec<Part>,
    #[serde(default)]
    order: Vec<usize>,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    unlock_seconds: Option<i64>,
    #[serde(default)]
    rotation: Option<Value>,
}
fn validate_parts(parts: &[Part]) -> Api<u64> {
    if parts.is_empty() || parts.len() > 1_000_000 {
        return Err(bad("Invalid encrypted vault layout"));
    }
    let mut n = 0u64;
    for p in parts {
        if !valid_hash(&p.hash) || p.size == 0 || p.size > MAX_BLOCK as u64 {
            return Err(bad("Invalid encrypted block"));
        }
        n = n.checked_add(p.size).ok_or(bad("Vault too large"))?;
    }
    if n > MAX_VAULT {
        return Err(bad("Vault exceeds the 1 TiB per-vault limit"));
    }
    Ok(n)
}
async fn stage(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Stage>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let parts = if v.order.is_empty() {
        v.blocks.clone()
    } else {
        if v.order.len() > 1_000_000 {
            return Err(bad("Vault layout is too large"));
        }
        v.order
            .iter()
            .map(|n| {
                v.catalog
                    .get(*n)
                    .cloned()
                    .ok_or(bad("Invalid encrypted layout"))
            })
            .collect::<Api<Vec<_>>>()?
    };
    let total = validate_parts(&parts)?;
    if let Some(t) = v.unlock_seconds {
        if !(0..=604800).contains(&t) {
            return Err(bad(
                "Vault unlock duration must be between immediate and seven days",
            ));
        }
    }
    let mut c = db(&a)?;
    let (base, key) = owned(&c, &s, &id)?;
    if base != v.base {
        return Err(Fault(
            StatusCode::PRECONDITION_FAILED,
            "This vault changed on another device",
        ));
    }
    if !v.public_key.is_empty() {
        let bytes = B64
            .decode(&v.public_key)
            .map_err(|_| bad("Invalid verification key"))?;
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| bad("Invalid verification key"))?;
        if !key.is_empty() && key != v.public_key {
            let proof = v.rotation.as_ref().ok_or(Fault(
                StatusCode::FORBIDDEN,
                "Vault key rotation requires the previous vault proof",
            ))?;
            let message:String=c.query_row("SELECT message FROM challenges WHERE id=? AND session=? AND vault=? AND purpose='rotate'",params![text(proof,"ticket"),s.hash,id],|r|r.get(0)).optional()?.ok_or(Fault(StatusCode::FORBIDDEN,"Rotation challenge unavailable"))?;
            let message: Value =
                serde_json::from_str(&message).map_err(|_| bad("Invalid rotation challenge"))?;
            if text(&message, "next_public") != v.public_key {
                return Err(Fault(
                    StatusCode::FORBIDDEN,
                    "Rotation proof is for another key",
                ));
            }
            prove(&c, &s, &id, "rotate", proof)?;
        }
    }
    let mut missing = Vec::new();
    let mut amount = 0;
    let mut seen = std::collections::HashSet::new();
    for (i, part) in parts.iter().enumerate() {
        if seen.insert(part.hash.clone())
            && fs::metadata(block_path(&a, s.owner, &part.hash))
                .map(|m| m.len())
                .unwrap_or(0)
                != part.size
        {
            missing.push(i);
            amount += part.size;
        }
    }
    // Replacing a stale uncommitted upload for this vault is safe; no live revision changes.
    c.execute(
        "DELETE FROM uploads WHERE vault=? AND owner=?",
        params![id, s.owner],
    )?;
    prune_history(&mut c, &a, true)?;
    if reserve(&c, &a, amount + MAX_MANIFEST as u64).is_err() {
        c.execute("DELETE FROM revisions WHERE EXISTS(SELECT 1 FROM vaults v WHERE v.id=revisions.vault AND revisions.number<v.revision)",[])?;
        gc_blocks(&c, &a)?;
    }
    reserve(&c, &a, amount + MAX_MANIFEST as u64)?;
    let upload = random(18);
    let manifest = json!({"blocks":parts,"bytes":total,"public_key":v.public_key,"unlock_seconds":v.unlock_seconds,"rotation":!key.is_empty()&&key!=v.public_key});
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO uploads VALUES(?,?,?,?,?,?,?)",
        params![
            upload,
            s.owner,
            id,
            base,
            manifest.to_string(),
            amount as i64 + MAX_MANIFEST as i64,
            now()
        ],
    )?;
    {
        let mut st = tx.prepare("INSERT INTO upload_parts VALUES(?,?,?,?)")?;
        for (n, part) in parts.iter().enumerate() {
            st.execute(params![upload, n as i64, part.hash, part.size as i64])?;
        }
    }
    tx.commit()?;
    Ok(Json(json!({"upload":upload,"missing":missing})))
}
async fn put_block(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((uid, n)): RoutePath<(String, usize)>,
    body: Bytes,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !valid_id(&uid) || body.len() > MAX_BLOCK {
        return Err(bad("Invalid encrypted block"));
    }
    let c = db(&a)?;
    let part=c.query_row("SELECT p.hash,p.size FROM upload_parts p JOIN uploads u ON u.id=p.upload WHERE u.id=? AND u.owner=? AND u.created>? AND p.number=?",params![uid,s.owner,now()-UPLOAD_SECONDS,n as i64],|r|Ok(Part{hash:r.get(0)?,size:r.get::<_,i64>(1)? as u64})).optional()?.ok_or(Fault(StatusCode::NOT_FOUND,"Upload piece unavailable"))?;
    if body.len() as u64 != part.size || hash(&body) != part.hash {
        return Err(bad("Encrypted block integrity check failed"));
    }
    let path = block_path(&a, s.owner, &part.hash);
    if path.exists() {
        return Ok(Json(json!({"ok":true})));
    }
    if free_bytes(&a.cfg.data_dir)?.saturating_sub(part.size) < safety_floor(&a) {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "Storage buffer reached",
        ));
    }
    fs::create_dir_all(path.parent().unwrap())?;
    let temp = path.with_extension(random(12));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&temp, &path)?;
    sync_directory(path.parent().unwrap())?;
    c.execute(
        "UPDATE uploads SET remaining=MAX(0,remaining-?) WHERE id=?",
        params![part.size as i64, uid],
    )?;
    Ok(Json(json!({"ok":true})))
}
async fn commit(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let mut c = db(&a)?;
    let row: Option<(String, i64, String)> = c
        .query_row(
            "SELECT vault,base,manifest FROM uploads WHERE id=? AND owner=? AND created>?",
            params![uid, s.owner, now() - UPLOAD_SECONDS],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (id, base, raw) = row.ok_or(Fault(StatusCode::NOT_FOUND, "Upload unavailable"))?;
    let (current, key) = owned(&c, &s, &id)?;
    if current != base {
        return Err(Fault(
            StatusCode::PRECONDITION_FAILED,
            "This vault changed on another device",
        ));
    }
    let v: Value = serde_json::from_str(&raw).map_err(|_| bad("Invalid upload"))?;
    let parts: Vec<Part> =
        serde_json::from_value(v["blocks"].clone()).map_err(|_| bad("Invalid upload"))?;
    let total = validate_parts(&parts)?;
    for part in &parts {
        if fs::metadata(block_path(&a, s.owner, &part.hash))
            .map(|m| m.len())
            .unwrap_or(0)
            != part.size
        {
            return Err(bad("Encrypted upload is incomplete"));
        }
    }
    let public = text(&v, "public_key");
    let policy = v["unlock_seconds"].as_i64();
    let first = &parts[0];
    let header = fs::read(block_path(&a, s.owner, &first.hash))?;
    let epoch = key_epoch(&header);
    let existing: Option<(String, i64, i64, i64)> = c
        .query_row(
            "SELECT epoch,issued,expires,seconds FROM vault_epochs WHERE vault=?",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let epoch_change = epoch
        .as_ref()
        .map(|e| existing.as_ref().map(|x| x.0 != *e).unwrap_or(true))
        .unwrap_or(false);
    if let Some(ref old) = existing {
        if !epoch_change && old.2 <= now() {
            return Err(Fault(
                StatusCode::LOCKED,
                "Vault session expired. Unlock with your full passphrase again",
            ));
        }
        if epoch.is_none() {
            return Err(bad("A protected vault cannot drop its key epoch"));
        }
    }
    if epoch_change {
        if let Some(ref e) = epoch {
            let used: i64 = c.query_row(
                "SELECT COUNT(*) FROM vault_epoch_history WHERE vault=? AND epoch=?",
                params![id, e],
                |r| r.get(0),
            )?;
            if used != 0 {
                return Err(Fault(
                    StatusCode::CONFLICT,
                    "A retired vault encryption key epoch cannot be reused",
                ));
            }
        }
    }
    let rotated = v["rotation"].as_bool().unwrap_or(false);
    if rotated && !epoch_change {
        return Err(bad(
            "Vault verification rotation requires a fresh encryption key epoch",
        ));
    }
    let seconds = policy
        .or_else(|| existing.as_ref().map(|x| x.3))
        .unwrap_or(86400);
    if !(0..=604800).contains(&seconds) {
        return Err(bad("Invalid vault session duration"));
    }
    let issued = if epoch_change {
        now()
    } else {
        existing.as_ref().map(|x| x.1).unwrap_or(now())
    };
    let wanted = issued + if seconds == 0 { 604800 } else { seconds };
    let expires = if epoch_change {
        wanted
    } else {
        existing.as_ref().map(|x| x.2.min(wanted)).unwrap_or(wanted)
    };
    let tx = c.transaction()?;
    if let Some(ref epoch) = epoch {
        tx.execute("INSERT INTO vault_epoch_history VALUES(?,?,?) ON CONFLICT(vault,epoch) DO UPDATE SET expires=MIN(expires,excluded.expires)",params![id,epoch,expires])?;
        tx.execute("INSERT INTO vault_epochs VALUES(?,?,?,?,?) ON CONFLICT(vault) DO UPDATE SET epoch=excluded.epoch,issued=excluded.issued,expires=excluded.expires,seconds=excluded.seconds",params![id,epoch,issued,expires,seconds])?;
        if epoch_change || seconds == 0 {
            tx.execute("DELETE FROM vault_leases WHERE vault=?", [&id])?;
        }
    }
    tx.execute(
        "INSERT INTO revisions VALUES(?,?,?,?,?)",
        params![id, base + 1, raw, total as i64, now()],
    )?;
    tx.execute(
        "UPDATE vaults SET revision=?,public_key=? WHERE id=?",
        params![
            base + 1,
            if key.is_empty() || rotated {
                public
            } else {
                key
            },
            id
        ],
    )?;
    tx.execute(
        "INSERT INTO revision_parts SELECT ?,?,number,hash,size FROM upload_parts WHERE upload=?",
        params![id, base + 1, uid],
    )?;
    tx.execute("DELETE FROM uploads WHERE id=?", [uid])?;
    tx.commit()?;
    audit(&c, Some(&s), None, "vault_saved", false, &id, total, &s.ip);
    prune_history(&mut c, &a, false)?;
    Ok(Json(
        json!({"revision":base+1,"bytes":total,"unlock":epoch.as_ref().map(|e|json!({"epoch":e,"issued":issued,"expires":expires,"seconds":seconds,"server_now":now()}))}),
    ))
}
async fn manifest(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let (rev, _) = owned(&c, &s, &id)?;
    if rev == 0 {
        return Err(Fault(
            StatusCode::NOT_FOUND,
            "This vault has not been saved yet",
        ));
    }
    let raw: String = c.query_row(
        "SELECT manifest FROM revisions WHERE vault=? AND number=?",
        params![id, rev],
        |r| r.get(0),
    )?;
    let v: Value = serde_json::from_str(&raw).map_err(|_| bad("Stored vault layout is damaged"))?;
    audit(
        &c,
        Some(&s),
        None,
        "vault_opened",
        false,
        &id,
        v["bytes"].as_u64().unwrap_or(0),
        &s.ip,
    );
    let parts: Vec<Part> =
        serde_json::from_value(v["blocks"].clone()).map_err(|_| bad("Invalid stored layout"))?;
    let mut indices = HashMap::new();
    let mut catalog = Vec::new();
    let mut order = Vec::new();
    for part in parts {
        let n = if let Some(n) = indices.get(&part.hash) {
            *n
        } else {
            let n = catalog.len();
            indices.insert(part.hash.clone(), n);
            catalog.push(part);
            n
        };
        order.push(n)
    }
    Ok(Json(
        json!({"revision":rev,"catalog":catalog,"order":order,"bytes":v["bytes"],"unlock":c.query_row("SELECT epoch,issued,expires,seconds FROM vault_epochs WHERE vault=?",[&id],|r|Ok(json!({"epoch":r.get::<_,String>(0)?,"issued":r.get::<_,i64>(1)?,"expires":r.get::<_,i64>(2)?,"seconds":r.get::<_,i64>(3)?,"server_now":now()}))).optional()?}),
    ))
}
async fn read_block(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((id, rev, n)): RoutePath<(String, i64, usize)>,
) -> Api<Response> {
    let s = session(&a, &h, p)?;
    let part: Part = {
        let c = db(&a)?;
        owned(&c, &s, &id)?;
        c.query_row("SELECT p.hash,p.size FROM revision_parts p JOIN revisions r ON r.vault=p.vault AND r.number=p.revision WHERE p.vault=? AND p.revision=? AND p.number=?",params![id,rev,n as i64],|r|Ok(Part{hash:r.get(0)?,size:r.get::<_,i64>(1)? as u64})).optional()?.ok_or(Fault(StatusCode::NOT_FOUND,"Revision piece unavailable"))?
    };
    let bytes = tokio::fs::read(block_path(&a, s.owner, &part.hash)).await?;
    if bytes.len() as u64 != part.size || hash(&bytes) != part.hash {
        return Err(Fault(StatusCode::CONFLICT, "Encrypted block is damaged"));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}
async fn remove_vault(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let mut c = db(&a)?;
    owned(&c, &s, &id)?;
    let tx = c.transaction()?;
    tx.execute("DELETE FROM revisions WHERE vault=?", [&id])?;
    tx.execute("DELETE FROM uploads WHERE vault=?", [&id])?;
    tx.execute("UPDATE shares SET state='revoked' WHERE vault=?", [&id])?;
    tx.execute("DELETE FROM vaults WHERE id=?", [&id])?;
    tx.commit()?;
    audit(&c, Some(&s), None, "vault_deleted", false, &id, 0, &s.ip);
    Ok(Json(json!({"ok":true})))
}

async fn challenge(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    rate(&a, format!("challenge:{}", s.hash), 30)?;
    let purpose = text(&v, "purpose");
    if !["verify", "share", "remember", "rotate"].contains(&purpose.as_str()) {
        return Err(bad("Invalid verification purpose"));
    }
    let c = db(&a)?;
    let (rev, key) = owned(&c, &s, &id)?;
    if key.is_empty() || rev == 0 {
        return Err(bad(
            "Save this unlocked vault to register its verification key",
        ));
    }
    if purpose != "rotate" {
        check_epoch(&c, &id)?;
    }
    let next_public = text(&v, "next_public");
    if purpose == "rotate" {
        let bytes = B64
            .decode(&next_public)
            .map_err(|_| bad("Invalid rotation key"))?;
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| bad("Invalid rotation key"))?;
    }
    let ticket = random(24);
    let message=json!({"node":a.cfg.node_id,"vault":id,"revision":rev,"session":s.hash,"purpose":purpose,"ticket":ticket,"expires":now()+60,"domain":"Vortex Node vault possession","next_public":next_public}).to_string();
    c.execute("DELETE FROM challenges WHERE expires<?", [now()])?;
    c.execute(
        "INSERT INTO challenges VALUES(?,?,?,?,?,?)",
        params![ticket, s.hash, id, purpose, message, now() + 60],
    )?;
    Ok(Json(json!({"ticket":ticket,"message":message})))
}
fn prove(c: &Connection, s: &Session, id: &str, purpose: &str, v: &Value) -> Api<()> {
    let (_, public) = owned(c, s, id)?;
    if purpose != "rotate" {
        check_epoch(c, id)?;
    }
    let ticket = text(v, "ticket");
    let message:Option<String>=c.query_row("SELECT message FROM challenges WHERE id=? AND session=? AND vault=? AND purpose=? AND expires>?",params![ticket,s.hash,id,purpose,now()],|r|r.get(0)).optional()?;
    let message = message.ok_or(Fault(
        StatusCode::FORBIDDEN,
        "Unlock your vault to verify this action",
    ))?;
    let pubkey = B64
        .decode(public)
        .map_err(|_| bad("Invalid verification key"))?;
    let sig = B64
        .decode(text(v, "signature"))
        .map_err(|_| bad("Invalid proof"))?;
    let key =
        VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| bad("Invalid verification key"))?;
    let signature = Signature::from_slice(&sig).map_err(|_| bad("Invalid proof"))?;
    key.verify(message.as_bytes(), &signature)
        .map_err(|_| Fault(StatusCode::FORBIDDEN, "Vault verification failed"))?;
    if c.execute("DELETE FROM challenges WHERE id=?", [ticket])? != 1 {
        return Err(Fault(StatusCode::FORBIDDEN, "Verification already used"));
    }
    Ok(())
}
async fn verify(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    prove(&c, &s, &id, "verify", &v)?;
    audit(&c, Some(&s), None, "vault_verified", true, &id, 0, &s.ip);
    Ok(Json(json!({"verified":true,"at":now()})))
}

async fn start_share(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let id = text(&v, "vault");
    let budget = v["bytes"].as_u64().ok_or(bad("Invalid transfer size"))?;
    let pieces = v["pieces"].as_u64().ok_or(bad("Invalid transfer layout"))?;
    if budget > MAX_SHARE + MAX_SHARE / BLOCK as u64 * 16 || pieces > 120000 || pieces > budget + 1
    {
        return Err(bad("Maximum transfer size is 100 GiB"));
    }
    let mut c = db(&a)?;
    cleanup(&mut c, &a)?;
    prove(&c, &s, &id, "share", &v)?;
    let busy: i64 = c.query_row(
        "SELECT COUNT(*) FROM shares WHERE state IN ('uploading','ready','receiving')",
        [],
        |r| r.get(0),
    )?;
    if busy != 0 {
        return Err(Fault(
            StatusCode::CONFLICT,
            "One transfer is already active; finish or revoke it first",
        ));
    }
    prune_history(&mut c, &a, true)?;
    reserve(&c, &a, budget + MAX_MANIFEST as u64)?;
    let share = random(18);
    fs::create_dir(share_path(&a, &share))?;
    sync_directory(&a.cfg.data_dir.join("shares"))?;
    c.execute("INSERT INTO shares(id,owner,vault,state,budget,pieces,created) VALUES(?,?,?,'uploading',?,?,?)",params![share,s.owner,id,budget as i64,pieces as i64,now()])?;
    audit(
        &c,
        Some(&s),
        None,
        "share_started",
        true,
        &id,
        budget,
        &s.ip,
    );
    Ok(Json(json!({"id":share})))
}
async fn share_piece(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((id, n)): RoutePath<(String, u64)>,
    body: Bytes,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !valid_id(&id) || body.len() > MAX_BLOCK || body.len() < 16 {
        return Err(bad("Invalid encrypted piece"));
    }
    let c = db(&a)?;
    let row:Option<(i64,i64,i64)>=c.query_row("SELECT pieces,budget,stored FROM shares WHERE id=? AND owner=? AND state='uploading' AND created>?",params![id,s.owner,now()-UPLOAD_SECONDS],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let (count, budget, stored) =
        row.ok_or(Fault(StatusCode::NOT_FOUND, "Transfer unavailable"))?;
    if n >= count as u64 {
        return Err(bad("Invalid piece index"));
    }
    let path = share_path(&a, &id).join(n.to_string());
    if path.exists() {
        if hash(fs::read(&path)?) != hash(&body) {
            return Err(Fault(
                StatusCode::CONFLICT,
                "Encrypted piece already exists",
            ));
        }
        return Ok(Json(json!({"ok":true})));
    }
    if stored + body.len() as i64 > budget {
        return Err(bad("Transfer exceeded its declared size"));
    }
    if free_bytes(&a.cfg.data_dir)?.saturating_sub(body.len() as u64) < safety_floor(&a) {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "Storage buffer reached",
        ));
    }
    let temporary = path.with_extension(random(12));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(temporary, &path)?;
    sync_directory(path.parent().unwrap())?;
    c.execute(
        "UPDATE shares SET stored=stored+? WHERE id=?",
        params![body.len() as i64, id],
    )?;
    Ok(Json(json!({"ok":true})))
}
async fn publish(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !valid_id(&id) {
        return Err(bad("Invalid transfer"));
    }
    let lookup = text(&v, "proof");
    if !valid_hash(&lookup) {
        return Err(bad("Invalid receive proof"));
    }
    let encrypted = B64
        .decode(text(&v, "manifest"))
        .map_err(|_| bad("Invalid encrypted manifest"))?;
    if encrypted.len() < 28 || encrypted.len() > MAX_MANIFEST {
        return Err(bad("Invalid encrypted manifest"));
    }
    let c = db(&a)?;
    let row:Option<(i64,i64,i64,String)>=c.query_row("SELECT pieces,budget,stored,vault FROM shares WHERE id=? AND owner=? AND state='uploading'",params![id,s.owner],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let (count, budget, stored, vault) =
        row.ok_or(Fault(StatusCode::NOT_FOUND, "Transfer unavailable"))?;
    if budget != stored {
        return Err(bad("Transfer is incomplete"));
    }
    for i in 0..count {
        if !share_path(&a, &id).join(i.to_string()).is_file() {
            return Err(bad("Transfer is incomplete"));
        }
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(share_path(&a, &id).join("manifest"))?;
    f.write_all(&encrypted)?;
    f.sync_all()?;
    sync_directory(&share_path(&a, &id))?;
    c.execute(
        "UPDATE shares SET state='ready',ready=?,expires=?,claim_hash=? WHERE id=?",
        params![now(), now() + CLAIM_SECONDS, lookup, id],
    )?;
    audit(
        &c,
        Some(&s),
        None,
        "share_ready",
        true,
        &vault,
        budget as u64,
        &s.ip,
    );
    Ok(Json(json!({"expires":now()+CLAIM_SECONDS})))
}
async fn revoke(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let n=c.execute("UPDATE shares SET state='revoked' WHERE id=? AND owner=? AND state IN ('uploading','ready','receiving')",params![id,s.owner])?;
    if n > 0 {
        audit(&c, Some(&s), None, "share_revoked", false, "", 0, &s.ip)
    }
    Ok(Json(json!({"ok":true})))
}
async fn share_status(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let row:Option<Value>=c.query_row("SELECT id,state,stored,budget,expires,deadline FROM shares WHERE owner=? ORDER BY created DESC LIMIT 1",[s.owner],|r|Ok(json!({"id":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"stored":r.get::<_,i64>(2)?,"bytes":r.get::<_,i64>(3)?,"expires":r.get::<_,i64>(4)?,"deadline":r.get::<_,i64>(5)?}))).optional()?;
    Ok(Json(json!({"share":row})))
}

fn receive_proof(v: &Value) -> Api<String> {
    let p = text(v, "proof");
    if !valid_hash(&p) {
        return Err(Fault(
            StatusCode::NOT_FOUND,
            "This download is unavailable or expired",
        ));
    }
    Ok(p)
}
async fn preview(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let addr = ip(&h, p);
    rate(&a, format!("receive:{addr}"), 30)?;
    if !valid_id(&id) {
        return Err(bad("Invalid transfer"));
    }
    let proof = receive_proof(&v)?;
    {
        let c = db(&a)?;
        let expected: Option<String> = c
            .query_row(
                "SELECT claim_hash FROM shares WHERE id=? AND state='ready' AND expires>?",
                params![id, now()],
                |r| r.get(0),
            )
            .optional()?;
        if !expected
            .map(|x| bool::from(x.as_bytes().ct_eq(proof.as_bytes())))
            .unwrap_or(false)
        {
            return Err(Fault(
                StatusCode::NOT_FOUND,
                "This download is unavailable or expired",
            ));
        }
    }
    let encrypted = tokio::fs::read(share_path(&a, &id).join("manifest")).await?;
    Ok(Json(json!({"manifest":B64.encode(encrypted)})))
}
async fn claim(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let addr = ip(&h, p);
    rate(&a, format!("receive:{addr}"), 30)?;
    if !valid_id(&id) {
        return Err(bad("Invalid transfer"));
    }
    let proof = receive_proof(&v)?;
    let mut c = db(&a)?;
    let token = random(32);
    let deadline = now() + RECEIVE_SECONDS;
    let tx = c.transaction()?;
    let n=tx.execute("UPDATE shares SET state='receiving',recipient=?,deadline=? WHERE id=? AND state='ready' AND expires>? AND claim_hash=?",params![hash(&token),deadline,id,now(),proof])?;
    if n != 1 {
        return Err(Fault(
            StatusCode::NOT_FOUND,
            "This download was claimed or has expired",
        ));
    }
    let (owner, vault, bytes): (i64, String, i64) = tx.query_row(
        "SELECT owner,vault,budget FROM shares WHERE id=?",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    tx.commit()?;
    audit(
        &c,
        None,
        Some(owner),
        "share_claimed",
        false,
        &vault,
        bytes as u64,
        &addr,
    );
    Ok(Json(json!({"token":token,"deadline":deadline})))
}
fn receiver(c: &Connection, h: &HeaderMap, id: &str) -> Api<(i64, String, u64)> {
    if !valid_id(id) {
        return Err(bad("Invalid transfer"));
    }
    let t = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Fault(
            StatusCode::UNAUTHORIZED,
            "Download authorization required",
        ))?;
    c.query_row("SELECT owner,vault,pieces FROM shares WHERE id=? AND state='receiving' AND deadline>? AND recipient=?",params![id,now(),hash(t)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(Fault(StatusCode::UNAUTHORIZED,"This download session has ended"))
}
async fn receive_piece(
    State(a): State<App>,
    h: HeaderMap,
    RoutePath((id, n)): RoutePath<(String, u64)>,
) -> Api<Response> {
    {
        let c = db(&a)?;
        let (_, _, count) = receiver(&c, &h, &id)?;
        if n >= count {
            return Err(bad("Invalid piece"));
        }
    }
    let bytes = tokio::fs::read(share_path(&a, &id).join(n.to_string())).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response())
}
async fn complete(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let c = db(&a)?;
    let (owner, vault, _) = receiver(&c, &h, &id)?;
    c.execute(
        "UPDATE shares SET state='complete',recipient='' WHERE id=?",
        [id],
    )?;
    audit(
        &c,
        None,
        Some(owner),
        "share_completed",
        false,
        &vault,
        0,
        &ip(&h, p),
    );
    Ok(Json(json!({"ok":true})))
}

fn prune_history(c: &mut Connection, a: &App, pressure: bool) -> Api<()> {
    // Three total revisions normally; one total under pressure. Never delete the current revision.
    let keep =
        if pressure && free_bytes(&a.cfg.data_dir)? < safety_floor(&a) + 4 * 1024 * 1024 * 1024 {
            1
        } else {
            3
        };
    c.execute("DELETE FROM revisions WHERE EXISTS(SELECT 1 FROM vaults v WHERE v.id=revisions.vault AND revisions.number<=v.revision-?)",[keep])?;
    if pressure {
        gc_blocks(c, a)?;
    }
    Ok(())
}
fn gc_blocks(c: &Connection, a: &App) -> Api<()> {
    let mut used = std::collections::HashSet::new();
    let mut st=c.prepare("SELECT v.owner,p.hash FROM revision_parts p JOIN vaults v ON v.id=p.vault UNION SELECT u.owner,p.hash FROM upload_parts p JOIN uploads u ON u.id=p.upload")?;
    for row in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
        used.insert(row?);
    }
    drop(st);
    for owner_dir in fs::read_dir(a.cfg.data_dir.join("blocks"))? {
        let d = owner_dir?;
        let Some(owner) = d.file_name().to_str().and_then(|s| s.parse::<i64>().ok()) else {
            continue;
        };
        for file in fs::read_dir(d.path())? {
            let f = file?;
            let name = f.file_name().to_string_lossy().to_string();
            if !used.contains(&(owner, name)) {
                let _ = fs::remove_file(f.path());
            }
        }
    }
    Ok(())
}
fn cleanup(c: &mut Connection, a: &App) -> Api<()> {
    let t = now();
    c.execute("DELETE FROM sessions WHERE expires<=?", [t])?;
    c.execute("DELETE FROM vault_leases WHERE expires<=? OR session NOT IN(SELECT hash FROM sessions) OR NOT EXISTS(SELECT 1 FROM vault_epochs e WHERE e.vault=vault_leases.vault AND e.epoch=vault_leases.epoch AND e.expires>? AND e.seconds>0)",params![t,t])?;
    c.execute("DELETE FROM challenges WHERE expires<=?", [t])?;
    c.execute("DELETE FROM uploads WHERE created<?", [t - UPLOAD_SECONDS])?;
    c.execute("DELETE FROM activity WHERE at<?", [t - 86400])?;
    c.execute("UPDATE shares SET state='expired',recipient='' WHERE (state='ready' AND expires<=?) OR (state='receiving' AND deadline<=?) OR (state='uploading' AND created<?)",params![t,t,t-UPLOAD_SECONDS])?;
    let mut st =
        c.prepare("SELECT id FROM shares WHERE state NOT IN ('uploading','ready','receiving')")?;
    let ids = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(st);
    for id in ids {
        let path = share_path(a, &id);
        if path.exists() {
            let _ = fs::remove_dir_all(path);
        }
    }
    c.execute(
        "DELETE FROM shares WHERE state NOT IN ('uploading','ready','receiving') AND created<?",
        [t - 86400],
    )?;
    Ok(())
}

async fn receive_html() -> Response {
    let nonce = random(18);
    let html = include_str!("../web/receive.html")
        .replace("/*VORTEX_CODEC*/", include_str!("../web/codec.js"))
        .replace("<script>", &format!("<script nonce=\"{nonce}\"> "))
        .replace("<style>", &format!("<style nonce=\"{nonce}\">"));
    let policy=format!("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; worker-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, policy.as_str()),
        ],
        html,
    )
        .into_response()
}
async fn worker() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../web/download-worker.js"),
    )
        .into_response()
}
async fn vault_html(State(a): State<App>) -> Api<Response> {
    let html = tokio::fs::read(&a.cfg.vault_html).await?;
    Ok(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response())
}
async fn gate_guard(
    State(a): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let login =
        request.method() == axum::http::Method::POST && request.uri().path().ends_with("/session");
    if !login && request.method() != axum::http::Method::OPTIONS {
        if let Err(e) = session(&a, request.headers(), peer) {
            return e.into_response();
        }
    }
    next.run(request).await
}
fn router(a: App) -> Router {
    let gate = format!("/gate/{}", a.cfg.bridge);
    let routes = Router::new()
        .route(
            "/session",
            post(login).get(current).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/forget", post(forget))
        .route("/preferences", post(preferences))
        .route("/panic", post(panic_logout))
        .route("/vault/{id}/remember", post(remember_vault))
        .route("/vault/{id}/remember/resume", post(resume_vault))
        .route("/vault/{id}/remember/forget", post(forget_vault))
        .route("/activity", get(activity))
        .route("/vaults", get(vaults).post(create_vault))
        .route("/vault/{id}", get(manifest).delete(remove_vault))
        .route("/vault/{id}/stage", post(stage))
        .route(
            "/upload/{id}/{n}",
            put(put_block).layer(DefaultBodyLimit::max(MAX_BLOCK)),
        )
        .route("/upload/{id}/finish", post(commit))
        .route("/vault/{id}/{rev}/{n}", get(read_block))
        .route("/vault/{id}/challenge", post(challenge))
        .route("/vault/{id}/verify", post(verify))
        .route("/shares", post(start_share).get(share_status))
        .route(
            "/share/{id}/{n}",
            put(share_piece).layer(DefaultBodyLimit::max(MAX_BLOCK)),
        )
        .route("/share/{id}/publish", post(publish))
        .route("/share/{id}", delete(revoke))
        .layer(axum::middleware::from_fn_with_state(a.clone(), gate_guard));
    Router::new()
        .route("/connect", get(info))
        .route("/health", get(health))
        .route("/", get(receive_html))
        .route("/receive/", get(receive_html))
        .route("/receive/{id}", get(receive_html))
        .route("/receive/worker.js", get(worker))
        .route(
            "/receive/preview/{id}",
            post(preview).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/receive/claim/{id}",
            post(claim).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/receive/piece/{id}/{n}", get(receive_piece))
        .route(
            "/receive/complete/{id}",
            post(complete).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/vault", get(vault_html))
        .route("/vault/", get(vault_html))
        .route("/Vault", get(vault_html))
        .nest(&gate, routes)
        .layer(DefaultBodyLimit::max(2 * MAX_MANIFEST + 65536))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("SAMEORIGIN"),
        ))
        .with_state(a)
}

fn base32(b: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut value, mut bits) = (String::new(), 0u32, 0);
    for x in b {
        value = (value << 8) | *x as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alphabet[((value >> bits) & 31) as usize] as char)
        }
    }
    if bits > 0 {
        out.push(alphabet[((value << (5 - bits)) & 31) as usize] as char)
    }
    out
}
fn decode32(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut val, mut bits) = (Vec::new(), 0u32, 0);
    for b in s.bytes() {
        let x = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        };
        val = (val << 5) | x as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((val >> bits) as u8)
        }
    }
    Some(out)
}
fn totp(seed: &str, step: i64) -> Option<String> {
    let key = decode32(seed)?;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).ok()?;
    mac.update(&(step as u64).to_be_bytes());
    let v = mac.finalize().into_bytes();
    let i = (v[19] & 15) as usize;
    let n = (u32::from_be_bytes(v[i..i + 4].try_into().ok()?) & 0x7fffffff) % 1_000_000;
    Some(format!("{n:06}"))
}
fn verify_totp(seed: &str, code: &str, last: i64) -> Option<i64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let t = now() / 30;
    for step in [t, t - 1, t + 1] {
        if step > last
            && totp(seed, step)
                .map(|x| bool::from(x.as_bytes().ct_eq(code.as_bytes())))
                .unwrap_or(false)
        {
            return Some(step);
        }
    }
    None
}
fn prompt(s: &str) -> Result<String> {
    print!("{s}");
    io::stdout().flush()?;
    let mut v = String::new();
    io::stdin().read_line(&mut v)?;
    Ok(v.trim_end_matches(['\r', '\n']).to_owned())
}
fn setup(path: &Path, stdin_user: Option<&str>) -> Result<()> {
    let c = initialize(path)?;
    let username = normalize_name(&match stdin_user {
        Some(s) => s.to_owned(),
        None => prompt("Node username (8-128 characters): ")?,
    });
    anyhow::ensure!(
        bounded(&username, 8, 128) && !username.trim().is_empty(),
        "Username must be 8-128 characters without control characters"
    );
    let mut password = if stdin_user.is_some() {
        prompt("")?
    } else {
        rpassword::prompt_password("Node password (15-128 characters): ")?
    };
    anyhow::ensure!(
        (15..=128).contains(&password.chars().count()) && password.len() <= 512,
        "Password must contain 15-128 characters"
    );
    if stdin_user.is_none() {
        let mut again = rpassword::prompt_password("Confirm password: ")?;
        let matches = password == again;
        again.zeroize();
        anyhow::ensure!(matches, "Passwords do not match")
    }
    let salt = SaltString::generate(&mut OsRng);
    let encoded = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
        .to_string();
    password.zeroize();
    let mut seed = String::new();
    if stdin_user.is_none()
        && prompt("Enable authenticator two-factor login? [y/N]: ")?.eq_ignore_ascii_case("y")
    {
        let mut b = [0u8; 20];
        OsRng.fill_bytes(&mut b);
        seed = base32(&b);
        b.zeroize();
        let label = username
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>();
        let uri=format!("otpauth://totp/Vortex%20Node:{label}?secret={seed}&issuer=Vortex%20Node&algorithm=SHA1&digits=6&period=30");
        let qr = qrcode::QrCode::new(uri.as_bytes())?;
        println!(
            "\n{}\n",
            qr.render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build()
        );
        println!("Manual authenticator secret: {seed}");
        let code = prompt("Scan the QR, then enter the six-digit code: ")?;
        anyhow::ensure!(
            verify_totp(&seed, &code, -1).is_some(),
            "Authenticator confirmation failed; account was not changed"
        );
    }
    c.execute("INSERT INTO accounts(username,password,totp) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET password=excluded.password,totp=excluded.totp,last_totp=-1",params![username,encoded,seed])?;
    c.execute(
        "DELETE FROM sessions WHERE owner=(SELECT id FROM accounts WHERE username=?)",
        [&username],
    )?;
    println!("Node account saved. Existing sessions for this account were revoked.");
    Ok(())
}
fn worker_budget() -> usize {
    // Leave CPU capacity for Nginx, SSH and other services on the host.
    let cores = std::thread::available_parallelism().map(usize::from).unwrap_or(1);
    cores.saturating_mul(7).div_ceil(10).clamp(1, 32)
}
fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_budget())
        .max_blocking_threads(32)
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|x| x == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    match args.get(1).map(String::as_str) {
        Some("setup") => {
            setup(
                Path::new(&arg("--data").context("--data is required")?),
                arg("--stdin-user").as_deref(),
            )?;
            return Ok(());
        }
        Some("check") => {
            let cfg: Config =
                serde_json::from_slice(&fs::read(arg("--config").context("--config required")?)?)?;
            let _ = initialize(&cfg.data_dir)?;
            println!("Configuration and database are readable");
            return Ok(());
        }
        Some("serve") => {}
        _ => {
            println!("Vortex Node\n  vortex-node serve --config PATH\n  vortex-node setup --data PATH\n  vortex-node check --config PATH");
            return Ok(());
        }
    }
    let cfg: Config =
        serde_json::from_slice(&fs::read(arg("--config").context("--config is required")?)?)?;
    anyhow::ensure!(
        cfg.listen.parse::<SocketAddr>()?.ip().is_loopback(),
        "Node must bind to loopback behind Nginx"
    );
    anyhow::ensure!(
        valid_id(&cfg.node_id) && valid_id(&cfg.bridge),
        "Invalid Node identity"
    );
    anyhow::ensure!(
        cfg.reserve_bytes >= FLOOR || std::env::var("VORTEX_TEST").as_deref() == Ok("1"),
        "Storage safety buffer must be at least 10 GB"
    );
    let c = initialize(&cfg.data_dir)?;
    let a = Arc::new(Inner {
        cfg,
        db: Mutex::new(c),
        rates: Mutex::new(HashMap::new()),
        auth_slots: Arc::new(tokio::sync::Semaphore::new(2)),
    });
    {
        let mut c = db(&a).map_err(|_| anyhow::anyhow!("Database unavailable"))?;
        cleanup(&mut c, &a).map_err(|_| anyhow::anyhow!("Recovery failed"))?;
        gc_blocks(&c, &a).map_err(|_| anyhow::anyhow!("Storage reconciliation failed"))?;
    }
    let maintenance = a.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Ok(mut c) = maintenance.db.lock() {
                let _ = cleanup(&mut c, &maintenance);
                let _ = prune_history(&mut c, &maintenance, false);
                let _ = gc_blocks(&c, &maintenance);
            }
        }
    });
    let listener = if std::env::var("LISTEN_FDS").as_deref() == Ok("1")
        && std::env::var("LISTEN_PID")
            .ok()
            .and_then(|x| x.parse::<u32>().ok())
            == Some(std::process::id())
    {
        use std::os::fd::FromRawFd;
        let inherited = unsafe { std::net::TcpListener::from_raw_fd(3) };
        anyhow::ensure!(
            inherited.local_addr()?.to_string() == a.cfg.listen,
            "Unexpected systemd socket"
        );
        inherited.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(inherited)?
    } else {
        tokio::net::TcpListener::bind(&a.cfg.listen).await?
    };
    println!("Vortex Node ready on {}", a.cfg.listen);
    axum::serve(
        listener,
        router(a).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn totp_rfc6238_sha1_vector() {
        let seed = base32(b"12345678901234567890");
        assert_eq!(totp(&seed, 1).as_deref(), Some("287082"));
        assert_eq!(decode32(&seed).unwrap(), b"12345678901234567890");
    }
    #[test]
    fn totp_replay_is_rejected() {
        let seed = base32(b"12345678901234567890");
        let step = now() / 30;
        let code = totp(&seed, step).unwrap();
        assert_eq!(verify_totp(&seed, &code, -1), Some(step));
        assert_eq!(verify_totp(&seed, &code, step), None);
    }
    #[test]
    fn block_bounds_and_paths() {
        assert!(validate_parts(&[Part {
            hash: hash(b"test"),
            size: 1
        }])
        .is_ok());
        assert!(validate_parts(&[Part {
            hash: "../secret".into(),
            size: 1
        }])
        .is_err());
        assert!(validate_parts(&[Part {
            hash: hash(b"test"),
            size: MAX_BLOCK as u64 + 1
        }])
        .is_err());
        assert!(!valid_id("../../../etc/shadow"));
    }
    #[test]
    fn vault_proof_cannot_be_replayed() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let dir = tempfile::tempdir().unwrap();
        let c = initialize(dir.path()).unwrap();
        let key = SigningKey::random(&mut OsRng);
        let public = B64.encode(key.verifying_key().to_encoded_point(false).as_bytes());
        let id = random(18);
        let s = Session {
            owner: 1,
            hash: "session-test".into(),
            expires: now() + 60,
            ip: "127.0.0.1".into(),
        };
        c.execute(
            "INSERT INTO vaults VALUES(?,1,'test',1,?)",
            params![id, public],
        )
        .unwrap();
        let ticket = random(24);
        let message = "domain-bound challenge";
        c.execute(
            "INSERT INTO challenges VALUES(?,?,?,?,?,?)",
            params![ticket, s.hash, id, "share", message, now() + 60],
        )
        .unwrap();
        let signature: Signature = key.sign(message.as_bytes());
        let proof = json!({"ticket":ticket,"signature":B64.encode(signature.to_bytes())});
        assert!(prove(&c, &s, &id, "verify", &proof).is_err());
        assert!(prove(&c, &s, &id, "share", &proof).is_ok());
        assert!(prove(&c, &s, &id, "share", &proof).is_err());
    }
    #[test]
    fn retention_never_removes_current() {
        let dir = tempfile::tempdir().unwrap();
        let c = initialize(dir.path()).unwrap();
        let id = random(18);
        c.execute("INSERT INTO vaults VALUES(?,1,'test',7,'')", [&id])
            .unwrap();
        for rev in 1..=7 {
            c.execute(
                "INSERT INTO revisions VALUES(?,?,?,1,0)",
                params![id, rev, "{}"],
            )
            .unwrap();
        }
        c.execute("DELETE FROM revisions WHERE EXISTS(SELECT 1 FROM vaults v WHERE v.id=revisions.vault AND revisions.number<=v.revision-3)",[]).unwrap();
        let rows: i64 = c
            .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 3);
        let latest: i64 = c
            .query_row("SELECT MAX(number) FROM revisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(latest, 7);
    }
}

