//! Bounded, ciphertext-only object storage. A job never changes the published root.
use super::*;
use axum::extract::Query;
use std::io::Read;

const PAGE: usize = 256;
const ROOT_LIMIT: usize = 128 * 1024;
const MAX_OBJECTS: i64 = 2_000_000;

pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS transfer_pieces(share TEXT NOT NULL,number INTEGER NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,ready INTEGER NOT NULL,PRIMARY KEY(share,number));
CREATE INDEX IF NOT EXISTS transfer_pending_sizes ON transfer_pieces(share,ready,size);
CREATE TRIGGER IF NOT EXISTS delete_transfer_pieces AFTER DELETE ON shares BEGIN DELETE FROM transfer_pieces WHERE share=old.id; END;
CREATE TABLE IF NOT EXISTS legacy_acks(upload TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(upload,hash));
CREATE TRIGGER IF NOT EXISTS delete_legacy_acks AFTER DELETE ON uploads BEGIN DELETE FROM legacy_acks WHERE upload=old.id; END;
CREATE TABLE IF NOT EXISTS object_jobs(id TEXT PRIMARY KEY,owner INTEGER NOT NULL,session TEXT NOT NULL,vault TEXT NOT NULL,base INTEGER NOT NULL,kind TEXT NOT NULL,epoch TEXT NOT NULL,public_key TEXT NOT NULL,renewal_key TEXT NOT NULL,seconds INTEGER NOT NULL,issued INTEGER NOT NULL,deadline INTEGER NOT NULL,budget INTEGER NOT NULL,remaining INTEGER NOT NULL,checkpoint TEXT NOT NULL DEFAULT '',root TEXT NOT NULL DEFAULT '',objects INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS job_objects(job TEXT NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,ready INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(job,hash));
CREATE TABLE IF NOT EXISTS revision_objects(vault TEXT NOT NULL,revision INTEGER NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(vault,revision,hash));
CREATE TABLE IF NOT EXISTS vault_renewal(vault TEXT PRIMARY KEY,public_key TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS job_pending_sizes ON job_objects(job,ready,size);
CREATE INDEX IF NOT EXISTS job_hash ON job_objects(hash,job);
CREATE INDEX IF NOT EXISTS jobs_vault ON object_jobs(vault,base);
CREATE INDEX IF NOT EXISTS object_references ON revision_objects(hash,vault);
CREATE INDEX IF NOT EXISTS legacy_references ON revision_parts(hash,vault);
CREATE INDEX IF NOT EXISTS upload_references ON upload_parts(hash,upload);
CREATE TRIGGER IF NOT EXISTS delete_revision_objects AFTER DELETE ON revisions BEGIN DELETE FROM revision_objects WHERE vault=old.vault AND revision=old.number; END;
CREATE TRIGGER IF NOT EXISTS delete_job_objects AFTER DELETE ON object_jobs BEGIN DELETE FROM job_objects WHERE job=old.id; END;")?;
    let columns = c
        .prepare("PRAGMA table_info(object_jobs)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !columns.iter().any(|s| s == "objects") {
        c.execute(
            "ALTER TABLE object_jobs ADD COLUMN objects INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
        c.execute("UPDATE object_jobs SET objects=(SELECT COUNT(*) FROM job_objects WHERE job=object_jobs.id)",[])?;
    }
    Ok(())
}

fn key_valid(public: &str) -> Api<()> {
    let raw = B64
        .decode(public)
        .map_err(|_| bad("Invalid verification key"))?;
    VerifyingKey::from_sec1_bytes(&raw).map_err(|_| bad("Invalid verification key"))?;
    Ok(())
}
fn live_session(c: &Connection, s: &Session) -> Api<()> {
    let yes: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE hash=? AND owner=? AND expires>?)",
        params![s.hash, s.owner, now()],
        |r| r.get(0),
    )?;
    if !yes {
        return Err(Fault(
            StatusCode::UNAUTHORIZED,
            "Your Node login has expired",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct Begin {
    base: i64,
    kind: String,
    epoch: String,
    public_key: String,
    renewal_key: String,
    seconds: i64,
    budget: u64,
    #[serde(default)]
    proof: Value,
}

pub(super) async fn renewal_challenge(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    rate(&a, format!("renew:{}", s.hash), 30)?;
    let c = db(&a)?;
    let (revision, _) = owned(&c, &s, &id)?;
    let epoch = text(&v, "epoch");
    let public = text(&v, "public_key");
    let renewal = text(&v, "renewal_key");
    if !valid_hash(&epoch) {
        return Err(bad("Invalid encryption generation"));
    }
    key_valid(&public)?;
    key_valid(&renewal)?;
    let ticket = random(24);
    let message=json!({"domain":"Vortex fresh unlock","node":a.cfg.node_id,"vault":id,"revision":revision,"session":s.hash,"epoch":epoch,"public_key":public,"renewal_key":renewal,"ticket":ticket,"expires":now()+120}).to_string();
    c.execute(
        "INSERT INTO challenges VALUES(?,?,?,?,?,?)",
        params![ticket, s.hash, id, "renew", message, now() + 120],
    )?;
    Ok(Json(json!({"ticket":ticket,"message":message})))
}

pub(super) async fn begin(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Begin>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !["edit", "renew"].contains(&v.kind.as_str())
        || !valid_hash(&v.epoch)
        || !(0..=604800).contains(&v.seconds)
        || v.budget > MAX_VAULT + MAX_VAULT / 8
        || v.budget < ROOT_LIMIT as u64
    {
        return Err(bad("Invalid encrypted write job"));
    }
    key_valid(&v.public_key)?;
    key_valid(&v.renewal_key)?;
    let mut c = db(&a)?;
    owned(&c, &s, &id)?;
    if reserve(&c, &a, v.budget).is_err() {
        prune_history(&c, &a, true)?;
    }
    let tx = c.transaction()?;
    live_session(&tx, &s)?;
    let (base, old_public) = owned(&tx, &s, &id)?;
    if base != v.base {
        return Err(Fault(
            StatusCode::PRECONDITION_FAILED,
            "This vault changed on another device",
        ));
    }
    let old: Option<(String, i64, i64)> = tx
        .query_row(
            "SELECT epoch,issued,expires FROM vault_epochs WHERE vault=?",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let renewal: Option<String> = tx
        .query_row(
            "SELECT public_key FROM vault_renewal WHERE vault=?",
            [&id],
            |r| r.get(0),
        )
        .optional()?;
    let (issued, deadline) = if v.kind == "renew" {
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_epoch_history WHERE vault=? AND epoch=?)",
            params![id, v.epoch],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Fault(
                StatusCode::CONFLICT,
                "A retired encryption generation cannot be reused",
            ));
        }
        if base > 0 {
            let ticket = text(&v.proof, "ticket");
            let message:String=tx.query_row("SELECT message FROM challenges WHERE id=? AND session=? AND vault=? AND purpose='renew' AND expires>?",params![ticket,s.hash,id,now()],|r|r.get(0)).optional()?.ok_or(Fault(StatusCode::FORBIDDEN,"Fresh passphrase verification is required"))?;
            let m: Value =
                serde_json::from_str(&message).map_err(|_| bad("Invalid renewal proof"))?;
            if m["revision"] != base
                || text(&m, "epoch") != v.epoch
                || text(&m, "public_key") != v.public_key
                || text(&m, "renewal_key") != v.renewal_key
            {
                return Err(Fault(
                    StatusCode::FORBIDDEN,
                    "Renewal proof belongs to another write",
                ));
            }
            // A legacy vault may bootstrap this authority once, using its old signing key.
            let authority = renewal.as_deref().unwrap_or(&old_public);
            let raw = B64
                .decode(authority)
                .map_err(|_| bad("Invalid renewal key"))?;
            let key =
                VerifyingKey::from_sec1_bytes(&raw).map_err(|_| bad("Invalid renewal key"))?;
            let sig = B64
                .decode(text(&v.proof, "signature"))
                .map_err(|_| bad("Invalid renewal proof"))?;
            key.verify(
                message.as_bytes(),
                &Signature::from_slice(&sig).map_err(|_| bad("Invalid renewal proof"))?,
            )
            .map_err(|_| {
                Fault(
                    StatusCode::FORBIDDEN,
                    "Fresh passphrase verification failed",
                )
            })?;
            tx.execute("DELETE FROM challenges WHERE id=?", [ticket])?;
        }
        let t = now();
        (t, t + if v.seconds == 0 { 604800 } else { v.seconds })
    } else {
        let e = old.as_ref().ok_or(bad("Unlock this vault first"))?;
        if (v.kind == "edit" && e.0 != v.epoch) || e.2 <= now() {
            return Err(Fault(
                StatusCode::LOCKED,
                "Vault session expired. Unlock with your full passphrase again",
            ));
        }
        if v.kind == "edit"
            && (old_public != v.public_key || renewal.as_deref() != Some(v.renewal_key.as_str()))
        {
            return Err(Fault(
                StatusCode::FORBIDDEN,
                "An ordinary save cannot change vault authority",
            ));
        }
        prove(&tx, &s, &id, "write", &v.proof)?;
        (
            e.1,
            e.2.min(e.1 + if v.seconds == 0 { 604800 } else { v.seconds }),
        )
    };
    // Serialize writers, but never silently discard another device's live job.
    tx.execute(
        "DELETE FROM object_jobs WHERE deadline<=? OR session NOT IN(SELECT hash FROM sessions)",
        [now()],
    )?;
    if v.kind == "renew" {
        tx.execute("DELETE FROM object_jobs WHERE vault=?", [&id])?;
    }
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_jobs WHERE vault=?)",
        [&id],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(Fault(
            StatusCode::CONFLICT,
            "An encrypted save is already in progress",
        ));
    }
    reserve(&tx, &a, v.budget)?;
    let uid = random(24);
    tx.execute("INSERT INTO object_jobs(id,owner,session,vault,base,kind,epoch,public_key,renewal_key,seconds,issued,deadline,budget,remaining) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![uid,s.owner,s.hash,id,base,v.kind,v.epoch,v.public_key,v.renewal_key,v.seconds,issued,deadline,v.budget as i64,v.budget as i64])?;
    tx.commit()?;
    Ok(Json(
        json!({"job":uid,"deadline":deadline,"issued":issued,"server_now":now()}),
    ))
}

fn live_job(c: &Connection, s: &Session, uid: &str) -> Api<(String, i64, i64)> {
    if !valid_id(uid) {
        return Err(bad("Invalid encrypted write job"));
    }
    live_session(c, s)?;
    let row:Option<(String,i64,i64)>=c.query_row("SELECT j.vault,j.base,j.deadline FROM object_jobs j JOIN vaults v ON v.id=j.vault AND v.owner=j.owner AND v.revision=j.base WHERE j.id=? AND j.owner=? AND j.session=? AND j.deadline>?",params![uid,s.owner,s.hash,now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    row.ok_or(Fault(
        StatusCode::LOCKED,
        "Encrypted write expired or its source revision changed",
    ))
}

pub(super) async fn register(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
    Json(parts): Json<Vec<Part>>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if parts.is_empty() || parts.len() > PAGE {
        return Err(bad("Invalid encrypted catalog page"));
    }
    for part in &parts {
        if !valid_hash(&part.hash) || part.size < 16 || part.size > MAX_BLOCK as u64 {
            return Err(bad("Invalid encrypted object"));
        }
    }
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    live_job(&tx, &s, &uid)?;
    let mut missing = Vec::new();
    let mut added = 0i64;
    for part in &parts {
        let prior: Option<i64> = tx
            .query_row(
                "SELECT size FROM job_objects WHERE job=? AND hash=?",
                params![uid, part.hash],
                |r| r.get(0),
            )
            .optional()?;
        if prior.is_some_and(|n| n != part.size as i64) {
            return Err(bad("Encrypted object size changed"));
        }
        let ready = fs::metadata(block_path(&a, s.owner, &part.hash))
            .map(|m| m.len() == part.size)
            .unwrap_or(false);
        if prior.is_none() {
            added += 1;
            let allocated: i64 = tx.query_row(
                "SELECT COALESCE(SUM(size),0) FROM job_objects WHERE job=? AND ready=0",
                [&uid],
                |r| r.get(0),
            )?;
            let remaining: i64 = tx.query_row(
                "SELECT remaining FROM object_jobs WHERE id=?",
                [&uid],
                |r| r.get(0),
            )?;
            if !ready && allocated.saturating_add(part.size as i64) > remaining {
                return Err(Fault(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Encrypted write exceeded its reservation",
                ));
            }
            tx.execute(
                "INSERT INTO job_objects VALUES(?,?,?,?)",
                params![uid, part.hash, part.size as i64, ready as i32],
            )?;
        }
        if !ready {
            missing.push(part.hash.clone());
        }
    }
    let count: i64 = tx.query_row("SELECT objects FROM object_jobs WHERE id=?", [&uid], |r| {
        r.get(0)
    })?;
    if count + added > MAX_OBJECTS {
        return Err(bad("Encrypted catalog is too large"));
    }
    tx.execute(
        "UPDATE object_jobs SET objects=objects+? WHERE id=?",
        params![added, uid],
    )?;
    tx.commit()?;
    Ok(Json(json!({"missing":missing})))
}

pub(super) async fn put_object(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((uid, digest)): RoutePath<(String, String)>,
    body: Bytes,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !valid_hash(&digest) || body.len() < 16 || body.len() > MAX_BLOCK || hash(&body) != digest {
        return Err(bad("Encrypted object integrity check failed"));
    }
    let size = {
        let c = db(&a)?;
        live_job(&c, &s, &uid)?;
        c.query_row(
            "SELECT size FROM job_objects WHERE job=? AND hash=?",
            params![uid, digest],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(bad("Register this ciphertext object first"))?
    };
    if size != body.len() as i64 {
        return Err(bad("Encrypted object size mismatch"));
    }
    let permit = a
        .io_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Fault(StatusCode::SERVICE_UNAVAILABLE, "Storage busy"))?;
    let app = a.clone();
    let owner = s.owner;
    let expected = digest.clone();
    tokio::task::spawn_blocking(move || -> Api<()> {
        let _permit = permit;
        durable_object(&app, owner, &expected, &body)
    })
    .await
    .map_err(|_| Fault(StatusCode::SERVICE_UNAVAILABLE, "Storage write interrupted"))??;
    // Recheck after disk I/O. Uncommitted ciphertext is harmless and reclaimed by GC.
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    live_job(&tx, &s, &uid)?;
    if tx.execute(
        "UPDATE job_objects SET ready=1 WHERE job=? AND hash=? AND ready=0",
        params![uid, digest],
    )? == 1
    {
        tx.execute(
            "UPDATE object_jobs SET remaining=MAX(0,remaining-?) WHERE id=?",
            params![size, uid],
        )?;
    }
    tx.commit()?;
    Ok(Json(json!({"ok":true})))
}

pub(super) fn durable_object(a: &App, owner: i64, digest: &str, body: &[u8]) -> Api<()> {
    let path = block_path(a, owner, digest);
    durable_file(a, &path, digest, body)
}
pub(super) fn durable_file(a: &App, path: &Path, digest: &str, body: &[u8]) -> Api<()> {
    if let Ok(mut f) = fs::File::open(&path) {
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        if bytes.len() == body.len() && hash(&bytes) == digest {
            return Ok(());
        }
    }
    if free_bytes(&a.cfg.data_dir)?.saturating_sub(body.len() as u64) < safety_floor(a) {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "Storage buffer reached",
        ));
    }
    fs::create_dir_all(path.parent().unwrap())?;
    let temp = path.with_extension(random(12));
    let result = (|| -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        f.write_all(body)?;
        f.sync_all()?;
        fs::rename(&temp, &path)?;
        sync_directory(path.parent().unwrap())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct Finish {
    root: String,
    bytes: u64,
    signature: String,
    #[serde(default)]
    checkpoint: String,
    #[serde(default = "default_copies")]
    copies: i64,
    #[serde(default = "default_history")]
    history: i64,
}
fn default_copies() -> i64 {
    2
}
fn default_history() -> i64 {
    1
}

pub(super) async fn finish(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
    Json(v): Json<Finish>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let root = B64
        .decode(&v.root)
        .map_err(|_| bad("Invalid encrypted root"))?;
    if root.len() < 192 + 16
        || root[7] != 2
        || !(1..=3).contains(&v.copies)
        || !(0..=3).contains(&v.history)
        || root.len() > ROOT_LIMIT
        || v.bytes > MAX_VAULT
        || v.checkpoint.len() > ROOT_LIMIT * 2
    {
        return Err(bad("Invalid encrypted root"));
    }
    let epoch = key_epoch(&root).ok_or(bad("An encrypted root requires a protected header"))?;
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    let (id, base, deadline) = live_job(&tx, &s, &uid)?;
    let (kind, target, public, renewal, seconds, issued): (
        String,
        String,
        String,
        String,
        i64,
        i64,
    ) = tx.query_row(
        "SELECT kind,epoch,public_key,renewal_key,seconds,issued FROM object_jobs WHERE id=?",
        [&uid],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    if epoch != target {
        return Err(bad("Encrypted root belongs to another generation"));
    }
    let intent = json!([
        "Vortex encrypted commit",
        a.cfg.node_id,
        id,
        uid,
        base,
        epoch,
        hash(&root),
        v.bytes
    ])
    .to_string();
    let pubkey = B64
        .decode(&public)
        .map_err(|_| bad("Invalid verification key"))?;
    let sig = B64
        .decode(&v.signature)
        .map_err(|_| bad("Invalid encrypted commit proof"))?;
    VerifyingKey::from_sec1_bytes(&pubkey)
        .map_err(|_| bad("Invalid verification key"))?
        .verify(
            intent.as_bytes(),
            &Signature::from_slice(&sig).map_err(|_| bad("Invalid encrypted commit proof"))?,
        )
        .map_err(|_| {
            Fault(
                StatusCode::FORBIDDEN,
                "Unlock the vault to publish this encrypted revision",
            )
        })?;

    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM job_objects WHERE job=? AND ready=0)",
        [&uid],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(bad("Encrypted upload is incomplete"));
    }
    let used: i64 = tx.query_row(
        "SELECT COALESCE(SUM(size),0) FROM job_objects WHERE job=?",
        [&uid],
        |r| r.get(0),
    )?;
    if used as u64 > MAX_VAULT + MAX_VAULT / 8 {
        return Err(bad("Vault exceeds its encrypted storage limit"));
    }
    if kind != "renew" {
        check_epoch(&tx, &id)?;
    }
    if kind != "edit"
        && tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_epoch_history WHERE vault=? AND epoch=?)",
            params![id, epoch],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Err(Fault(
            StatusCode::CONFLICT,
            "Encryption generation was already used",
        ));
    }
    let descriptor = json!({"format":"paged","layout":4,"root":v.root,"epoch":epoch,"copies":v.copies,"history":v.history,"bytes":v.bytes,"stored":used,"objects":tx.query_row("SELECT COUNT(*) FROM job_objects WHERE job=?",[&uid],|r|r.get::<_,i64>(0))?});
    tx.execute(
        "INSERT INTO revisions VALUES(?,?,?,?,?)",
        params![id, base + 1, descriptor.to_string(), used, now()],
    )?;
    tx.execute(
        "INSERT INTO revision_objects SELECT ?,?,hash,size FROM job_objects WHERE job=?",
        params![id, base + 1, uid],
    )?;
    tx.execute(
        "UPDATE vaults SET revision=?,public_key=? WHERE id=? AND revision=?",
        params![base + 1, public, id, base],
    )?;
    tx.execute("INSERT INTO vault_renewal VALUES(?,?) ON CONFLICT(vault) DO UPDATE SET public_key=excluded.public_key",params![id,renewal])?;
    tx.execute("INSERT INTO vault_epochs VALUES(?,?,?,?,?) ON CONFLICT(vault) DO UPDATE SET epoch=excluded.epoch,issued=excluded.issued,expires=excluded.expires,seconds=excluded.seconds",params![id,epoch,issued,deadline,seconds])?;
    tx.execute("INSERT INTO vault_epoch_history VALUES(?,?,?) ON CONFLICT(vault,epoch) DO UPDATE SET expires=MIN(expires,excluded.expires)",params![id,epoch,deadline])?;
    if kind != "edit" || seconds == 0 {
        tx.execute("DELETE FROM vault_leases WHERE vault=?", [&id])?;
    }
    tx.execute("DELETE FROM object_jobs WHERE id=?", [&uid])?;
    audit(
        &tx,
        Some(&s),
        None,
        "vault_saved",
        true,
        &id,
        v.bytes,
        &s.ip,
    );
    tx.commit()?;
    Ok(Json(
        json!({"revision":base+1,"bytes":v.bytes,"unlock":{"epoch":epoch,"issued":issued,"expires":deadline,"seconds":seconds,"server_now":now()}}),
    ))
}

pub(super) async fn job(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    live_job(&c, &s, &uid)?;
    let value=c.query_row("SELECT vault,base,epoch,deadline,checkpoint,remaining FROM object_jobs WHERE id=?",[&uid],|r|Ok(json!({"vault":r.get::<_,String>(0)?,"base":r.get::<_,i64>(1)?,"epoch":r.get::<_,String>(2)?,"deadline":r.get::<_,i64>(3)?,"checkpoint":r.get::<_,String>(4)?,"remaining":r.get::<_,i64>(5)?})))?;
    Ok(Json(value))
}
pub(super) async fn cancel(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    db(&a)?.execute(
        "DELETE FROM object_jobs WHERE id=? AND owner=? AND session=?",
        params![uid, s.owner, s.hash],
    )?;
    Ok(Json(json!({"ok":true})))
}
pub(super) async fn checkpoint(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let value = text(&v, "checkpoint");
    if value.len() > ROOT_LIMIT * 2 {
        return Err(bad("Checkpoint too large"));
    }
    let c = db(&a)?;
    live_job(&c, &s, &uid)?;
    let public = text(&v, "header");
    let header = B64
        .decode(&public)
        .map_err(|_| bad("Invalid checkpoint header"))?;
    if header.len() != 192
        || header[7] != 2
        || key_epoch(&header)
            != Some(
                c.query_row("SELECT epoch FROM object_jobs WHERE id=?", [&uid], |r| {
                    r.get::<_, String>(0)
                })?,
            )
    {
        return Err(bad("Invalid checkpoint generation"));
    }
    c.execute(
        "UPDATE object_jobs SET checkpoint=?,root=? WHERE id=?",
        params![value, public, uid],
    )?;
    Ok(Json(json!({"ok":true})))
}

pub(super) async fn grow(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(uid): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let extra = v["extra"]
        .as_u64()
        .filter(|x| *x > 0 && *x <= MAX_VAULT)
        .ok_or(bad("Invalid storage reservation"))?;
    let mut c = db(&a)?;
    live_job(&c, &s, &uid)?;
    if reserve(&c, &a, extra).is_err() {
        prune_history(&c, &a, true)?;
    }
    let tx = c.transaction()?;
    live_job(&tx, &s, &uid)?;
    let budget: i64 = tx.query_row("SELECT budget FROM object_jobs WHERE id=?", [&uid], |r| {
        r.get(0)
    })?;
    if budget as u64 + extra > MAX_VAULT + MAX_VAULT / 8 {
        return Err(bad("Encrypted write exceeds the per-vault limit"));
    }
    reserve(&tx, &a, extra)?;
    tx.execute(
        "UPDATE object_jobs SET budget=budget+?,remaining=remaining+? WHERE id=?",
        params![extra as i64, extra as i64, uid],
    )?;
    tx.commit()?;
    Ok(Json(json!({"budget":budget as u64+extra})))
}

pub(super) async fn object(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((id, revision, digest)): RoutePath<(String, i64, String)>,
) -> Api<Response> {
    let s = session(&a, &h, p)?;
    if !valid_hash(&digest) {
        return Err(bad("Invalid encrypted object"));
    }
    let size = {
        let c = db(&a)?;
        owned(&c, &s, &id)?;
        c.query_row(
            "SELECT size FROM revision_objects WHERE vault=? AND revision=? AND hash=?",
            params![id, revision, digest],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(Fault(StatusCode::NOT_FOUND, "Encrypted object unavailable"))?
    };
    let _permit = a
        .io_slots
        .acquire()
        .await
        .map_err(|_| Fault(StatusCode::SERVICE_UNAVAILABLE, "Storage busy"))?;
    let bytes = tokio::fs::read(block_path(&a, s.owner, &digest)).await?;
    if bytes.len() != size as usize || hash(&bytes) != digest {
        return Err(Fault(StatusCode::CONFLICT, "Encrypted object is damaged"));
    }
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

pub(super) async fn job_object(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((uid, digest)): RoutePath<(String, String)>,
) -> Api<Response> {
    let s = session(&a, &h, p)?;
    if !valid_hash(&digest) {
        return Err(bad("Invalid encrypted object"));
    }
    let size = {
        let c = db(&a)?;
        live_job(&c, &s, &uid)?;
        c.query_row(
            "SELECT size FROM job_objects WHERE job=? AND hash=? AND ready=1",
            params![uid, digest],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(Fault(StatusCode::NOT_FOUND, "Encrypted object unavailable"))?
    };
    let _permit = a
        .io_slots
        .acquire()
        .await
        .map_err(|_| Fault(StatusCode::SERVICE_UNAVAILABLE, "Storage busy"))?;
    let bytes = tokio::fs::read(block_path(&a, s.owner, &digest)).await?;
    if bytes.len() != size as usize || hash(&bytes) != digest {
        return Err(Fault(StatusCode::CONFLICT, "Encrypted object is damaged"));
    }
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

#[derive(Deserialize)]
pub(super) struct Cursor {
    #[serde(default)]
    after: String,
}
pub(super) async fn catalog(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath((id, revision)): RoutePath<(String, i64)>,
    Query(q): Query<Cursor>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    if !q.after.is_empty() && !valid_hash(&q.after) {
        return Err(bad("Invalid encrypted catalog cursor"));
    }
    let c = db(&a)?;
    owned(&c, &s, &id)?;
    let mut st=c.prepare("SELECT hash,size FROM revision_objects WHERE vault=? AND revision=? AND hash>? ORDER BY hash LIMIT 256")?;
    let parts = st
        .query_map(params![id, revision, q.after], |r| {
            Ok(Part {
                hash: r.get(0)?,
                size: r.get::<_, i64>(1)? as u64,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let next = if parts.len() == PAGE {
        parts.last().map(|p| p.hash.clone())
    } else {
        None
    };
    Ok(Json(json!({"objects":parts,"next":next})))
}

pub(super) async fn history(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    owned(&c, &s, &id)?;
    let mut query=c.prepare("SELECT number,manifest,created FROM revisions WHERE vault=? AND json_extract(manifest,'$.format')='paged' ORDER BY number DESC LIMIT 3")?;
    let rows = query
        .query_map([&id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut values = Vec::new();
    for (revision, raw, created) in rows {
        let mut value: Value =
            serde_json::from_str(&raw).map_err(|_| bad("Encrypted revision is damaged"))?;
        value["revision"] = json!(revision);
        value["created"] = json!(created);
        values.push(value);
    }
    Ok(Json(json!({"revisions":values})))
}

pub(super) fn cleanup(c: &Connection) -> Api<()> {
    c.execute("DELETE FROM object_jobs WHERE deadline<=? OR session NOT IN(SELECT hash FROM sessions) OR NOT EXISTS(SELECT 1 FROM vaults v WHERE v.id=object_jobs.vault AND v.revision=object_jobs.base)",[now()])?;
    Ok(())
}

pub(super) async fn pending(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    let c = db(&a)?;
    let (base, _) = owned(&c, &s, &id)?;
    let value=c.query_row("SELECT id,kind,epoch,deadline,issued,budget,remaining,checkpoint,root,public_key,renewal_key FROM object_jobs WHERE owner=? AND session=? AND vault=? AND base=? AND deadline>?",params![s.owner,s.hash,id,base,now()],|r|Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"epoch":r.get::<_,String>(2)?,"deadline":r.get::<_,i64>(3)?,"issued":r.get::<_,i64>(4)?,"budget":r.get::<_,i64>(5)?,"remaining":r.get::<_,i64>(6)?,"checkpoint":r.get::<_,String>(7)?,"header":r.get::<_,String>(8)?,"public_key":r.get::<_,String>(9)?,"renewal_key":r.get::<_,String>(10)?,"base":base}))).optional()?;
    Ok(Json(json!({"pending":value})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    fn fixture() -> (
        tempfile::TempDir,
        App,
        HeaderMap,
        String,
        SigningKey,
        SigningKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let c = super::super::initialize(dir.path()).unwrap();
        initialize(&c).unwrap();
        crate::export::initialize(&c).unwrap();
        let signing = SigningKey::random(&mut OsRng);
        let renewal = SigningKey::random(&mut OsRng);
        let id = random(18);
        let token = random(32);
        let public = B64.encode(signing.verifying_key().to_encoded_point(false).as_bytes());
        let renew = B64.encode(renewal.verifying_key().to_encoded_point(false).as_bytes());
        c.execute(
            "INSERT INTO accounts VALUES(1,'integration-user','unused','',-1)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO sessions VALUES(?,1,?,?,'test')",
            params![hash(&token), now() + 86400, now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO vaults VALUES(?,1,'private',1,?)",
            params![id, public],
        )
        .unwrap();
        c.execute(
            "INSERT INTO revisions VALUES(?,1,'{}',0,?)",
            params![id, now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO vault_epochs VALUES(?,?,?, ?,86400)",
            params![id, hash(b"old"), now() - 100, now() + 3600],
        )
        .unwrap();
        c.execute("INSERT INTO vault_renewal VALUES(?,?)", params![id, renew])
            .unwrap();
        let a = Arc::new(Inner {
            cfg: Config {
                vault_enabled: true,
                public_url: None,
                chat_web_dir: None,
                media:None,
                email:default_email(),
                listen: "127.0.0.1:0".into(),
                data_dir: dir.path().to_owned(),
                vault_html: dir.path().join("unused.html"),
                node_id: random(18),
                bridge: random(18),
                reserve_bytes: FLOOR,
            },
            db: Mutex::new(c),
            rates: Mutex::new(HashMap::new()),
            traffic:Mutex::new(traffic::Traffic::default()),
            public_slots:Arc::new(tokio::sync::Semaphore::new(24)),
            chat_stream_slots:Arc::new(tokio::sync::Semaphore::new(256)),
            chat_events:tokio::sync::broadcast::channel(256).0,
            auth_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            io_slots: Arc::new(tokio::sync::Semaphore::new(8)),
            request_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            gc: Mutex::new(GcCursor::default()),
        });
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        (dir, a, h, id, signing, renewal)
    }
    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:4242".parse().unwrap())
    }
    fn header() -> Vec<u8> {
        let mut h = vec![0u8; 208];
        h[..4].copy_from_slice(b"AVLT");
        h[4] = 3;
        h[5] = 1;
        h[6] = 1;
        h[7] = 2;
        OsRng.fill_bytes(&mut h[16..48]);
        h
    }
    async fn proposed(
        a: &App,
        h: &HeaderMap,
        id: &str,
        root: &[u8],
        key: &SigningKey,
        authority: &SigningKey,
    ) -> Begin {
        let public = B64.encode(key.verifying_key().to_encoded_point(false).as_bytes());
        let renew = SigningKey::random(&mut OsRng);
        let renewal_key = B64.encode(renew.verifying_key().to_encoded_point(false).as_bytes());
        let epoch = key_epoch(root).unwrap();
        let Json(ch) = renewal_challenge(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(id.into()),
            Json(json!({"epoch":epoch,"public_key":public,"renewal_key":renewal_key})),
        )
        .await
        .unwrap();
        let signature: Signature = authority.sign(text(&ch, "message").as_bytes());
        Begin {
            base: 1,
            kind: "renew".into(),
            epoch,
            public_key: public,
            renewal_key,
            seconds: 86400,
            budget: 16 * 1024 * 1024,
            proof: json!({"ticket":ch["ticket"],"signature":B64.encode(signature.to_bytes())}),
        }
    }
    fn finish_body(a: &App, id: &str, job: &str, root: Vec<u8>, key: &SigningKey) -> Finish {
        let intent = json!([
            "Vortex encrypted commit",
            a.cfg.node_id,
            id,
            job,
            1,
            key_epoch(&root).unwrap(),
            hash(&root),
            0
        ])
        .to_string();
        let sig: Signature = key.sign(intent.as_bytes());
        Finish {
            root: B64.encode(root),
            bytes: 0,
            signature: B64.encode(sig.to_bytes()),
            checkpoint: String::new(),
            copies: 2,
            history: 1,
        }
    }
    #[tokio::test]
    async fn renewal_needs_separate_authority_and_atomic_signed_commit() {
        let (_dir, a, h, id, old, renewal) = fixture();
        let root = header();
        let next = SigningKey::random(&mut OsRng);
        let forged = proposed(&a, &h, &id, &root, &next, &old).await;
        assert_eq!(
            begin(
                State(a.clone()),
                peer(),
                h.clone(),
                RoutePath(id.clone()),
                Json(forged)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        let valid = proposed(&a, &h, &id, &root, &next, &renewal).await;
        let Json(start) = begin(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(id.clone()),
            Json(valid),
        )
        .await
        .unwrap();
        let job = text(&start, "job");
        let before: i64 = db(&a)
            .unwrap()
            .query_row("SELECT revision FROM vaults WHERE id=?", [&id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(before, 1);
        let wrong = finish_body(&a, &id, &job, root.clone(), &old);
        assert_eq!(
            finish(
                State(a.clone()),
                peer(),
                h.clone(),
                RoutePath(job.clone()),
                Json(wrong)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        let body = finish_body(&a, &id, &job, root, &next);
        let Json(done) = finish(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(job.clone()),
            Json(body),
        )
        .await
        .unwrap();
        assert_eq!(done["revision"], 2);
        assert!(job_exists(&a, &job) == 0);
        assert_eq!(
            db(&a)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM vault_epoch_history WHERE vault=?",
                    [id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }
    fn job_exists(a: &App, id: &str) -> i64 {
        db(a)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM object_jobs WHERE id=?", [id], |r| {
                r.get(0)
            })
            .unwrap()
    }
    #[tokio::test]
    async fn expired_job_and_revoked_account_cannot_publish() {
        let (_dir, a, h, id, _old, renewal) = fixture();
        let root = header();
        let next = SigningKey::random(&mut OsRng);
        let valid = proposed(&a, &h, &id, &root, &next, &renewal).await;
        let Json(start) = begin(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(id.clone()),
            Json(valid),
        )
        .await
        .unwrap();
        let job = text(&start, "job");
        db(&a)
            .unwrap()
            .execute(
                "UPDATE object_jobs SET deadline=? WHERE id=?",
                params![now() - 1, job],
            )
            .unwrap();
        let body = finish_body(&a, &id, &job, root.clone(), &next);
        assert_eq!(
            finish(
                State(a.clone()),
                peer(),
                h.clone(),
                RoutePath(job.clone()),
                Json(body)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::LOCKED
        );
        db(&a)
            .unwrap()
            .execute(
                "UPDATE object_jobs SET deadline=? WHERE id=?",
                params![now() + 3600, job],
            )
            .unwrap();
        db(&a).unwrap().execute("DELETE FROM sessions", []).unwrap();
        let body = finish_body(&a, &id, &job, root, &next);
        assert_eq!(
            finish(
                State(a.clone()),
                peer(),
                h.clone(),
                RoutePath(job),
                Json(body)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            db(&a)
                .unwrap()
                .query_row("SELECT revision FROM vaults WHERE id=?", [id], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn object_ack_is_durable_idempotent_and_checks_digest() {
        let (_dir, a, h, id, _old, renewal) = fixture();
        let root = header();
        let next = SigningKey::random(&mut OsRng);
        let valid = proposed(&a, &h, &id, &root, &next, &renewal).await;
        let Json(start) = begin(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(id.clone()),
            Json(valid),
        )
        .await
        .unwrap();
        let job = text(&start, "job");
        let body = Bytes::from(vec![42; 1024]);
        let digest = hash(&body);
        let _ = register(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath(job.clone()),
            Json(vec![Part {
                hash: digest.clone(),
                size: 1024,
            }]),
        )
        .await
        .unwrap();
        assert!(put_object(
            State(a.clone()),
            peer(),
            h.clone(),
            RoutePath((job.clone(), digest.clone())),
            Bytes::from(vec![0; 1024])
        )
        .await
        .is_err());
        for _ in 0..2 {
            let _ = put_object(
                State(a.clone()),
                peer(),
                h.clone(),
                RoutePath((job.clone(), digest.clone())),
                body.clone(),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            db(&a)
                .unwrap()
                .query_row(
                    "SELECT budget-remaining FROM object_jobs WHERE id=?",
                    [&job],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1024
        );
        assert_eq!(fs::read(block_path(&a, 1, &digest)).unwrap(), body);
        let _ = cancel(State(a.clone()), peer(), h.clone(), RoutePath(job.clone()))
            .await
            .unwrap();
        assert_eq!(job_exists(&a, &job), 0);
    }
    #[test]
    fn reservations_preserve_disk_floor_and_include_other_jobs() {
        let (_dir, mut a, _h, _id, _old, _renewal) = fixture();
        let free = free_bytes(&a.cfg.data_dir).unwrap();
        Arc::get_mut(&mut a).unwrap().cfg.reserve_bytes = free;
        assert_eq!(
            reserve(&db(&a).unwrap(), &a, 1024).unwrap_err().0,
            StatusCode::INSUFFICIENT_STORAGE
        );
    }
}
