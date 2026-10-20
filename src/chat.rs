//! Chat stores ciphertext and routing/permission metadata. No content keys live here.
use super::*;
use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use p256::ecdsa::{signature::Signer, SigningKey};
struct Suite;
impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}
#[derive(Clone)]
struct User {
    id: String,
    owner: bool,
    session: String,
}
fn denied() -> Fault {
    Fault(StatusCode::FORBIDDEN, "You do not have permission")
}
fn conflict() -> Fault {
    Fault(
        StatusCode::CONFLICT,
        "This conversation changed. Reconnect and retry",
    )
}
fn decode(v: &Value, k: &str, max: usize) -> Api<Vec<u8>> {
    let s = text(v, k);
    if s.len() > max * 2 {
        return Err(bad("Request too large"));
    }
    let b = B64.decode(s).map_err(|_| bad("Invalid encoding"))?;
    if b.len() > max {
        return Err(bad("Request too large"));
    }
    Ok(b)
}
fn serial<T: AsRef<[u8]>>(v: T) -> String {
    B64.encode(v)
}
fn setting(c: &Connection, k: &str) -> Api<Value> {
    Ok(
        c.query_row("SELECT value FROM chat_settings WHERE key=?", [k], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or(Value::Null),
    )
}
fn set(c: &Connection, k: &str, v: &Value) -> Api<()> {
    c.execute(
        "INSERT INTO chat_settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![k, v.to_string()],
    )?;
    Ok(())
}
fn token(h: &HeaderMap) -> Api<String> {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 43)
        .map(hash)
        .ok_or(Fault(StatusCode::UNAUTHORIZED, "Sign in to Vortex"))
}
fn user(a: &App, h: &HeaderMap) -> Api<User> {
    let sh = token(h)?;
    let c = db(a)?;
    if let Some(id)=c.query_row("SELECT s.user FROM chat_sessions s JOIN chat_users u ON u.id=s.user WHERE s.hash=? AND s.expires>? AND u.disabled=0",params![sh,now()],|r|r.get::<_,String>(0)).optional()?{return Ok(User{id,owner:false,session:sh})}
    let id=c.query_row("SELECT u.id FROM sessions s JOIN chat_users u ON u.node_owner=s.owner WHERE s.hash=? AND s.expires>? AND u.disabled=0",params![sh,now()],|r|r.get::<_,String>(0)).optional()?.ok_or(Fault(StatusCode::UNAUTHORIZED,"Sign in to Vortex"))?;
    Ok(User {
        id,
        owner: true,
        session: sh,
    })
}
pub fn authenticated(a: &App, h: &HeaderMap) -> Api<bool> {
    Ok(user(a, h).is_ok())
}
fn permission(c: &Connection, u: &User, space: &str, bit: i64) -> Api<bool> {
    if u.owner {
        return Ok(true);
    }
    Ok(c.query_row("SELECT (m.permissions & ?) != 0 OR s.creator=? FROM chat_space_members m JOIN chat_spaces s ON s.id=m.space WHERE m.space=? AND m.user=? AND m.banned=0",params![bit,u.id,space,u.id],|r|r.get(0)).optional()?.unwrap_or(false))
}
fn member(c: &Connection, u: &User, room: &str) -> Api<()> {
    if c.query_row("SELECT 1 FROM chat_members m JOIN chat_rooms r ON r.id=m.room WHERE m.room=? AND m.user=? AND m.banned=0 AND NOT EXISTS(SELECT 1 FROM chat_space_members s WHERE s.space=r.space AND s.user=m.user AND s.banned=1)",params![room,u.id],|_|Ok(())).optional()?.is_none(){return Err(denied())}
    Ok(())
}
fn manager(c: &Connection, u: &User, room: &str) -> Api<()> {
    member(c, u, room)?;
    let (space, creator): (String, String) = c.query_row(
        "SELECT space,creator FROM chat_rooms WHERE id=?",
        [room],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if creator == u.id || !space.is_empty() && permission(c, u, &space, 1)? {
        Ok(())
    } else {
        Err(denied())
    }
}
fn room_permission(c: &Connection, u: &User, room: &str, bit: i64) -> Api<()> {
    member(c, u, room)?;
    let (space, creator): (String, String) = c.query_row(
        "SELECT space,creator FROM chat_rooms WHERE id=?",
        [room],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if creator == u.id || u.owner && bit == 8 || !space.is_empty() && permission(c, u, &space, bit)?
    {
        Ok(())
    } else {
        Err(denied())
    }
}
fn owner(u: &User) -> Api<()> {
    if u.owner {
        Ok(())
    } else {
        Err(denied())
    }
}
fn ciphertext(v: &Value, k: &str, max: usize) -> Api<String> {
    let b = decode(v, k, max)?;
    if b.len() < 28 {
        return Err(bad("Encrypted data required"));
    }
    Ok(B64.encode(b))
}
// The catalog contains signed ciphertext and encrypted per-account key boxes only.
fn node_emoji_audience(id: &str, creator: &str, envelope: &Value) -> Api<Vec<String>> {
    let raw = text(envelope, "data");
    if raw.len() > 1800 * 1024 {
        return Err(bad("Emoji catalog entry is too large"));
    }
    let data: Value = serde_json::from_str(&raw).map_err(|_| bad("Invalid encrypted emoji"))?;
    if text(&data, "id") != id || data["version"] != 1 {
        return Err(bad("Invalid emoji context"));
    }
    if decode(envelope, "signature", 256)?.len() != 64 {
        return Err(bad("Invalid emoji signature"));
    }
    ciphertext(&data, "cipher", 512 * 1024)?;
    let boxes = data["boxes"]
        .as_object()
        .ok_or(bad("Encrypted account keys are required"))?;
    if boxes.is_empty() || boxes.len() > 4096 || !boxes.contains_key(creator) {
        return Err(bad("Invalid emoji audience"));
    }
    for (user, value) in boxes {
        if !valid_id(user)
            || value
                .as_str()
                .map(|s| s.len() < 28 || s.len() > 4096)
                .unwrap_or(true)
        {
            return Err(bad("Invalid encrypted account key"));
        }
    }
    Ok(boxes.keys().cloned().collect())
}
fn devices(c: &Connection, id: &str) -> Api<Value> {
    let mut q=c.prepare("SELECT id,certificate,key_package FROM chat_devices WHERE user=? AND revoked=0 ORDER BY created")?;
    let rows=q.query_map([id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"certificate":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"keyPackage":r.get::<_,String>(2)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(json!(rows))
}
fn directory(c: &Connection) -> Api<Value> {
    let mut q=c.prepare("SELECT id,username,display,identity,profile,CASE WHEN status='invisible' OR COALESCE((SELECT at FROM chat_presence WHERE user=chat_users.id),0)<unixepoch()-90 THEN 'offline' WHEN status='online' AND COALESCE((SELECT idle FROM chat_presence WHERE user=chat_users.id),0)=1 THEN 'idle' ELSE status END,created,node_owner IS NOT NULL FROM chat_users WHERE disabled=0 ORDER BY username LIMIT 4096")?;
    let rows=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"username":r.get::<_,String>(1)?,"display":r.get::<_,String>(2)?,"identity":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"profile":!r.get::<_,String>(4)?.is_empty(),"status":r.get::<_,String>(5)?,"created":r.get::<_,i64>(6)?,"owner":r.get::<_,bool>(7)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(json!(rows))
}
fn notify(c: &Connection, target: &str, kind: &str, room: &str) -> Api<()> {
    c.execute(
        "INSERT INTO chat_notices(user,kind,room,at) VALUES(?,?,?,?)",
        params![target, kind, room, now()],
    )?;
    Ok(())
}
fn setup(c: &Connection) -> Api<ServerSetup<Suite>> {
    let raw = setting(c, "opaque")?
        .as_str()
        .ok_or(bad("Authentication unavailable"))?
        .to_string();
    ServerSetup::deserialize(
        &B64.decode(raw)
            .map_err(|_| bad("Authentication unavailable"))?,
    )
    .map_err(|_| bad("Authentication unavailable"))
}

pub fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS chat_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,node_owner INTEGER UNIQUE,registration TEXT NOT NULL,bundle TEXT NOT NULL,identity TEXT NOT NULL,display TEXT NOT NULL,profile TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'online',disabled INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,totp TEXT NOT NULL DEFAULT '',last_totp INTEGER NOT NULL DEFAULT -1,quota INTEGER NOT NULL DEFAULT 10737418240,can_invite INTEGER NOT NULL DEFAULT 0,can_space INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS chat_sessions(hash TEXT PRIMARY KEY,user TEXT NOT NULL,device TEXT NOT NULL,expires INTEGER NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_auth(id TEXT PRIMARY KEY,kind TEXT NOT NULL,username TEXT NOT NULL,state TEXT NOT NULL,expires INTEGER NOT NULL,ip TEXT NOT NULL,owner INTEGER,invite TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS chat_devices(id TEXT PRIMARY KEY,user TEXT NOT NULL,certificate TEXT NOT NULL,key_package TEXT NOT NULL,created INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS chat_key_packages(device TEXT NOT NULL,digest TEXT NOT NULL,package TEXT NOT NULL,room TEXT NOT NULL DEFAULT '',PRIMARY KEY(device,digest));
 CREATE TABLE IF NOT EXISTS chat_invites(hash TEXT PRIMARY KEY,creator TEXT NOT NULL,expires INTEGER NOT NULL,remaining INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_spaces(id TEXT PRIMARY KEY,creator TEXT NOT NULL,sealed TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_space_members(space TEXT NOT NULL,user TEXT NOT NULL,permissions INTEGER NOT NULL DEFAULT 0,role TEXT NOT NULL DEFAULT '',color TEXT NOT NULL DEFAULT '',banned INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(space,user));
 CREATE TABLE IF NOT EXISTS chat_rooms(id TEXT PRIMARY KEY,space TEXT NOT NULL,creator TEXT NOT NULL,kind TEXT NOT NULL,sealed TEXT NOT NULL,epoch INTEGER NOT NULL DEFAULT 0,audio INTEGER NOT NULL DEFAULT 128,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_members(room TEXT NOT NULL,user TEXT NOT NULL,box TEXT NOT NULL,banned INTEGER NOT NULL DEFAULT 0,timeout INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(room,user));
 CREATE TABLE IF NOT EXISTS chat_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,room TEXT NOT NULL,sender TEXT NOT NULL,device TEXT NOT NULL,id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,body TEXT NOT NULL,at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS chat_event_room ON chat_events(room,seq);
 CREATE TABLE IF NOT EXISTS chat_objects(id TEXT PRIMARY KEY,room TEXT NOT NULL,sender TEXT NOT NULL,bytes INTEGER NOT NULL,stored INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,complete INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS chat_parts(object TEXT NOT NULL,n INTEGER NOT NULL,digest TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(object,n));
 CREATE TABLE IF NOT EXISTS chat_push(user TEXT NOT NULL,endpoint TEXT PRIMARY KEY,p256dh TEXT NOT NULL,auth TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_notices(id INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT NOT NULL,kind TEXT NOT NULL,room TEXT NOT NULL,at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS chat_notice_user ON chat_notices(user,id);
 CREATE TABLE IF NOT EXISTS chat_login_policy(user TEXT PRIMARY KEY,months INTEGER NOT NULL CHECK(months BETWEEN 1 AND 12));
 CREATE TABLE IF NOT EXISTS chat_preferences(user TEXT PRIMARY KEY,body TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_node_emoji(id TEXT PRIMARY KEY,creator TEXT NOT NULL,body TEXT NOT NULL,audience TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_presence(user TEXT PRIMARY KEY,at INTEGER NOT NULL,idle INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS chat_object_sender ON chat_objects(sender);
 CREATE INDEX IF NOT EXISTS chat_object_room ON chat_objects(room);
 CREATE INDEX IF NOT EXISTS chat_event_sender ON chat_events(sender);
 CREATE INDEX IF NOT EXISTS chat_room_space ON chat_rooms(space);
 CREATE TABLE IF NOT EXISTS chat_friends(user TEXT NOT NULL,other TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(user,other));
 CREATE TABLE IF NOT EXISTS chat_totp(user TEXT PRIMARY KEY,seed TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_recovery(user TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(user,hash));")?;
    if !c.prepare("SELECT quota FROM chat_spaces LIMIT 0").is_ok() {
        c.execute(
            "ALTER TABLE chat_spaces ADD COLUMN quota INTEGER NOT NULL DEFAULT 107374182400",
            [],
        )?;
    }
    if !c.prepare("SELECT session FROM chat_push LIMIT 0").is_ok() {
        c.execute(
            "ALTER TABLE chat_push ADD COLUMN session TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !c
        .prepare("SELECT group_info FROM chat_rooms LIMIT 0")
        .is_ok()
    {
        c.execute(
            "ALTER TABLE chat_rooms ADD COLUMN group_info TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !c
        .prepare("SELECT needs_rekey FROM chat_rooms LIMIT 0")
        .is_ok()
    {
        c.execute(
            "ALTER TABLE chat_rooms ADD COLUMN needs_rekey INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if setting(c, "opaque")
        .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?
        .is_null()
    {
        set(
            c,
            "opaque",
            &json!(B64.encode(ServerSetup::<Suite>::new(&mut OsRng).serialize())),
        )
        .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?;
    }
    if setting(c, "policy")
        .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?
        .is_null()
    {
        set(
            c,
            "policy",
            &json!({"signupUntil":0,"createSpaces":"owner","title":"Vortex","ready":false}),
        )
        .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?;
    }
    if setting(c, "vapid")
        .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?
        .is_null()
    {
        let k = SigningKey::random(&mut OsRng);
        set(c, "vapid", &json!(B64.encode(k.to_bytes())))
            .map_err(|_| anyhow::anyhow!("Chat initialization failed"))?;
    }
    Ok(())
}

pub async fn action(
    State(a): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let addr = ip(&h, peer);
    let name = text(&v, "action");
    if name.starts_with("auth.") {
        rate(&a, format!("chat-auth:{addr}"), 30)?;
    }
    let slots = if name.starts_with("auth.") {
        &a.auth_slots
    } else {
        &a.io_slots
    };
    let permit = slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Fault(StatusCode::TOO_MANY_REQUESTS, "Please retry shortly"))?;
    let changed = ![
        "me",
        "rooms",
        "events",
        "directory",
        "devices",
        "room.members",
        "notices",
        "auth.config",
        "presence",
        "emoji.list",
        "emoji.get",
    ]
    .contains(&name.as_str());
    let room = text(&v, "room");
    let kick = if name == "room.moderate"
        && (v["banned"] == true || v["seconds"].as_i64().unwrap_or(0) > 0)
    {
        Some(text(&v, "user"))
    } else {
        None
    };
    let work = a.clone();
    let out = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        dispatch(&work, &h, peer, &addr, v)
    })
    .await
    .map_err(|_| Fault(StatusCode::INTERNAL_SERVER_ERROR, "Chat operation failed"))??;
    if let Some(target) = kick {
        kick_media(&a, &room, &target).await;
    }
    if changed {
        let _ = a.chat_events.send(room);
    }
    Ok(Json(out))
}
fn dispatch(a: &App, h: &HeaderMap, peer: SocketAddr, addr: &str, v: Value) -> Api<Value> {
    let op = text(&v, "action");
    if op == "auth.config" {
        let c = db(a)?;
        let policy = setting(&c, "policy")?;
        let name = normalize_name(&text(&v, "username"));
        let registered = c
            .query_row("SELECT 1 FROM chat_users WHERE username=?", [&name], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        let k = B64
            .decode(setting(&c, "vapid")?.as_str().unwrap_or(""))
            .map_err(|_| bad("Push unavailable"))?;
        let key = SigningKey::from_slice(&k).map_err(|_| bad("Push unavailable"))?;
        return Ok(
            json!({"policy":policy,"registered":registered,"vapid":B64.encode(key.verifying_key().to_encoded_point(false).as_bytes()),"node":a.cfg.node_id,"gate":format!("/gate/{}",a.cfg.bridge)}),
        );
    }
    if op == "auth.register.start" {
        let name = normalize_name(&text(&v, "username"));
        if !bounded(&name, 8, 128) {
            return Err(bad("Use an 8–128 character username"));
        }
        let ns = session(a, h, peer).ok();
        let c = db(a)?;
        let node_owner = if let Some(s) = ns {
            let first: i64 = c.query_row("SELECT MIN(id) FROM accounts", [], |r| r.get(0))?;
            if s.owner != first {
                return Err(denied());
            }
            let original: String =
                c.query_row("SELECT username FROM accounts WHERE id=?", [s.owner], |r| {
                    r.get(0)
                })?;
            if original != name {
                return Err(denied());
            }
            Some(s.owner)
        } else {
            None
        };
        if c.query_row("SELECT 1 FROM chat_users WHERE username=?", [&name], |_| {
            Ok(())
        })
        .optional()?
        .is_some()
        {
            return Err(Fault(StatusCode::CONFLICT, "Username already exists"));
        }
        let invite = hash(text(&v, "invite"));
        let policy = setting(&c, "policy")?;
        if node_owner.is_none()
            && policy["signupUntil"].as_i64().unwrap_or(0) <= now()
            && c.query_row(
                "SELECT 1 FROM chat_invites WHERE hash=? AND expires>? AND remaining>0",
                params![invite, now()],
                |_| Ok(()),
            )
            .optional()?
            .is_none()
        {
            return Err(denied());
        }
        let r = ServerRegistration::<Suite>::start(
            &setup(&c)?,
            RegistrationRequest::deserialize(&decode(&v, "request", 4096)?)
                .map_err(|_| bad("Invalid registration"))?,
            name.as_bytes(),
        )
        .map_err(|_| bad("Registration failed"))?;
        let id = random(24);
        c.execute(
            "INSERT INTO chat_auth VALUES(?,?,?,?,?,?,?,?)",
            params![
                id,
                "register",
                name,
                "",
                now() + 120,
                addr,
                node_owner,
                invite
            ],
        )?;
        return Ok(json!({"id":id,"response":serial(r.message.serialize())}));
    }
    if op == "auth.register.finish" {
        let mut c = db(a)?;
        let tx = c.transaction()?;
        let id = text(&v, "id");
        let(name,own,invite):(String,Option<i64>,String)=tx.query_row("SELECT username,owner,invite FROM chat_auth WHERE id=? AND kind='register' AND expires>? AND ip=?",params![id,now(),addr],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(denied())?;
        drop(tx);
        drop(c);
        if let Some(o) = own {
            if session(a, h, peer)?.owner != o {
                return Err(denied());
            }
        }
        c = db(a)?;
        // The final insert is protected by unique username and owner constraints.
        let registration = ServerRegistration::<Suite>::finish(
            RegistrationUpload::deserialize(&decode(&v, "record", 8192)?)
                .map_err(|_| bad("Invalid registration"))?,
        );
        let bundle = ciphertext(&v, "bundle", 1024 * 1024)?;
        let identity = v["identity"].clone();
        if identity.to_string().len() > 4096
            || identity["sign"].is_null()
            || identity["exchange"].is_null()
        {
            return Err(bad("Invalid identity"));
        }
        let uid = random(24);
        let tx = c.transaction()?;
        if own.is_none() && setting(&tx, "policy")?["signupUntil"].as_i64().unwrap_or(0) <= now() {
            if tx.execute("UPDATE chat_invites SET remaining=remaining-1 WHERE hash=? AND remaining>0 AND expires>?",params![invite,now()])?!=1{return Err(denied())}
        }
        tx.execute("INSERT INTO chat_users(id,username,node_owner,registration,bundle,identity,display,created) VALUES(?,?,?,?,?,?,?,?)",params![uid,name,own,serial(registration.serialize()),bundle,identity.to_string(),name,now()])?;
        if let Some(o) = own {
            tx.execute(
                "UPDATE chat_users SET totp=(SELECT totp FROM accounts WHERE id=?) WHERE id=?",
                params![o, uid],
            )?;
        }
        tx.execute("DELETE FROM chat_auth WHERE id=?", [id])?;
        tx.commit()?;
        return Ok(json!({"id":uid}));
    }
    if op == "auth.login.start" {
        let name = normalize_name(&text(&v, "username"));
        if !bounded(&name, 8, 128) {
            return Err(bad("Invalid credentials"));
        }
        rate(a, format!("chat-user:{}", hash(&name)), 20)?;
        let c = db(a)?;
        let record: Option<String> = c
            .query_row(
                "SELECT registration FROM chat_users WHERE username=? AND disabled=0",
                [&name],
                |r| r.get(0),
            )
            .optional()?;
        let rec = record
            .map(|s| B64.decode(s).map_err(|_| bad("Sign-in failed")))
            .transpose()?
            .map(|b| {
                ServerRegistration::<Suite>::deserialize(&b).map_err(|_| bad("Sign-in failed"))
            })
            .transpose()?;
        let r = ServerLogin::<Suite>::start(
            &mut OsRng,
            &setup(&c)?,
            rec,
            CredentialRequest::deserialize(&decode(&v, "request", 4096)?)
                .map_err(|_| bad("Sign-in failed"))?,
            name.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| bad("Sign-in failed"))?;
        let id = random(24);
        c.execute(
            "INSERT INTO chat_auth VALUES(?,?,?,?,?,?,NULL,'')",
            params![
                id,
                "login",
                name,
                serial(r.state.serialize()),
                now() + 120,
                addr
            ],
        )?;
        return Ok(json!({"id":id,"response":serial(r.message.serialize())}));
    }
    if op == "auth.login.finish" {
        let mut c = db(a)?;
        let tx = c.transaction()?;
        let(name,state):(String,String)=tx.query_row("SELECT username,state FROM chat_auth WHERE id=? AND kind='login' AND expires>? AND ip=?",params![text(&v,"id"),now(),addr],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or(denied())?;
        tx.execute("DELETE FROM chat_auth WHERE id=?", [text(&v, "id")])?;
        tx.commit()?;
        let state = ServerLogin::<Suite>::deserialize(&B64.decode(state).map_err(|_| denied())?)
            .map_err(|_| denied())?;
        state
            .finish(
                CredentialFinalization::deserialize(&decode(&v, "proof", 4096)?)
                    .map_err(|_| denied())?,
                ServerLoginParameters::default(),
            )
            .map_err(|_| Fault(StatusCode::UNAUTHORIZED, "Sign-in failed"))?;
        let(uid,own,bundle,identity,seed,last):(String,Option<i64>,String,String,String,i64)=c.query_row("SELECT id,node_owner,bundle,identity,totp,last_totp FROM chat_users WHERE username=? AND disabled=0",[&name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        if !seed.is_empty() {
            let code = text(&v, "otp");
            if let Some(step) = verify_totp(&seed, &code, last) {
                if c.execute(
                    "UPDATE chat_users SET last_totp=? WHERE id=? AND last_totp<?",
                    params![step, uid, step],
                )? != 1
                {
                    return Err(denied());
                }
            } else if c.execute(
                "DELETE FROM chat_recovery WHERE user=? AND hash=?",
                params![uid, hash(&code)],
            )? != 1
            {
                return Err(Fault(
                    StatusCode::UNAUTHORIZED,
                    "Check your authenticator code",
                ));
            }
        }
        let tok = random(32);
        let sh = hash(&tok);
        let configured = if let Some(o) = own {
            c.query_row(
                "SELECT months FROM account_policy WHERE owner=?",
                [o],
                |r| r.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(12)
        } else {
            c.query_row(
                "SELECT months FROM chat_login_policy WHERE user=?",
                [&uid],
                |r| r.get::<_, u64>(0),
            )
            .optional()?
            .unwrap_or(12)
        };
        let months = v["months"].as_u64().unwrap_or(configured).clamp(1, 12);
        let expires = Utc::now()
            .checked_add_months(Months::new(months as u32))
            .ok_or(bad("Clock unavailable"))?
            .timestamp();
        if let Some(o) = own {
            c.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?)",
                params![sh, o, expires, now(), text(&v, "device")],
            )?;
        } else {
            c.execute(
                "INSERT INTO chat_sessions VALUES(?,?,?,?,?)",
                params![sh, uid, text(&v, "device"), expires, now()],
            )?;
        }
        notify(&c, &uid, "login", "")?;
        return Ok(
            json!({"token":tok,"id":uid,"owner":own.is_some(),"username":name,"expires":expires,"months":months,"bundle":bundle,"identity":serde_json::from_str::<Value>(&identity).unwrap_or(Value::Null)}),
        );
    }
    let u = user(a, h)?;
    let mut c = db(a)?;
    match op.as_str() {
        "emoji.list" => {
            let mut q = c.prepare(
                "SELECT id,creator,body,audience FROM chat_node_emoji ORDER BY id LIMIT 128",
            )?;
            let items = q.query_map([], |r| {
                let body: String = r.get(2)?;
                let audience: String = r.get(3)?;
                let recipients = serde_json::from_str::<Vec<String>>(&audience).unwrap_or_default();
                Ok(json!({"id":r.get::<_,String>(0)?,"creator":r.get::<_,String>(1)?,"version":hash(&body),"ready":recipients.contains(&u.id),"recipients":if u.owner { json!(recipients) } else { Value::Null }}))
            })?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"items":items}))
        }
        "emoji.get" => {
            let (body, audience): (String, String) = c
                .query_row(
                    "SELECT body,audience FROM chat_node_emoji WHERE id=?",
                    [text(&v, "id")],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
                .ok_or(bad("Emoji is unavailable"))?;
            let recipients = serde_json::from_str::<Vec<String>>(&audience).unwrap_or_default();
            if !u.owner && !recipients.contains(&u.id) {
                return Err(conflict());
            }
            Ok(
                json!({"body":serde_json::from_str::<Value>(&body).unwrap_or(Value::Null),"version":hash(&body)}),
            )
        }
        "emoji.publish" => {
            owner(&u)?;
            let id = text(&v, "id");
            if !valid_id(&id) {
                return Err(bad("Invalid emoji"));
            }
            let body = v["body"].to_string();
            let audience = node_emoji_audience(&id, &u.id, &v["body"])?;
            let identity: String =
                c.query_row("SELECT identity FROM chat_users WHERE id=?", [&u.id], |r| {
                    r.get(0)
                })?;
            let identity: Value =
                serde_json::from_str(&identity).map_err(|_| bad("Invalid publisher identity"))?;
            let public = decode(&identity, "sign", 128)?;
            let public = VerifyingKey::from_sec1_bytes(&public)
                .map_err(|_| bad("Invalid publisher identity"))?;
            let signature = decode(&v["body"], "signature", 256)?;
            let signature =
                Signature::from_slice(&signature).map_err(|_| bad("Invalid emoji signature"))?;
            public
                .verify(text(&v["body"], "data").as_bytes(), &signature)
                .map_err(|_| bad("Emoji signature could not be verified"))?;
            let old: Option<String> = c
                .query_row("SELECT body FROM chat_node_emoji WHERE id=?", [&id], |r| {
                    r.get(0)
                })
                .optional()?;
            if old.as_ref().map(|b| hash(b)).unwrap_or_default() != text(&v, "version") {
                return Err(conflict());
            }
            if old.is_none()
                && c.query_row("SELECT COUNT(*) FROM chat_node_emoji", [], |r| {
                    r.get::<_, i64>(0)
                })? >= 128
            {
                return Err(bad("This Node has 128 custom emoji"));
            }
            let used: i64 = c.query_row(
                "SELECT COALESCE(SUM(length(body)),0) FROM chat_node_emoji WHERE id!=?",
                [&id],
                |r| r.get(0),
            )?;
            if used + body.len() as i64 > 64 * 1024 * 1024 {
                return Err(bad("The Node emoji catalog is full"));
            }
            c.execute("INSERT INTO chat_node_emoji VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET creator=excluded.creator,body=excluded.body,audience=excluded.audience", params![id,u.id,body,json!(audience).to_string()])?;
            Ok(json!({"ok":true,"version":hash(&body)}))
        }
        "emoji.delete" => {
            owner(&u)?;
            c.execute("DELETE FROM chat_node_emoji WHERE id=?", [text(&v, "id")])?;
            Ok(json!({"ok":true}))
        }
        "me" => {
            let (bundle, name, identity, totp): (String, String, String, String) = c.query_row(
                "SELECT bundle,username,identity,totp FROM chat_users WHERE id=?",
                [&u.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            Ok(
                json!({"id":u.id,"owner":u.owner,"canInvite":u.owner || c.query_row("SELECT can_invite FROM chat_users WHERE id=?",[&u.id],|r|r.get::<_,bool>(0))?,"canSpace":u.owner || c.query_row("SELECT can_space FROM chat_users WHERE id=?",[&u.id],|r|r.get::<_,bool>(0))?,"username":name,"bundle":bundle,"identity":serde_json::from_str::<Value>(&identity).unwrap_or(Value::Null),"totp":!totp.is_empty(),"policy":setting(&c,"policy")?,"users":directory(&c)?,"media":a.cfg.media.is_some(),"months":c.query_row("SELECT months FROM chat_login_policy WHERE user=?",[&u.id],|r|r.get::<_,i64>(0)).optional()?.unwrap_or(12),"preferences":c.query_row("SELECT body FROM chat_preferences WHERE user=?",[&u.id],|r|r.get::<_,String>(0)).optional()?.unwrap_or_default()}),
            )
        }
        "logout" => {
            c.execute("DELETE FROM chat_push WHERE session=?", [&u.session])?;
            c.execute("DELETE FROM chat_sessions WHERE hash=?", [&u.session])?;
            if u.owner {
                c.execute("DELETE FROM sessions WHERE hash=?", [&u.session])?;
                c.execute("DELETE FROM vault_leases WHERE session=?", [&u.session])?;
            }
            Ok(json!({"ok":true}))
        }
        "device" => {
            let id = text(&v, "id");
            if !valid_id(&id) {
                return Err(bad("Invalid device"));
            }
            let cert = v["certificate"].clone();
            let raw = cert.to_string();
            if raw.len() > 8192 {
                return Err(bad("Invalid device certificate"));
            }
            let identity: String =
                c.query_row("SELECT identity FROM chat_users WHERE id=?", [&u.id], |r| {
                    r.get(0)
                })?;
            let identity: Value =
                serde_json::from_str(&identity).map_err(|_| bad("Invalid identity"))?;
            let key = VerifyingKey::from_sec1_bytes(&decode(&identity, "sign", 256)?)
                .map_err(|_| bad("Invalid identity"))?;
            let data = text(&cert, "data");
            let payload: Value =
                serde_json::from_str(&data).map_err(|_| bad("Invalid device certificate"))?;
            if payload["device"] != id || payload["user"] != u.id {
                return Err(denied());
            }
            let sig = Signature::from_slice(&decode(&cert, "signature", 256)?)
                .map_err(|_| bad("Invalid signature"))?;
            key.verify(data.as_bytes(), &sig).map_err(|_| denied())?;
            let kp = serial(decode(&v, "keyPackage", 65536)?);
            if B64
                .decode(text(&payload, "mls"))
                .map_err(|_| bad("Invalid device key"))?
                .len()
                != 32
            {
                return Err(denied());
            }
            if c.query_row("SELECT user FROM chat_devices WHERE id=?", [&id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .is_some_and(|x| x != u.id)
            {
                return Err(denied());
            }
            c.execute("INSERT INTO chat_devices VALUES(?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET certificate=excluded.certificate,key_package=excluded.key_package WHERE user=excluded.user AND revoked=0",params![id,u.id,raw,kp,now()])?;
            if let Some(packages) = v["keyPackages"].as_array() {
                if packages.len() > 32 {
                    return Err(bad("Too many key packages"));
                }
                for package in packages {
                    let raw = package.as_str().ok_or(bad("Invalid key package"))?;
                    let decoded = B64.decode(raw).map_err(|_| bad("Invalid key package"))?;
                    if decoded.len() > 65536 {
                        return Err(bad("Invalid key package"));
                    }
                    c.execute("INSERT OR IGNORE INTO chat_key_packages(device,digest,package) SELECT ?,?,? WHERE (SELECT COUNT(*) FROM chat_key_packages WHERE device=?)<512",params![id,hash(&decoded),raw,id])?;
                }
            }
            Ok(json!({"ok":true}))
        }
        "devices" => Ok(json!({"devices":devices(&c,&text(&v,"user"))?})),
        "directory" => Ok(json!({"users":directory(&c)?})),
        "session.months" => {
            let months = v["months"].as_u64().unwrap_or(12);
            if !(1..=12).contains(&months) {
                return Err(bad("Choose 1–12 months"));
            }
            let table = if u.owner { "sessions" } else { "chat_sessions" };
            let created: i64 = c.query_row(
                &format!("SELECT created FROM {table} WHERE hash=?"),
                [&u.session],
                |r| r.get(0),
            )?;
            let expires = chrono::DateTime::from_timestamp(created, 0)
                .ok_or(bad("Clock unavailable"))?
                .checked_add_months(Months::new(months as u32))
                .ok_or(bad("Clock unavailable"))?
                .timestamp();
            c.execute(
                &format!("UPDATE {table} SET expires=? WHERE hash=?"),
                params![expires, u.session],
            )?;
            c.execute("INSERT INTO chat_login_policy VALUES(?,?) ON CONFLICT(user) DO UPDATE SET months=excluded.months",params![u.id,months])?;
            if u.owner {
                c.execute("INSERT INTO account_policy(owner,months) SELECT node_owner,? FROM chat_users WHERE id=? ON CONFLICT(owner) DO UPDATE SET months=excluded.months",params![months,u.id])?;
            }
            Ok(json!({"expires":expires,"months":months}))
        }
        "preferences" => {
            let body = ciphertext(&v, "body", 512 * 1024)?;
            c.execute("INSERT INTO chat_preferences VALUES(?,?) ON CONFLICT(user) DO UPDATE SET body=excluded.body",params![u.id,body])?;
            Ok(json!({"ok":true}))
        }
        "admin.users" => {
            owner(&u)?;
            let mut q = c.prepare(
                "SELECT id,can_invite,can_space,disabled,quota,username,display FROM chat_users",
            )?;
            let users=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"invite":r.get::<_,bool>(1)?,"spaces":r.get::<_,bool>(2)?,"disabled":r.get::<_,bool>(3)?,"quota":r.get::<_,i64>(4)?,"username":r.get::<_,String>(5)?,"display":r.get::<_,String>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"users":users}))
        }
        "profile.get" => {
            let target = text(&v, "user");
            let value: String = c.query_row(
                "SELECT profile FROM chat_users WHERE id=? AND disabled=0",
                [target],
                |r| r.get(0),
            )?;
            Ok(json!({"profile":value}))
        }
        "friend" => {
            let other = text(&v, "user");
            if other == u.id {
                return Err(bad("Choose another person"));
            }
            let kind = text(&v, "kind");
            if !["request", "accept", "remove", "block"].contains(&kind.as_str()) {
                return Err(bad("Invalid action"));
            }
            if kind == "accept"
                && c.query_row(
                    "SELECT 1 FROM chat_friends WHERE user=? AND other=? AND status='request'",
                    params![other, u.id],
                    |_| Ok(()),
                )
                .optional()?
                .is_none()
            {
                return Err(denied());
            }
            if c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends WHERE user=? AND other=? AND status='blocked')",params![other,u.id],|r|r.get::<_,bool>(0))? {return Err(denied())}
            let tx = c.transaction()?;
            if kind == "remove" {
                tx.execute(
                    "DELETE FROM chat_friends WHERE (user=? AND other=?) OR (user=? AND other=?)",
                    params![u.id, other, other, u.id],
                )?;
            } else {
                tx.execute("INSERT INTO chat_friends VALUES(?,?,?) ON CONFLICT(user,other) DO UPDATE SET status=excluded.status",params![u.id,other,if kind=="accept"{"friend"}else if kind=="block"{"blocked"}else{"request"}])?;
                if kind == "accept" {
                    tx.execute(
                        "UPDATE chat_friends SET status='friend' WHERE user=? AND other=?",
                        params![other, u.id],
                    )?;
                }
            }
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "friends" => {
            let mut q =
                c.prepare("SELECT user,other,status FROM chat_friends WHERE user=? OR other=?")?;
            let rows=q.query_map(params![u.id,u.id],|r|Ok(json!({"user":r.get::<_,String>(0)?,"other":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"friends":rows}))
        }
        "room.init" => {
            let room = text(&v, "room");
            manager(&c, &u, &room)?;
            let info = serial(decode(&v, "info", 262144)?);
            if c.execute(
                "UPDATE chat_rooms SET group_info=? WHERE id=? AND epoch=0 AND group_info=''",
                params![info, room],
            )? != 1
            {
                return Err(conflict());
            }
            Ok(json!({"ok":true}))
        }
        "room.member" => {
            let room = text(&v, "room");
            room_permission(&c, &u, &room, 2)?;
            let target = text(&v, "user");
            let box_value = ciphertext(&v, "box", 32768)?;
            c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,?) ON CONFLICT(room,user) DO UPDATE SET box=excluded.box,banned=0",params![room,target,box_value])?;
            let space: String =
                c.query_row("SELECT space FROM chat_rooms WHERE id=?", [&room], |r| {
                    r.get(0)
                })?;
            if !space.is_empty() {
                c.execute(
                    "INSERT OR IGNORE INTO chat_space_members(space,user) VALUES(?,?)",
                    params![space, target],
                )?;
            }
            Ok(json!({"ok":true}))
        }
        "room.metadata" => {
            let room = text(&v, "room");
            manager(&c, &u, &room)?;
            let sealed = ciphertext(&v, "sealed", 65536)?;
            c.execute(
                "UPDATE chat_rooms SET sealed=? WHERE id=?",
                params![sealed, room],
            )?;
            Ok(json!({"ok":true}))
        }
        "space.members" => {
            let space = text(&v, "space");
            if !permission(&c, &u, &space, 1)?
                && !permission(&c, &u, &space, 2)?
                && !permission(&c, &u, &space, 128)?
            {
                return Err(denied());
            }
            let mut q = c.prepare(
                "SELECT user,permissions,role,color,banned FROM chat_space_members WHERE space=?",
            )?;
            let rows=q.query_map([space],|r|Ok(json!({"user":r.get::<_,String>(0)?,"permissions":r.get::<_,i64>(1)?,"role":r.get::<_,String>(2)?,"color":r.get::<_,String>(3)?,"banned":r.get::<_,bool>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"members":rows}))
        }
        "room.rekey" => {
            let room = text(&v, "room");
            room_permission(&c, &u, &room, 2)?;
            let boxes = v["members"].as_array().ok_or(bad("Invalid participants"))?;
            let sealed = ciphertext(&v, "sealed", 65536)?;
            let tx = c.transaction()?;
            for m in boxes {
                tx.execute(
                    "UPDATE chat_members SET box=? WHERE room=? AND user=? AND banned=0",
                    params![ciphertext(m, "box", 32768)?, room, text(m, "user")],
                )?;
            }
            tx.execute(
                "UPDATE chat_rooms SET sealed=?,needs_rekey=0 WHERE id=?",
                params![sealed, room],
            )?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "space.delete" => {
            let space = text(&v, "space");
            let creator: String = c.query_row(
                "SELECT creator FROM chat_spaces WHERE id=?",
                [&space],
                |r| r.get(0),
            )?;
            if !u.owner && creator != u.id {
                return Err(denied());
            }
            let tx = c.transaction()?;
            tx.execute(
                "DELETE FROM chat_events WHERE room IN(SELECT id FROM chat_rooms WHERE space=?)",
                [&space],
            )?;
            tx.execute(
                "DELETE FROM chat_members WHERE room IN(SELECT id FROM chat_rooms WHERE space=?)",
                [&space],
            )?;
            tx.execute("DELETE FROM chat_rooms WHERE space=?", [&space])?;
            tx.execute("DELETE FROM chat_space_members WHERE space=?", [&space])?;
            tx.execute("DELETE FROM chat_spaces WHERE id=?", [&space])?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "profile" => {
            let display = normalize_name(&text(&v, "display"));
            let status = text(&v, "status");
            if !bounded(&display, 1, 80)
                || !["online", "idle", "dnd", "invisible"].contains(&status.as_str())
            {
                return Err(bad("Invalid profile"));
            }
            let profile = text(&v, "profile");
            if profile.len() > 512 * 1024 {
                return Err(bad("Profile too large"));
            }
            c.execute(
                "UPDATE chat_users SET display=?,status=?,profile=? WHERE id=?",
                params![display, status, profile, u.id],
            )?;
            Ok(json!({"ok":true}))
        }
        "gif.configure" => {
            owner(&u)?;
            let key = text(&v, "key");
            if key.len() > 256 {
                return Err(bad("Invalid provider key"));
            }
            set(&c, "gif-key", &json!(key))?;
            Ok(json!({"ok":true}))
        }
        "policy" => {
            owner(&u)?;
            let until = v["signupUntil"].as_i64().unwrap_or(0);
            let create = text(&v, "createSpaces");
            if !["owner", "selected", "everyone"].contains(&create.as_str())
                || until > now() + 366 * 86400
            {
                return Err(bad("Invalid registration policy"));
            }
            let title = text(&v, "title");
            if !bounded(&title, 1, 80) {
                return Err(bad("Invalid name"));
            }
            let tx = c.transaction()?;
            if let Some(people) = v.get("spaceCreators") {
                let people = people.as_array().ok_or(bad("Invalid Space creators"))?;
                if people.len() > 4096 {
                    return Err(bad("Too many Space creators"));
                }
                for person in people {
                    let id = person.as_str().ok_or(bad("Invalid Space creator"))?;
                    if tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND disabled=0 AND node_owner IS NULL)", [id], |r|r.get::<_,bool>(0))? == false { return Err(bad("Choose an active standard account")); }
                }
                tx.execute(
                    "UPDATE chat_users SET can_space=0 WHERE node_owner IS NULL AND disabled=0",
                    [],
                )?;
                for person in people {
                    tx.execute(
                        "UPDATE chat_users SET can_space=1 WHERE id=?",
                        [person.as_str().unwrap_or_default()],
                    )?;
                }
            }
            set(
                &tx,
                "policy",
                &json!({"signupUntil":until,"createSpaces":create,"title":title,"ready":true}),
            )?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "invite" => {
            if !u.owner
                && c.query_row(
                    "SELECT can_invite FROM chat_users WHERE id=?",
                    [&u.id],
                    |r| r.get::<_, i64>(0),
                )? != 1
            {
                return Err(denied());
            }
            let secret = random(32);
            let seconds = v["seconds"].as_i64().unwrap_or(86400).clamp(60, 604800);
            let uses = v["uses"].as_i64().unwrap_or(1).clamp(1, 100);
            c.execute(
                "INSERT INTO chat_invites VALUES(?,?,?,?)",
                params![hash(&secret), u.id, now() + seconds, uses],
            )?;
            Ok(json!({"secret":secret,"expires":now()+seconds}))
        }
        "admin.user" => {
            owner(&u)?;
            let id = text(&v, "user");
            let node_owner: Option<i64> =
                c.query_row("SELECT node_owner FROM chat_users WHERE id=?", [&id], |r| {
                    r.get(0)
                })?;
            if node_owner.is_some() {
                return Err(denied());
            }
            c.execute(
                "UPDATE chat_users SET can_invite=?,can_space=?,disabled=?,quota=? WHERE id=?",
                params![
                    v["invite"].as_bool().unwrap_or(false) as i32,
                    v["spaces"].as_bool().unwrap_or(false) as i32,
                    v["disabled"].as_bool().unwrap_or(false) as i32,
                    v["quota"]
                        .as_i64()
                        .unwrap_or(10 * 1024 * 1024 * 1024)
                        .clamp(0, 1024 * 1024 * 1024 * 1024i64),
                    id
                ],
            )?;
            if v["disabled"] == true {
                c.execute("DELETE FROM chat_sessions WHERE user=?", [&id])?;
            }
            Ok(json!({"ok":true}))
        }
        "space.quota" => {
            owner(&u)?;
            let quota = v["quota"]
                .as_i64()
                .unwrap_or(107374182400)
                .clamp(0, MAX_VAULT as i64);
            c.execute(
                "UPDATE chat_spaces SET quota=? WHERE id=?",
                params![quota, text(&v, "space")],
            )?;
            Ok(json!({"ok":true}))
        }
        "presence" => {
            c.execute("INSERT INTO chat_presence VALUES(?,?,?) ON CONFLICT(user) DO UPDATE SET at=excluded.at,idle=excluded.idle",params![u.id,now(),v["idle"].as_bool().unwrap_or(false) as i32])?;
            Ok(json!({"ok":true}))
        }
        "space.create" => {
            let policy = setting(&c, "policy")?;
            let selected = c.query_row(
                "SELECT can_space FROM chat_users WHERE id=?",
                [&u.id],
                |r| r.get::<_, bool>(0),
            )?;
            if !u.owner
                && !(policy["createSpaces"] == "everyone"
                    || policy["createSpaces"] == "selected" && selected)
            {
                return Err(denied());
            }
            let id = random(24);
            let sealed = ciphertext(&v, "sealed", 65536)?;
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO chat_spaces(id,creator,sealed,created) VALUES(?,?,?,?)",
                params![id, u.id, sealed, now()],
            )?;
            tx.execute(
                "INSERT INTO chat_space_members(space,user,permissions) VALUES(?,?,255)",
                params![id, u.id],
            )?;
            tx.execute("INSERT OR IGNORE INTO chat_space_members(space,user,permissions) SELECT ?,id,255 FROM chat_users WHERE node_owner IS NOT NULL",[&id])?;
            tx.commit()?;
            Ok(json!({"id":id}))
        }
        "space.member" => {
            let space = text(&v, "space");
            if !permission(&c, &u, &space, 128)? {
                return Err(denied());
            }
            let target = text(&v, "user");
            let perms = v["permissions"].as_i64().unwrap_or(0).clamp(0, 255);
            let creator: String = c.query_row(
                "SELECT creator FROM chat_spaces WHERE id=?",
                [&space],
                |r| r.get(0),
            )?;
            let is_owner: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND node_owner IS NOT NULL)",
                [&target],
                |r| r.get(0),
            )?;
            if target == creator || is_owner || target == u.id {
                return Err(denied());
            }
            let mine: i64 = if u.owner || creator == u.id {
                255
            } else {
                c.query_row(
                    "SELECT permissions FROM chat_space_members WHERE space=? AND user=?",
                    params![space, u.id],
                    |r| r.get(0),
                )?
            };
            if perms & !mine != 0 {
                return Err(denied());
            }
            let role = text(&v, "role");
            let color = text(&v, "color");
            if role.len() > 80 || color.len() > 16 {
                return Err(bad("Invalid role"));
            }
            c.execute("INSERT INTO chat_space_members VALUES(?,?,?,?,?,?) ON CONFLICT(space,user) DO UPDATE SET permissions=excluded.permissions,role=excluded.role,color=excluded.color,banned=excluded.banned",params![space,target,perms,role,color,v["banned"].as_bool().unwrap_or(false) as i32])?;
            Ok(json!({"ok":true}))
        }
        "room.create" => {
            let id = text(&v, "id");
            if !valid_id(&id) {
                return Err(bad("Invalid conversation"));
            }
            let space = text(&v, "space");
            let kind = text(&v, "kind");
            if !["dm", "group", "text", "voice"].contains(&kind.as_str()) {
                return Err(bad("Invalid conversation type"));
            }
            if !space.is_empty() && !permission(&c, &u, &space, 1)? {
                return Err(denied());
            }
            let users = v["members"].as_array().ok_or(bad("Choose participants"))?;
            if users.len() > 256 || !users.iter().any(|x| x["user"] == u.id) {
                return Err(bad("Invalid participants"));
            }
            if !space.is_empty() {
                let administrator: String = c.query_row(
                    "SELECT id FROM chat_users WHERE node_owner IS NOT NULL LIMIT 1",
                    [],
                    |r| r.get(0),
                )?;
                if !users.iter().any(|m| m["user"] == administrator) {
                    return Err(bad("Space channels must include their Node owner"));
                }
            }
            let sealed = ciphertext(&v, "sealed", 65536)?;
            let tx = c.transaction()?;
            tx.execute("INSERT INTO chat_rooms(id,space,creator,kind,sealed,epoch,audio,created) VALUES(?,?,?,?,?,0,128,?)",params![id,space,u.id,kind,sealed,now()])?;
            for m in users {
                let target = text(m, "user");
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND disabled=0)",
                    [&target],
                    |r| r.get(0),
                )?;
                if !exists {
                    return Err(bad("Unknown account"));
                }
                if space.is_empty() && tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends WHERE ((user=? AND other=?) OR (user=? AND other=?)) AND status='blocked')",params![u.id,target,target,u.id],|r|r.get::<_,bool>(0))? {return Err(denied())}
                if !space.is_empty() {
                    tx.execute(
                        "INSERT OR IGNORE INTO chat_space_members(space,user) VALUES(?,?)",
                        params![space, target],
                    )?;
                }
                tx.execute(
                    "INSERT INTO chat_members(room,user,box) VALUES(?,?,?)",
                    params![id, target, ciphertext(m, "box", 8192)?],
                )?;
            }
            tx.commit()?;
            Ok(json!({"id":id}))
        }
        "rooms" => {
            let mut q=c.prepare("SELECT r.id,r.space,r.creator,r.kind,r.sealed,r.epoch,r.audio,m.box,r.group_info FROM chat_rooms r JOIN chat_members m ON m.room=r.id WHERE m.user=? AND m.banned=0 AND NOT EXISTS(SELECT 1 FROM chat_space_members s WHERE s.space=r.space AND s.user=m.user AND s.banned=1) ORDER BY r.created")?;
            let mut rows=q.query_map([&u.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"space":r.get::<_,String>(1)?,"creator":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"sealed":r.get::<_,String>(4)?,"epoch":r.get::<_,i64>(5)?,"audio":r.get::<_,i64>(6)?,"box":r.get::<_,String>(7)?,"info":r.get::<_,String>(8)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            for room in &mut rows {
                let space = text(room, "space");
                let mut roles=c.prepare("SELECT user,role,color,permissions FROM chat_space_members WHERE space=? AND banned=0")?;
                let values=roles.query_map([&space],|r|Ok(json!({"user":r.get::<_,String>(0)?,"role":r.get::<_,String>(1)?,"color":r.get::<_,String>(2)?,"permissions":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
                room["moderators"] = json!(values
                    .iter()
                    .filter(|x| x["permissions"].as_i64().unwrap_or(0) & 4 != 0)
                    .map(|x| x["user"].clone())
                    .collect::<Vec<_>>());
                room["roles"] = json!(values);
            }
            let mut spaces=c.prepare("SELECT s.id,s.creator,s.sealed,m.permissions,m.role,m.color,s.quota FROM chat_spaces s JOIN chat_space_members m ON m.space=s.id WHERE m.user=? AND m.banned=0")?;
            let spaces=spaces.query_map([&u.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"creator":r.get::<_,String>(1)?,"sealed":r.get::<_,String>(2)?,"permissions":r.get::<_,i64>(3)?,"role":r.get::<_,String>(4)?,"color":r.get::<_,String>(5)?,"quota":r.get::<_,i64>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"rooms":rows,"spaces":spaces}))
        }
        "room.members" => {
            let room = text(&v, "room");
            member(&c, &u, &room)?;
            let mut q = c.prepare("SELECT user FROM chat_members WHERE room=? AND banned=0")?;
            let ids = q
                .query_map([&room], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut all = Vec::new();
            for id in ids {
                let mut list = devices(&c, &id)?;
                if let Some(devices) = list.as_array_mut() {
                    for device in devices {
                        let did = text(device, "id");
                        let package:Option<(String,String)>=c.query_row("SELECT digest,package FROM chat_key_packages WHERE device=? AND (room=? OR room='') ORDER BY (room=?) DESC LIMIT 1",params![did,room,room],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                        if let Some((digest, package)) = package {
                            c.execute("UPDATE chat_key_packages SET room=? WHERE device=? AND digest=? AND (room='' OR room=?)",params![room,did,digest,room])?;
                            device["keyPackage"] = json!(package);
                        }
                    }
                }
                all.push(json!({"user":id,"devices":list}));
            }
            Ok(json!({"members":all}))
        }
        "room.audio" => {
            let room = text(&v, "room");
            manager(&c, &u, &room)?;
            let audio = v["audio"].as_i64().unwrap_or(128);
            if ![32, 64, 128].contains(&audio) {
                return Err(bad("Invalid audio quality"));
            }
            c.execute(
                "UPDATE chat_rooms SET audio=? WHERE id=?",
                params![audio, room],
            )?;
            Ok(json!({"ok":true}))
        }
        "room.delete" => {
            let room = text(&v, "room");
            manager(&c, &u, &room)?;
            let tx = c.transaction()?;
            tx.execute("DELETE FROM chat_events WHERE room=?", [&room])?;
            tx.execute("DELETE FROM chat_members WHERE room=?", [&room])?;
            tx.execute("DELETE FROM chat_rooms WHERE id=?", [&room])?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "room.moderate" => {
            let room = text(&v, "room");
            room_permission(&c, &u, &room, 2)?;
            let target = text(&v, "user");
            let creator: String =
                c.query_row("SELECT creator FROM chat_rooms WHERE id=?", [&room], |r| {
                    r.get(0)
                })?;
            let is_owner: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND node_owner IS NOT NULL)",
                [&target],
                |r| r.get(0),
            )?;
            if target == creator || is_owner || target == u.id {
                return Err(denied());
            }
            c.execute(
                "UPDATE chat_members SET banned=?,timeout=? WHERE room=? AND user=?",
                params![
                    v["banned"].as_bool().unwrap_or(false) as i32,
                    now() + v["seconds"].as_i64().unwrap_or(0).clamp(0, 2419200),
                    room,
                    target
                ],
            )?;
            if v["banned"] == true {
                c.execute("UPDATE chat_rooms SET needs_rekey=1 WHERE id=?", [&room])?;
            }
            Ok(json!({"ok":true}))
        }
        "event" => {
            let room = text(&v, "room");
            member(&c, &u, &room)?;
            if c.query_row(
                "SELECT timeout FROM chat_members WHERE room=? AND user=?",
                params![room, u.id],
                |r| r.get::<_, i64>(0),
            )? > now()
            {
                return Err(denied());
            }
            let (space, kind_room): (String, String) = c.query_row(
                "SELECT space,kind FROM chat_rooms WHERE id=?",
                [&room],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if space.is_empty() && kind_room=="dm" && c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends f JOIN chat_members m ON (m.user=f.user OR m.user=f.other) WHERE m.room=? AND f.status='blocked' AND (f.user=? OR f.other=?))",params![room,u.id,u.id],|r|r.get::<_,bool>(0))? {return Err(denied())}
            let device = text(&v, "device");
            if c.query_row(
                "SELECT 1 FROM chat_devices WHERE id=? AND user=? AND revoked=0",
                params![device, u.id],
                |_| Ok(()),
            )
            .optional()?
            .is_none()
            {
                return Err(denied());
            }
            let kind = text(&v, "kind");
            if ![
                "message", "mls", "welcome", "call", "typing", "receipt", "emoji",
            ]
            .contains(&kind.as_str())
            {
                return Err(bad("Invalid event"));
            }
            if kind == "emoji" {
                room_permission(&c, &u, &room, 8)?;
            }
            let body = v["body"].to_string();
            if body.len() > 262144 {
                return Err(bad("Message too large"));
            }
            let id = text(&v, "id");
            if !valid_id(&id) {
                return Err(bad("Invalid message"));
            }
            let tx = c.transaction()?;
            if kind != "mls"
                && tx.query_row(
                    "SELECT needs_rekey FROM chat_rooms WHERE id=?",
                    [&room],
                    |r| r.get::<_, i64>(0),
                )? != 0
            {
                return Err(conflict());
            }
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM chat_events WHERE id=? AND room=? AND sender=?",
                    params![id, room, u.id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(seq) = existing {
                return Ok(json!({"seq":seq}));
            }
            if kind == "mls" {
                if tx.execute(
                    "UPDATE chat_rooms SET epoch=epoch+1,group_info=? WHERE id=? AND epoch=?",
                    params![
                        text(&v["body"], "info"),
                        room,
                        v["epoch"].as_i64().unwrap_or(-1)
                    ],
                )? != 1
                {
                    return Err(conflict());
                }
            }
            {
                let (quota,used):(i64,i64)=tx.query_row("SELECT quota,(SELECT COALESCE(SUM(bytes),0) FROM chat_objects WHERE sender=?)+(SELECT COALESCE(SUM(length(body)),0) FROM chat_events WHERE sender=?) FROM chat_users WHERE id=?",params![u.id,u.id,u.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
                if used.saturating_add(body.len() as i64)
                    > quota.saturating_add(if kind == "mls" { 16 * 1024 * 1024 } else { 0 })
                {
                    return Err(Fault(
                        StatusCode::INSUFFICIENT_STORAGE,
                        "Your storage allowance is full",
                    ));
                }
                let space: String =
                    tx.query_row("SELECT space FROM chat_rooms WHERE id=?", [&room], |r| {
                        r.get(0)
                    })?;
                if !space.is_empty() {
                    let (quota,used):(i64,i64)=tx.query_row("SELECT quota,(SELECT COALESCE(SUM(bytes),0) FROM chat_objects WHERE room IN(SELECT id FROM chat_rooms WHERE space=?))+(SELECT COALESCE(SUM(length(body)),0) FROM chat_events WHERE room IN(SELECT id FROM chat_rooms WHERE space=?)) FROM chat_spaces WHERE id=?",params![space,space,space],|r|Ok((r.get(0)?,r.get(1)?)))?;
                    if used.saturating_add(body.len() as i64)
                        > quota.saturating_add(if kind == "mls" { 64 * 1024 * 1024 } else { 0 })
                    {
                        return Err(Fault(
                            StatusCode::INSUFFICIENT_STORAGE,
                            "This Space storage allowance is full",
                        ));
                    }
                }
            }
            reserve(&tx, a, body.len() as u64)?;
            if free_bytes(&a.cfg.data_dir)? < safety_floor(a) + CONTROL_HEADROOM {
                return Err(Fault(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Storage reserve reached",
                ));
            }
            tx.execute(
                "INSERT INTO chat_events(room,sender,device,id,kind,body,at) VALUES(?,?,?,?,?,?,?)",
                params![room, u.id, device, id, kind, body, now()],
            )?;
            let seq = tx.last_insert_rowid();
            if ["message", "call"].contains(&kind.as_str()) {
                let mut q = tx.prepare(
                    "SELECT user FROM chat_members WHERE room=? AND user<>? AND banned=0",
                )?;
                let recipients = q
                    .query_map(params![room, u.id], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                drop(q);
                for target in recipients {
                    notify(
                        &tx,
                        &target,
                        if kind == "call" { "call" } else { "message" },
                        &room,
                    )?;
                }
            }
            tx.commit()?;
            Ok(json!({"seq":seq}))
        }
        "events" => {
            let room = text(&v, "room");
            member(&c, &u, &room)?;
            let mut after = v["after"].as_i64().unwrap_or(0);
            let recent = v["recent"].as_bool().unwrap_or(false);
            if recent {
                after=c.query_row("SELECT COALESCE(MIN(seq)-1,0) FROM (SELECT seq FROM chat_events WHERE room=? AND kind IN ('message','call','emoji') ORDER BY seq DESC LIMIT 100)",[&room],|r|r.get(0))?;
            }
            let (epoch, info): (i64, String) = c.query_row(
                "SELECT epoch,group_info FROM chat_rooms WHERE id=?",
                [&room],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let before = v["before"].as_i64().unwrap_or(0);
            let filter = if recent || before > 0 || v["archive"].as_bool().unwrap_or(false) {
                " AND kind IN ('message','call','emoji')"
            } else {
                ""
            };
            let sql = if before > 0 {
                format!("SELECT seq,sender,device,id,kind,body,at FROM (SELECT seq,sender,device,id,kind,body,at FROM chat_events WHERE room=? AND seq<?{filter} ORDER BY seq DESC LIMIT 100) ORDER BY seq")
            } else {
                format!("SELECT seq,sender,device,id,kind,body,at FROM chat_events WHERE room=? AND seq>?{filter} ORDER BY seq LIMIT 100")
            };
            let cursor: i64 = c.query_row(
                "SELECT COALESCE(MAX(seq),0) FROM chat_events WHERE room=?",
                [&room],
                |r| r.get(0),
            )?;
            let mut q = c.prepare(&sql)?;
            let rows=q.query_map(params![room,if before>0{before}else{after}],|r|Ok(json!({"seq":r.get::<_,i64>(0)?,"sender":r.get::<_,String>(1)?,"device":r.get::<_,String>(2)?,"id":r.get::<_,String>(3)?,"kind":r.get::<_,String>(4)?,"body":serde_json::from_str::<Value>(&r.get::<_,String>(5)?).unwrap_or(Value::Null),"at":r.get::<_,i64>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"events":rows,"epoch":epoch,"info":info,"cursor":cursor}))
        }
        "notices" => {
            let after = v["after"].as_i64().unwrap_or(0);
            let mut q=c.prepare("SELECT id,kind,room,at FROM chat_notices WHERE user=? AND id>? ORDER BY id LIMIT 100")?;
            let rows=q.query_map(params![u.id,after],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"room":r.get::<_,String>(2)?,"at":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"notices":rows}))
        }
        "totp.disable" => {
            let (seed, last): (String, i64) = c.query_row(
                "SELECT totp,last_totp FROM chat_users WHERE id=?",
                [&u.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            verify_totp(&seed, &text(&v, "otp"), last)
                .ok_or(bad("Check your authenticator code"))?;
            c.execute(
                "UPDATE chat_users SET totp='',last_totp=-1 WHERE id=?",
                [&u.id],
            )?;
            c.execute("DELETE FROM chat_recovery WHERE user=?", [&u.id])?;
            Ok(json!({"ok":true}))
        }
        "totp.start" => {
            let seed = base32(&{
                let mut b = [0; 20];
                OsRng.fill_bytes(&mut b);
                b
            });
            c.execute("INSERT INTO chat_totp VALUES(?,?,?) ON CONFLICT(user) DO UPDATE SET seed=excluded.seed,expires=excluded.expires",params![u.id,seed,now()+600])?;
            Ok(json!({"seed":seed}))
        }
        "totp.finish" => {
            let seed: String = c.query_row(
                "SELECT seed FROM chat_totp WHERE user=? AND expires>?",
                params![u.id, now()],
                |r| r.get(0),
            )?;
            let step = verify_totp(&seed, &text(&v, "otp"), -1)
                .ok_or(bad("Check your authenticator code"))?;
            let tx = c.transaction()?;
            tx.execute(
                "UPDATE chat_users SET totp=?,last_totp=? WHERE id=?",
                params![seed, step, u.id],
            )?;
            tx.execute("DELETE FROM chat_totp WHERE user=?", [&u.id])?;
            tx.execute("DELETE FROM chat_recovery WHERE user=?", [&u.id])?;
            let codes = (0..10).map(|_| random(12)).collect::<Vec<_>>();
            for code in &codes {
                tx.execute(
                    "INSERT INTO chat_recovery VALUES(?,?)",
                    params![u.id, hash(code)],
                )?;
            }
            tx.commit()?;
            Ok(json!({"recovery":codes}))
        }
        "push" => {
            let endpoint = text(&v, "endpoint");
            let parsed = reqwest::Url::parse(&endpoint).map_err(|_| bad("Invalid push service"))?;
            let host = parsed.host_str().unwrap_or("");
            if parsed.scheme() != "https"
                || !(host == "fcm.googleapis.com"
                    || host.ends_with(".push.services.mozilla.com")
                    || host == "updates.push.services.mozilla.com"
                    || host == "web.push.apple.com")
            {
                return Err(bad("Unsupported push service"));
            }
            if endpoint.len() > 4096 {
                return Err(bad("Invalid push subscription"));
            }
            c.execute("INSERT INTO chat_push(user,endpoint,p256dh,auth,created,session) VALUES(?,?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user=excluded.user,p256dh=excluded.p256dh,auth=excluded.auth,session=excluded.session",params![u.id,endpoint,text(&v,"p256dh"),text(&v,"auth"),now(),u.session])?;
            Ok(json!({"ok":true}))
        }
        _ => Err(bad("Unknown action")),
    }
}

pub async fn html() -> Response {
    let nonce = random(18);
    let html = include_str!("../Vortex Chat.html")
        .replace("<script>", &format!("<script nonce=\"{nonce}\">"));
    let policy=format!("default-src 'none'; script-src 'nonce-{nonce}' 'wasm-unsafe-eval' blob:; style-src 'unsafe-inline'; img-src 'self' blob: data:; media-src blob: mediastream:; connect-src https: wss: http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; worker-src 'self' blob:; manifest-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'");
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, policy.as_str()),
        ],
        html,
    )
        .into_response()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Media {
    pub url: String,
    pub http: String,
    pub key: String,
    pub secret: String,
}
fn jwt(key: &str, secret: &str, claims: Value) -> String {
    let head = B64.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let body = B64.encode(claims.to_string());
    let value = format!("{head}.{body}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    let _ = key;
    format!("{value}.{}", B64.encode(mac.finalize().into_bytes()))
}
pub async fn media_token(
    State(a): State<App>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&a, &h)?;
    let room = text(&v, "room");
    let device = text(&v, "device");
    {
        let c = db(&a)?;
        member(&c, &u, &room)?;
        if c.query_row(
            "SELECT timeout FROM chat_members WHERE room=? AND user=?",
            params![room, u.id],
            |r| r.get::<_, i64>(0),
        )? > now()
        {
            return Err(denied());
        }
        if c.query_row(
            "SELECT 1 FROM chat_devices WHERE id=? AND user=? AND revoked=0",
            params![device, u.id],
            |_| Ok(()),
        )
        .optional()?
        .is_none()
        {
            return Err(denied());
        }
    }
    let cfg = a.cfg.media.as_ref().ok_or(Fault(
        StatusCode::SERVICE_UNAVAILABLE,
        "Calling is unavailable",
    ))?;
    let claims = json!({"iss":cfg.key,"sub":format!("{}:{}",u.id,device),"nbf":now()-5,"exp":now()+120,"video":{"roomJoin":true,"room":room,"canPublish":true,"canSubscribe":true,"canPublishData":false}});
    Ok(Json(
        json!({"url":cfg.url,"token":jwt(&cfg.key,&cfg.secret,claims)}),
    ))
}
pub async fn begin_object(
    State(a): State<App>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&a, &h)?;
    let room = text(&v, "room");
    let bytes = v["bytes"].as_i64().ok_or(bad("Invalid upload size"))?;
    if !(28..=MAX_VAULT as i64).contains(&bytes) {
        return Err(bad("Invalid upload size"));
    }
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    member(&tx, &u, &room)?;
    let (quota,used):(i64,i64)=tx.query_row("SELECT quota,(SELECT COALESCE(SUM(bytes),0) FROM chat_objects WHERE sender=chat_users.id)+(SELECT COALESCE(SUM(length(body)),0) FROM chat_events WHERE sender=chat_users.id) FROM chat_users WHERE id=?",[&u.id],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if used.saturating_add(bytes) > quota {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "Your storage allowance is full",
        ));
    }
    let space: String = tx.query_row("SELECT space FROM chat_rooms WHERE id=?", [&room], |r| {
        r.get(0)
    })?;
    if !space.is_empty() {
        let (quota,used):(i64,i64)=tx.query_row("SELECT quota,(SELECT COALESCE(SUM(o.bytes),0) FROM chat_objects o JOIN chat_rooms r ON r.id=o.room WHERE r.space=chat_spaces.id)+(SELECT COALESCE(SUM(length(e.body)),0) FROM chat_events e JOIN chat_rooms r ON r.id=e.room WHERE r.space=chat_spaces.id) FROM chat_spaces WHERE id=?",[&space],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if used.saturating_add(bytes) > quota {
            return Err(Fault(
                StatusCode::INSUFFICIENT_STORAGE,
                "This Space has reached its storage allowance",
            ));
        }
    }
    reserve(&tx, &a, bytes as u64)?;
    let id = random(24);
    tx.execute(
        "INSERT INTO chat_objects VALUES(?,?,?,?,0,?,0)",
        params![id, room, u.id, bytes, now()],
    )?;
    fs::create_dir_all(a.cfg.data_dir.join("chat").join(&id))?;
    tx.commit()?;
    Ok(Json(json!({"id":id,"chunk":BLOCK})))
}
pub async fn object_part(
    State(a): State<App>,
    h: HeaderMap,
    RoutePath((id, n)): RoutePath<(String, u64)>,
    bytes: Bytes,
) -> Api<Json<Value>> {
    let u = user(&a, &h)?;
    if !valid_id(&id) || bytes.len() > MAX_BLOCK || bytes.len() < 28 || n > MAX_VAULT / BLOCK as u64
    {
        return Err(bad("Invalid encrypted chunk"));
    }
    let _slot = a
        .io_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Fault(StatusCode::TOO_MANY_REQUESTS, "Retry shortly"))?;
    let digest = hash(&bytes);
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    let (room,limit,stored):(String,i64,i64)=tx.query_row("SELECT room,bytes,stored FROM chat_objects WHERE id=? AND sender=? AND complete=0 AND created>?",params![id,u.id,now()-86400],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(denied())?;
    member(&tx, &u, &room)?;
    if let Some(old) = tx
        .query_row(
            "SELECT digest FROM chat_parts WHERE object=? AND n=?",
            params![id, n as i64],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        if old != digest {
            return Err(conflict());
        }
        return Ok(Json(json!({"ok":true})));
    }
    if stored + bytes.len() as i64 > limit {
        return Err(bad("Upload exceeds reservation"));
    }
    if free_bytes(&a.cfg.data_dir)? < safety_floor(&a) + bytes.len() as u64 {
        return Err(Fault(
            StatusCode::INSUFFICIENT_STORAGE,
            "Storage reserve reached",
        ));
    }
    let folder = a.cfg.data_dir.join("chat").join(&id);
    let path = folder.join(n.to_string());
    let temp = folder.join(format!("{}.new", random(12)));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, &path)?;
    sync_directory(&folder)?;
    tx.execute(
        "INSERT INTO chat_parts VALUES(?,?,?,?)",
        params![id, n as i64, digest, bytes.len() as i64],
    )?;
    tx.execute(
        "UPDATE chat_objects SET stored=stored+? WHERE id=?",
        params![bytes.len() as i64, id],
    )?;
    tx.commit()?;
    Ok(Json(json!({"ok":true})))
}
pub async fn finish_object(
    State(a): State<App>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
) -> Api<Json<Value>> {
    let u = user(&a, &h)?;
    let c = db(&a)?;
    let room: String = c
        .query_row(
            "SELECT room FROM chat_objects WHERE id=? AND sender=? AND bytes=stored",
            params![id, u.id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(bad("Upload is incomplete"))?;
    member(&c, &u, &room)?;
    let (count, max): (i64, i64) = c.query_row(
        "SELECT COUNT(*),COALESCE(MAX(n),-1) FROM chat_parts WHERE object=?",
        [&id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count == 0 || max != count - 1 {
        return Err(bad("Upload is incomplete"));
    }
    c.execute("UPDATE chat_objects SET complete=1 WHERE id=?", [id])?;
    Ok(Json(json!({"ok":true})))
}
pub async fn get_object(
    State(a): State<App>,
    h: HeaderMap,
    RoutePath((id, n)): RoutePath<(String, u64)>,
) -> Api<Response> {
    let u = user(&a, &h)?;
    if !valid_id(&id) {
        return Err(bad("Invalid object"));
    }
    let digest;
    {
        let c = db(&a)?;
        let room: String = c
            .query_row(
                "SELECT room FROM chat_objects WHERE id=? AND complete=1",
                [&id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(denied())?;
        member(&c, &u, &room)?;
        digest = c.query_row(
            "SELECT digest FROM chat_parts WHERE object=? AND n=?",
            params![id, n as i64],
            |r| r.get::<_, String>(0),
        )?;
    }
    let bytes = tokio::fs::read(a.cfg.data_dir.join("chat").join(&id).join(n.to_string())).await?;
    if hash(&bytes) != digest {
        return Err(Fault(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Encrypted chunk failed integrity check",
        ));
    }
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}
pub fn cleanup(c: &Connection, a: &App) -> Api<()> {
    c.execute("DELETE FROM chat_auth WHERE expires<?", [now()])?;
    c.execute(
        "DELETE FROM chat_invites WHERE expires<? OR remaining<=0",
        [now()],
    )?;
    c.execute("DELETE FROM chat_sessions WHERE expires<?", [now()])?;
    c.execute("DELETE FROM chat_notices WHERE at<?", [now() - 86400])?;
    c.execute(
        "DELETE FROM chat_events WHERE kind IN ('typing','receipt') AND at<?",
        [now() - 86400],
    )?;
    let mut q=c.prepare("SELECT id FROM chat_objects WHERE (complete=0 AND created<?) OR room NOT IN(SELECT id FROM chat_rooms)")?;
    let ids = q
        .query_map([now() - 86400], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(q);
    for id in ids {
        if valid_id(&id) {
            let _ = fs::remove_dir_all(a.cfg.data_dir.join("chat").join(&id));
        }
        c.execute("DELETE FROM chat_parts WHERE object=?", [&id])?;
        c.execute("DELETE FROM chat_objects WHERE id=?", [&id])?;
    }
    Ok(())
}
pub async fn push_loop(a: App) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut cursor = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let pending = (|| -> Api<_> {
            let c = db(&a)?;
            let key = B64
                .decode(setting(&c, "vapid")?.as_str().unwrap_or(""))
                .map_err(|_| bad("Push unavailable"))?;
            let mut q=c.prepare("SELECT MAX(n.id),p.endpoint FROM chat_notices n JOIN chat_push p ON p.user=n.user WHERE n.id>? AND n.at>? AND (EXISTS(SELECT 1 FROM sessions s WHERE s.hash=p.session AND s.expires>unixepoch()) OR EXISTS(SELECT 1 FROM chat_sessions s WHERE s.hash=p.session AND s.expires>unixepoch())) GROUP BY p.endpoint ORDER BY MAX(n.id) ASC LIMIT 128")?;
            let rows = q
                .query_map(params![cursor, now() - 60], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok((key, rows))
        })();
        let Ok((key, rows)) = pending else { continue };
        let Ok(signing) = SigningKey::from_slice(&key) else {
            continue;
        };
        for (seq, endpoint) in rows {
            cursor = cursor.max(seq);
            let Ok(url) = reqwest::Url::parse(&endpoint) else {
                continue;
            };
            let head = B64.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
            let claim=B64.encode(json!({"aud":url.origin().ascii_serialization(),"exp":now()+3600,"sub":format!("mailto:{}",a.cfg.email)}).to_string());
            let msg = format!("{head}.{claim}");
            let sig: Signature = signing.sign(msg.as_bytes());
            let auth = format!(
                "vapid t={msg}.{}, k={}",
                B64.encode(sig.to_bytes()),
                B64.encode(signing.verifying_key().to_encoded_point(false).as_bytes())
            );
            let result = client
                .post(&endpoint)
                .header("Authorization", auth)
                .header("TTL", "60")
                .header("Urgency", "high")
                .header("Content-Length", "0")
                .send()
                .await;
            if result
                .as_ref()
                .is_ok_and(|r| matches!(r.status().as_u16(), 404 | 410))
            {
                if let Ok(c) = db(&a) {
                    let _ = c.execute("DELETE FROM chat_push WHERE endpoint=?", [&endpoint]);
                }
            }
        }
    }
}
pub async fn sw() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (
                header::HeaderName::from_static("service-worker-allowed"),
                "/chat/",
            ),
        ],
        include_str!("../web/chat-worker.js"),
    )
        .into_response()
}
pub async fn manifest() -> Response {
    ([(header::CONTENT_TYPE,"application/manifest+json")],r##"{"name":"Vortex Chat","short_name":"Vortex","start_url":"/chat/","scope":"/chat/","display":"standalone","background_color":"#080c14","theme_color":"#080c14","icons":[{"src":"/chat/icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any"}]}"##).into_response()
}
pub async fn icon() -> Response {
    ([(header::CONTENT_TYPE,"image/svg+xml")],r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192"><rect width="192" height="192" rx="44" fill="#080c14"/><path d="M45 52h102v72h-57l-30 22v-22H45Z" fill="none" stroke="#8bb5ff" stroke-width="10" stroke-linejoin="round"/><path d="M71 78h50M71 99h32" stroke="#8bb5ff" stroke-width="8" stroke-linecap="round"/></svg>"##).into_response()
}
async fn gif_user(a: &App, h: &HeaderMap) -> Api<()> {
    let u = user(a, h)?;
    rate(a, format!("gifs:{}", u.id), 90)
}
pub async fn gifs(State(a): State<App>, h: HeaderMap, Json(v): Json<Value>) -> Api<Json<Value>> {
    gif_user(&a, &h).await?;
    let key = {
        let c = db(&a)?;
        setting(&c, "gif-key")?.as_str().unwrap_or("").to_owned()
    };
    let query = text(&v, "query");
    if query.len() > 256 {
        return Err(bad("Search is too long"));
    }
    let endpoint = if query.trim().is_empty() {
        "trending"
    } else {
        "search"
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("VortexNode/1.0 (self-hosted encrypted chat)")
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| bad("GIF search unavailable"))?;
    if key.is_empty() {
        return commons_gifs(&client, &query).await;
    }
    let result: Value = client
        .get(format!("https://api.giphy.com/v1/gifs/{endpoint}"))
        .query(&[
            ("api_key", key.as_str()),
            ("q", query.as_str()),
            ("limit", "12"),
            ("rating", "pg-13"),
        ])
        .send()
        .await
        .map_err(|_| bad("GIF search unavailable"))?
        .error_for_status()
        .map_err(|_| bad("The GIF provider rejected the request. Check its API key or clear it to use Wikimedia Commons."))?
        .json()
        .await
        .map_err(|_| bad("GIF search unavailable"))?;
    let items=result["data"].as_array().map(|list|list.iter().map(|i|json!({"title":i["title"],"preview":i["images"]["fixed_width_small"]["url"],"url":i["images"]["original"]["url"]})).collect::<Vec<_>>()).unwrap_or_default();
    Ok(Json(json!({"items":items,"provider":"GIPHY"})))
}
fn plain_metadata(value: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    for c in value.chars().take(4096) {
        match c {
            '<' => tag = true,
            '>' => tag = false,
            _ if !tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}
async fn commons_gifs(client: &reqwest::Client, query: &str) -> Api<Json<Value>> {
    let search = format!(
        "filemime:image/gif {}",
        if query.trim().is_empty() {
            "animation"
        } else {
            query.trim()
        }
    );
    let result: Value = client
        .get("https://commons.wikimedia.org/w/api.php")
        .query(&[
            ("action", "query"),
            ("format", "json"),
            ("formatversion", "2"),
            ("generator", "search"),
            ("gsrnamespace", "6"),
            ("gsrsearch", search.as_str()),
            ("gsrlimit", "12"),
            ("prop", "imageinfo"),
            ("iiprop", "url|mime|size|extmetadata"),
        ])
        .send()
        .await
        .map_err(|_| bad("GIF search is temporarily unavailable"))?
        .error_for_status()
        .map_err(|_| bad("GIF search is temporarily unavailable"))?
        .json()
        .await
        .map_err(|_| bad("GIF search is temporarily unavailable"))?;
    if result.get("error").is_some() {
        return Err(bad("GIF search is temporarily unavailable"));
    }
    let items = result["query"]["pages"].as_array().map(|pages| pages.iter().filter_map(|page| {
        let info = &page["imageinfo"][0];
        let url = info["url"].as_str()?;
        if info["mime"] != "image/gif" || info["size"].as_u64().unwrap_or(u64::MAX) > 16 * 1024 * 1024 || !allowed_gif_url(url) { return None; }
        let title = page["title"].as_str().unwrap_or("GIF").trim_start_matches("File:");
        let meta = &info["extmetadata"];
        Some(json!({"title":title,"url":url,"preview":url,"source":info["descriptionurl"],"attribution":format!("{} — {} · {}",title,plain_metadata(meta["Artist"]["value"].as_str().unwrap_or("Wikimedia Commons")),plain_metadata(meta["LicenseShortName"]["value"].as_str().unwrap_or("See source for license")))}))
    }).collect::<Vec<_>>()).unwrap_or_default();
    Ok(Json(json!({"items":items,"provider":"Wikimedia Commons"})))
}
fn allowed_gif_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    let host = url.host_str().unwrap_or("");
    let provider = host == "media.giphy.com"
        || (host.starts_with("media") && host.ends_with(".giphy.com") && host.len() < 24);
    let commons = host == "upload.wikimedia.org"
        && url.path().starts_with("/wikipedia/commons/")
        && url.path().to_ascii_lowercase().ends_with(".gif");
    url.scheme() == "https"
        && (provider || commons)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}
pub async fn gif_file(State(a): State<App>, h: HeaderMap, Json(v): Json<Value>) -> Api<Response> {
    gif_user(&a, &h).await?;
    let raw = text(&v, "url");
    if !allowed_gif_url(&raw) {
        return Err(bad("Unsupported GIF source"));
    }
    let url = reqwest::Url::parse(&raw).map_err(|_| bad("Invalid GIF"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| bad("GIF unavailable"))?;
    let mut r = client
        .get(url)
        .send()
        .await
        .map_err(|_| bad("GIF unavailable"))?;
    if !r.status().is_success() {
        return Err(bad("GIF unavailable"));
    }
    let mut out = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|_| bad("GIF unavailable"))? {
        if out.len() + chunk.len() > 16 * 1024 * 1024 {
            return Err(bad("Choose a smaller GIF"));
        }
        out.extend_from_slice(&chunk);
    }
    if !(out.starts_with(b"GIF87a") || out.starts_with(b"GIF89a")) {
        return Err(bad("Unsupported image format"));
    }
    Ok(([(header::CONTENT_TYPE, "image/gif")], out).into_response())
}
pub async fn auth_script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/chat-auth.js"),
    )
        .into_response()
}
pub async fn stream(State(a): State<App>, h: HeaderMap) -> Api<Response> {
    let u = user(&a, &h)?;
    let rx = a.chat_events.subscribe();
    let stream = futures_util::stream::unfold((a, rx, u), |(a, mut rx, u)| async move {
        loop {
            let event = tokio::select! {result=rx.recv()=>Some(result),_=tokio::time::sleep(Duration::from_secs(20))=>None};
            let live = {
                let c = db(&a).ok()?;
                c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE hash=? AND expires>?) OR EXISTS(SELECT 1 FROM chat_sessions WHERE hash=? AND expires>?)",params![u.session,now(),u.session,now()],|r|r.get::<_,bool>(0)).ok()?
            };
            if !live {
                return None;
            }
            let room = match event {
                Some(Ok(room)) => room,
                Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return None,
                _ => String::new(),
            };
            if !room.is_empty() {
                let permitted = db(&a).ok().is_some_and(|c| member(&c, &u, &room).is_ok());
                if !permitted {
                    continue;
                }
            }
            let e = axum::response::sse::Event::default().data(room);
            return Some((Ok::<_, std::convert::Infallible>(e), (a, rx, u)));
        }
    });
    Ok(axum::response::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(10)))
        .into_response())
}
async fn kick_media(a: &App, room: &str, target: &str) {
    let Some(cfg) = &a.cfg.media else { return };
    let token = jwt(
        &cfg.key,
        &cfg.secret,
        json!({"iss":cfg.key,"sub":"vortex-node","nbf":now()-5,"exp":now()+60,"video":{"roomAdmin":true,"room":room}}),
    );
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return;
    };
    let result = client
        .post(format!(
            "{}/twirp/livekit.RoomService/ListParticipants",
            cfg.http
        ))
        .bearer_auth(&token)
        .json(&json!({"room":room}))
        .send()
        .await;
    let Ok(response) = result else { return };
    let Ok(value) = response.json::<Value>().await else {
        return;
    };
    if let Some(list) = value["participants"].as_array() {
        for p in list {
            let id = text(p, "identity");
            if id.starts_with(&format!("{target}:")) {
                let _ = client
                    .post(format!(
                        "{}/twirp/livekit.RoomService/RemoveParticipant",
                        cfg.http
                    ))
                    .bearer_auth(&token)
                    .json(&json!({"room":room,"identity":id}))
                    .send()
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod polish_tests {
    use super::*;

    fn fixture() -> (
        tempfile::TempDir,
        App,
        HeaderMap,
        HeaderMap,
        SigningKey,
        String,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let c = crate::initialize(dir.path()).unwrap();
        let key = SigningKey::random(&mut OsRng);
        let identity =
            json!({"sign":B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())})
                .to_string();
        let owner_id = random(24);
        let reader_id = random(24);
        c.execute(
            "INSERT INTO accounts(id,username,password) VALUES(1,'owner.user','unused')",
            [],
        )
        .unwrap();
        for (id, name, owner) in [
            (&owner_id, "owner.user", Some(1)),
            (&reader_id, "reader.user", None),
        ] {
            c.execute("INSERT INTO chat_users(id,username,node_owner,registration,bundle,identity,display,created) VALUES(?,?,?,'unused','unused',?,?,?)", params![id,name,owner,identity,name,now()]).unwrap();
        }
        let owner_token = random(32);
        let reader_token = random(32);
        c.execute(
            "INSERT INTO sessions VALUES(?,1,?,?,'test')",
            params![hash(&owner_token), now() + 3600, now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO chat_sessions VALUES(?,?,'test',?,?)",
            params![hash(&reader_token), reader_id, now() + 3600, now()],
        )
        .unwrap();
        let app = Arc::new(Inner {
            cfg: Config {
                email: default_email(),
                media: None,
                listen: "127.0.0.1:0".into(),
                data_dir: dir.path().to_owned(),
                vault_html: dir.path().join("unused"),
                node_id: random(18),
                bridge: random(18),
                reserve_bytes: FLOOR,
            },
            db: Mutex::new(c),
            rates: Mutex::new(HashMap::new()),
            auth_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            io_slots: Arc::new(tokio::sync::Semaphore::new(8)),
            request_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            public_slots: Arc::new(tokio::sync::Semaphore::new(24)),
            chat_stream_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            chat_events: tokio::sync::broadcast::channel(256).0,
            traffic: Mutex::new(traffic::Traffic::default()),
            gc: Mutex::new(GcCursor::default()),
        });
        let mut owner = HeaderMap::new();
        owner.insert(
            header::AUTHORIZATION,
            format!("Bearer {owner_token}").parse().unwrap(),
        );
        let mut reader = HeaderMap::new();
        reader.insert(
            header::AUTHORIZATION,
            format!("Bearer {reader_token}").parse().unwrap(),
        );
        (dir, app, owner, reader, key, owner_id, reader_id)
    }
    fn run(app: &App, h: &HeaderMap, value: Value) -> Api<Value> {
        dispatch(
            app,
            h,
            "127.0.0.1:4242".parse().unwrap(),
            "127.0.0.1",
            value,
        )
    }
    fn envelope(id: &str, owner: &str, reader: Option<&str>, key: &SigningKey) -> Value {
        let mut boxes = serde_json::Map::new();
        boxes.insert(owner.into(), json!(B64.encode([1u8; 64])));
        if let Some(reader) = reader {
            boxes.insert(reader.into(), json!(B64.encode([2u8; 64])));
        }
        let data =
            json!({"version":1,"id":id,"cipher":B64.encode([3u8;64]),"boxes":boxes}).to_string();
        let signature: Signature = key.sign(data.as_bytes());
        json!({"data":data,"signature":B64.encode(signature.to_bytes())})
    }
    #[test]
    fn encrypted_catalog_is_owner_only_signed_versioned_and_recipient_scoped() {
        let (_dir, app, owner, reader, key, owner_id, reader_id) = fixture();
        let id = random(24);
        let body = envelope(&id, &owner_id, None, &key);
        let request = json!({"action":"emoji.publish","id":id,"version":"","body":body});
        assert_eq!(
            run(&app, &reader, request.clone()).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        let published = run(&app, &owner, request.clone()).unwrap();
        let listing = run(&app, &reader, json!({"action":"emoji.list"})).unwrap();
        assert_eq!(listing["items"][0]["ready"], false);
        assert!(listing["items"][0]["recipients"].is_null());
        assert_eq!(
            run(&app, &reader, json!({"action":"emoji.get","id":id}))
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            run(&app, &owner, request).unwrap_err().0,
            StatusCode::CONFLICT
        );
        let next = envelope(&id, &owner_id, Some(&reader_id), &key);
        run(
            &app,
            &owner,
            json!({"action":"emoji.publish","id":id,"version":published["version"],"body":next}),
        )
        .unwrap();
        let entry = run(&app, &reader, json!({"action":"emoji.get","id":id})).unwrap();
        assert_eq!(entry["body"], next);
        assert_eq!(
            run(&app, &reader, json!({"action":"emoji.delete","id":id}))
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        run(&app, &owner, json!({"action":"emoji.delete","id":id})).unwrap();
        assert!(
            run(&app, &owner, json!({"action":"emoji.list"})).unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn altered_or_wrong_publisher_catalog_signatures_are_rejected() {
        let (_dir, app, owner, _reader, key, owner_id, _reader_id) = fixture();
        let id = random(24);
        let mut body = envelope(&id, &owner_id, None, &key);
        let mut data: Value = serde_json::from_str(body["data"].as_str().unwrap()).unwrap();
        data["cipher"] = json!(B64.encode([9u8; 64]));
        body["data"] = json!(data.to_string());
        assert_eq!(
            run(
                &app,
                &owner,
                json!({"action":"emoji.publish","id":id,"body":body})
            )
            .unwrap_err()
            .0,
            StatusCode::BAD_REQUEST
        );
        let wrong = SigningKey::random(&mut OsRng);
        assert!(run(
            &app,
            &owner,
            json!({"action":"emoji.publish","id":id,"body":envelope(&id,&owner_id,None,&wrong)})
        )
        .is_err());
        assert!(
            run(&app, &owner, json!({"action":"emoji.list"})).unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn policy_and_selected_creators_change_atomically_and_preserve_other_permissions() {
        let (_dir, app, owner, reader, _key, _owner_id, reader_id) = fixture();
        {
            let c = db(&app).unwrap();
            c.execute(
                "UPDATE chat_users SET can_invite=1,quota=123456 WHERE id=?",
                [&reader_id],
            )
            .unwrap();
        }
        let initial = json!({"action":"policy","title":"Node","signupUntil":0,"createSpaces":"selected","spaceCreators":[reader_id]});
        assert_eq!(
            run(&app, &reader, initial.clone()).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        run(&app, &owner, initial).unwrap();
        let invalid = json!({"action":"policy","title":"Invalid change","signupUntil":0,"createSpaces":"selected","spaceCreators":[random(24)]});
        assert!(run(&app, &owner, invalid).is_err());
        let c = db(&app).unwrap();
        assert_eq!(setting(&c, "policy").unwrap()["title"], "Node");
        let values: (bool, bool, i64) = c
            .query_row(
                "SELECT can_space,can_invite,quota FROM chat_users WHERE id=?",
                [&reader_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(values, (true, true, 123456));
    }
    #[test]
    fn gif_proxy_allowlist_blocks_other_hosts_ports_credentials_and_non_gif_commons_files() {
        for url in [
            "https://media.giphy.com/media/id/giphy.gif",
            "https://media2.giphy.com/media/id/giphy.gif",
            "https://upload.wikimedia.org/wikipedia/commons/a/ab/Cat.gif?utm_source=commons",
        ] {
            assert!(allowed_gif_url(url), "{url}");
        }
        for url in [
            "http://media.giphy.com/a.gif",
            "https://media.giphy.com.evil.test/a.gif",
            "https://127.0.0.1/a.gif",
            "https://media.giphy.com:8443/a.gif",
            "https://user:password@media.giphy.com/a.gif",
            "https://upload.wikimedia.org/wikipedia/en/a.gif",
            "https://upload.wikimedia.org/wikipedia/commons/a.svg",
            "https://evil.test/a.gif",
            "https://media.giphy.com/a.gif#fragment",
        ] {
            assert!(!allowed_gif_url(url), "{url}");
        }
        assert_eq!(
            plain_metadata("<a href='https://example.test'>Creator &amp; artist</a>"),
            "Creator & artist"
        );
    }
    #[tokio::test]
    async fn attachment_ciphertext_stays_restricted_to_conversation_members() {
        let (_dir, app, owner, reader, _key, owner_id, _reader_id) = fixture();
        let room = random(24);
        let object = random(24);
        let bytes = vec![7u8; 64];
        {
            let c = db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','dm',?,'cipher',?)",params![room,owner_id,now()]).unwrap();
            c.execute(
                "INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",
                params![room, owner_id],
            )
            .unwrap();
            c.execute(
                "INSERT INTO chat_objects VALUES(?,?,?,?,?, ?,1)",
                params![object, room, owner_id, 64, 64, now()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO chat_parts VALUES(?,0,?,64)",
                params![object, hash(&bytes)],
            )
            .unwrap();
        }
        let folder = app.cfg.data_dir.join("chat").join(&object);
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("0"), &bytes).unwrap();
        assert!(
            get_object(State(app.clone()), owner, RoutePath((object.clone(), 0)))
                .await
                .is_ok()
        );
        assert_eq!(
            get_object(State(app.clone()), reader, RoutePath((object, 0)))
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn media_tokens_require_membership_an_active_owned_device_and_no_timeout() {
        let (_dir, mut app, owner, reader, _key, owner_id, reader_id) = fixture();
        Arc::get_mut(&mut app).unwrap().cfg.media = Some(Media {
            url: "wss://node.test/chat/relay".into(),
            http: "http://127.0.0.1:7880".into(),
            key: "test-key".into(),
            secret: "test-secret".into(),
        });
        let room = random(24);
        let device = random(24);
        {
            let c = db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','group',?,'cipher',?)",params![room,owner_id,now()]).unwrap();
            c.execute(
                "INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",
                params![room, reader_id],
            )
            .unwrap();
            c.execute(
                "INSERT INTO chat_devices VALUES(?,?,'certificate','package',?,0)",
                params![device, reader_id, now()],
            )
            .unwrap();
        }
        let value = json!({"room":room,"device":device});
        let token = media_token(State(app.clone()), reader.clone(), Json(value.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(token["url"], "wss://node.test/chat/relay");
        let claims: Value = serde_json::from_slice(
            &B64.decode(token["token"].as_str().unwrap().split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["sub"], format!("{reader_id}:{device}"));
        assert_eq!(claims["video"]["room"], room);
        assert_eq!(claims["video"]["canPublishData"], false);
        assert_eq!(
            media_token(State(app.clone()), owner, Json(value.clone()))
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        {
            let c = db(&app).unwrap();
            c.execute(
                "UPDATE chat_members SET timeout=? WHERE room=? AND user=?",
                params![now() + 60, room, reader_id],
            )
            .unwrap();
        }
        assert_eq!(
            media_token(State(app.clone()), reader.clone(), Json(value.clone()))
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        {
            let c = db(&app).unwrap();
            c.execute("UPDATE chat_members SET timeout=0", []).unwrap();
            c.execute("UPDATE chat_devices SET revoked=1", []).unwrap();
        }
        assert_eq!(
            media_token(State(app.clone()), reader, Json(value))
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    #[ignore = "Calls the public Wikimedia Commons service; run explicitly for provider smoke testing"]
    async fn commons_live_search_returns_allowlisted_gifs_without_a_key() {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("VortexNode/1.0 (self-hosted encrypted chat)")
            .timeout(Duration::from_secs(15));
        // Optional trust anchor for a test runner behind a TLS-inspecting proxy.
        // This test-only setting never changes the production provider client.
        if let Ok(path) = std::env::var("VORTEX_TEST_CA") {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&fs::read(path).unwrap()).unwrap(),
            );
        }
        let client = builder.build().unwrap();
        let result = commons_gifs(&client, "cat").await.unwrap().0;
        let items = result["items"].as_array().unwrap();
        assert!(!items.is_empty());
        for item in items {
            assert!(allowed_gif_url(item["url"].as_str().unwrap()));
            assert!(item["attribution"].as_str().unwrap().contains('·'));
        }
    }
}
