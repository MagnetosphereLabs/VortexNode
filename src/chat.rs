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
pub fn push_public_key(c: &Connection) -> Api<String> {
    let bytes = B64.decode(setting(c, "vapid")?.as_str().unwrap_or("")).map_err(|_| bad("Push unavailable"))?;
    let key = SigningKey::from_slice(&bytes).map_err(|_| bad("Push unavailable"))?;
    Ok(B64.encode(key.verifying_key().to_encoded_point(false).as_bytes()))
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
    if creator == u.id || !space.is_empty() && permission(c, u, &space, bit)?
    {
        Ok(())
    } else {
        Err(denied())
    }
}
const MAX_CHAT_UPLOAD: i64 = 100 * 1024 * 1024 * 1024;
// Keep settings exactly representable by the JavaScript administration UI (~8 PiB).
const MAX_CHAT_QUOTA: i64 = 9_007_199_254_740_991;
fn chat_limits(c: &Connection) -> Api<(i64, i64)> {
    let policy = setting(c, "policy")?;
    Ok((policy["maxUpload"].as_i64().unwrap_or(MAX_CHAT_UPLOAD).clamp(1, MAX_CHAT_UPLOAD),
        policy["chatQuota"].as_i64().unwrap_or(0).max(0)))
}
fn chat_storage_used(c: &Connection) -> Api<i64> {
    // Count complete files and in-flight reservations, so concurrent uploads cannot overbook.
    Ok(c.query_row("SELECT (SELECT COALESCE(SUM(bytes),0) FROM chat_objects)+(SELECT COALESCE(SUM(length(CAST(body AS BLOB))),0) FROM chat_events)+(SELECT COALESCE(SUM(length(CAST(body AS BLOB))),0) FROM chat_node_emoji)", [], |r|r.get(0))?)
}
fn reserve_chat(c: &Connection, additional: i64) -> Api<()> {
    let (_, quota) = chat_limits(c)?;
    if quota > 0 && chat_storage_used(c)?.saturating_add(additional) > quota {
        return Err(Fault(StatusCode::INSUFFICIENT_STORAGE, "The Node's Chat storage allowance is full"));
    }
    Ok(())
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
    let mut q=c.prepare("SELECT id,username,display,identity,profile,CASE WHEN status='invisible' OR NOT EXISTS(SELECT 1 FROM chat_activity WHERE user=chat_users.id AND at>unixepoch()-90) THEN 'offline' WHEN status='online' AND NOT EXISTS(SELECT 1 FROM chat_activity WHERE user=chat_users.id AND at>unixepoch()-45 AND idle=0) THEN 'idle' ELSE status END,created,node_owner IS NOT NULL FROM chat_users WHERE disabled=0 ORDER BY username LIMIT 4096")?;
    let rows=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"username":r.get::<_,String>(1)?,"display":r.get::<_,String>(2)?,"identity":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"profile":!r.get::<_,String>(4)?.is_empty(),"status":r.get::<_,String>(5)?,"created":r.get::<_,i64>(6)?,"owner":r.get::<_,bool>(7)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(json!(rows))
}
// Only public signing/exchange keys survive account deletion, so shared history
// and conversation key signatures remain verifiable. No login or profile remains.
fn former_users(c: &Connection) -> Api<Value> {
    let mut q = c.prepare("SELECT id,identity,devices FROM chat_deleted_users")?;
    let rows = q.query_map([], |r| Ok(json!({"id":r.get::<_,String>(0)?,"identity":serde_json::from_str::<Value>(&r.get::<_,String>(1)?).unwrap_or(Value::Null),"devices":serde_json::from_str::<Value>(&r.get::<_,String>(2)?).unwrap_or(json!([])),"username":"deleted","display":"Deleted account","status":"offline","deleted":true})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(json!(rows))
}
fn are_friends(c: &Connection, a: &str, b: &str) -> Api<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends f JOIN chat_friends other ON other.user=f.other AND other.other=f.user JOIN chat_users person ON person.id=f.other WHERE f.user=? AND f.other=? AND f.status='friend' AND other.status='friend' AND person.disabled=0)", params![a,b], |r| r.get(0))?)
}
fn friend_ids(c: &Connection, user: &str) -> Api<Value> {
    let mut q = c.prepare("SELECT f.other FROM chat_friends f JOIN chat_friends other ON other.user=f.other AND other.other=f.user JOIN chat_users person ON person.id=f.other WHERE f.user=? AND f.status='friend' AND other.status='friend' AND person.disabled=0 ORDER BY f.other")?;
    let ids = q.query_map([user], |r| r.get::<_, String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(json!(ids))
}
fn require_dm_friend(c: &Connection, user: &str, room: &str) -> Api<()> {
    let direct: bool = c.query_row("SELECT kind='dm' AND space='' FROM chat_rooms WHERE id=?", [room], |r| r.get(0))?;
    if direct {
        let other: Option<String> = c.query_row("SELECT user FROM chat_members WHERE room=? AND user!=? AND banned=0 LIMIT 1", params![room,user], |r| r.get(0)).optional()?;
        if !other.as_deref().map(|other| are_friends(c,user,other)).transpose()?.unwrap_or(false) {
            return Err(Fault(StatusCode::FORBIDDEN, "Become friends before sending direct messages or starting a call"));
        }
    }
    Ok(())
}
fn active_now(c: &Connection, user: &str) -> Api<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM chat_activity WHERE user=? AND at>? AND idle=0 AND viewing=1)",
        params![user, now() - 45],
        |r| r.get(0),
    )?)
}
fn notify(c: &Connection, target: &str, kind: &str, room: &str) -> Api<()> {
    let muted:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_mutes WHERE user=? AND until>? AND (scope='room:'||? OR scope='space:'||COALESCE((SELECT space FROM chat_rooms WHERE id=?),'')))",params![target,now(),room,room],|r|r.get(0))?;
    let dnd: bool = c
        .query_row(
            "SELECT status='dnd' FROM chat_users WHERE id=?",
            [target],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false);
    let push_ok = !(muted || dnd || active_now(c, target)?);
    c.execute(
        "INSERT INTO chat_notices(user,kind,room,at,push_ok) VALUES(?,?,?,?,?)",
        params![target, kind, room, now(), push_ok as i32],
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
 CREATE TABLE IF NOT EXISTS chat_activity(user TEXT NOT NULL,session TEXT NOT NULL,instance TEXT NOT NULL,at INTEGER NOT NULL,idle INTEGER NOT NULL,PRIMARY KEY(user,session,instance));
 CREATE INDEX IF NOT EXISTS chat_activity_user ON chat_activity(user,at);
 CREATE TABLE IF NOT EXISTS chat_mutes(user TEXT NOT NULL,scope TEXT NOT NULL,until INTEGER NOT NULL,PRIMARY KEY(user,scope));
 CREATE TABLE IF NOT EXISTS chat_space_invites(id TEXT PRIMARY KEY,space TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS chat_object_sender ON chat_objects(sender);
 CREATE INDEX IF NOT EXISTS chat_object_room ON chat_objects(room);
 CREATE INDEX IF NOT EXISTS chat_event_sender ON chat_events(sender);
 CREATE INDEX IF NOT EXISTS chat_room_space ON chat_rooms(space);
 CREATE TABLE IF NOT EXISTS chat_friends(user TEXT NOT NULL,other TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(user,other));
 CREATE TABLE IF NOT EXISTS chat_deleted_users(id TEXT PRIMARY KEY,identity TEXT NOT NULL,devices TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_totp(user TEXT PRIMARY KEY,seed TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS chat_recovery(user TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(user,hash));")?;
    if c.prepare("SELECT viewing FROM chat_activity LIMIT 0").is_err() {
        c.execute_batch("ALTER TABLE chat_activity ADD COLUMN viewing INTEGER NOT NULL DEFAULT 1")?;
    }
    if !c.prepare("SELECT quota FROM chat_spaces LIMIT 0").is_ok() {
        c.execute(
            "ALTER TABLE chat_spaces ADD COLUMN quota INTEGER NOT NULL DEFAULT 107374182400",
            [],
        )?;
    }
    if c.prepare("SELECT push_ok FROM chat_notices LIMIT 0")
        .is_err()
    {
        c.execute(
            "ALTER TABLE chat_notices ADD COLUMN push_ok INTEGER NOT NULL DEFAULT 1",
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
        "space.invites",
        "auth.config",
        "presence",
        "emoji.list",
        "emoji.get",
        "admin.storage",
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
    let access_removed = if name == "room.access" {
        let actor = user(&a, &h)?;
        let c = db(&a)?;
        room_permission(&c, &actor, &room, 1)?;
        let selected = v["members"].as_array().ok_or(bad("Invalid channel participants"))?;
        let mut query = c.prepare("SELECT user FROM chat_members WHERE room=? AND banned=0")?;
        let rows = query.query_map([&room], |r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        rows.into_iter().filter(|id| !selected.iter().any(|entry| text(entry,"user")==*id)).collect::<Vec<_>>()
    } else { Vec::new() };
    let deleted_user = if name == "admin.user.delete" || (name == "admin.user" && v["disabled"] == true) { Some(text(&v, "user")) } else { None };
    let deleted_rooms = if let Some(target) = &deleted_user {
        owner(&user(&a, &h)?)?;
        let c = db(&a)?;
        let mut q = c.prepare("SELECT room FROM chat_members WHERE user=?")?;
        let rows = q.query_map([target], |r| r.get::<_, String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        rows
    } else { Vec::new() };
    let space_ban = if name == "space.member" && v["banned"] == true {
        let actor = user(&a, &h)?;
        let c = db(&a)?;
        let space = text(&v, "space");
        if !permission(&c, &actor, &space, 128)? { return Err(denied()); }
        let mut q = c.prepare("SELECT id FROM chat_rooms WHERE space=?")?;
        let rooms = q.query_map([space], |r| r.get::<_, String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Some((text(&v, "user"), rooms))
    } else { None };
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
    if !access_removed.is_empty() { kick_media_users(&a, &room, &access_removed).await; }
    if let Some(target) = deleted_user {
        for room in deleted_rooms { kick_media(&a, &room, &target).await; }
    }
    if let Some((target, rooms)) = space_ban {
        for room in rooms { kick_media(&a, &room, &target).await; }
    }
    if changed {
        let _ = a.chat_events.send(if name == "room.access" { String::new() } else { room });
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
            let tx = c.transaction()?;
            let growth = (body.len() as i64 - old.as_ref().map(|value|value.len() as i64).unwrap_or(0)).max(0);
            if growth > 0 { reserve_chat(&tx, growth)?; reserve(&tx, a, growth as u64)?; }
            tx.execute("INSERT INTO chat_node_emoji VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET creator=excluded.creator,body=excluded.body,audience=excluded.audience", params![id,u.id,body,json!(audience).to_string()])?;
            tx.commit()?;
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
                json!({"id":u.id,"owner":u.owner,"canInvite":u.owner || c.query_row("SELECT can_invite FROM chat_users WHERE id=?",[&u.id],|r|r.get::<_,bool>(0))?,"canSpace":u.owner || c.query_row("SELECT can_space FROM chat_users WHERE id=?",[&u.id],|r|r.get::<_,bool>(0))?,"username":name,"bundle":bundle,"identity":serde_json::from_str::<Value>(&identity).unwrap_or(Value::Null),"totp":!totp.is_empty(),"policy":setting(&c,"policy")?,"users":directory(&c)?,"formerUsers":former_users(&c)?,"friendIds":friend_ids(&c,&u.id)?,"media":a.cfg.media.is_some(),"months":c.query_row("SELECT months FROM chat_login_policy WHERE user=?",[&u.id],|r|r.get::<_,i64>(0)).optional()?.unwrap_or(12),"preferences":c.query_row("SELECT body FROM chat_preferences WHERE user=?",[&u.id],|r|r.get::<_,String>(0)).optional()?.unwrap_or_default()}),
            )
        }
        "logout" => {
            c.execute("DELETE FROM chat_push WHERE session=?", [&u.session])?;
            c.execute("DELETE FROM chat_activity WHERE session=?", [&u.session])?;
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
        "directory" => Ok(json!({"users":directory(&c)?,"formerUsers":former_users(&c)?})),
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
                "SELECT id,can_invite,can_space,disabled,quota,username,display,node_owner IS NOT NULL FROM chat_users",
            )?;
            let users=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"invite":r.get::<_,bool>(1)?,"spaces":r.get::<_,bool>(2)?,"disabled":r.get::<_,bool>(3)?,"quota":r.get::<_,i64>(4)?,"username":r.get::<_,String>(5)?,"display":r.get::<_,String>(6)?,"owner":r.get::<_,bool>(7)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"users":users}))
        }
        "profile.get" => {
            let target = text(&v, "user");
            if c.query_row("SELECT EXISTS(SELECT 1 FROM chat_deleted_users WHERE id=?)", [&target], |r| r.get::<_, bool>(0))? { return Ok(json!({"profile":""})); }
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
            let was_request:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends WHERE user=? AND other=? AND status='request')",params![u.id,other],|r|r.get(0))?;
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
            if kind == "request" && !was_request {
                notify(&tx, &other, "friend.request", &u.id)?;
            }
            if kind == "accept" {
                notify(&tx, &other, "friend.accept", &u.id)?;
            }
            tx.commit()?;
            Ok(json!({"ok":true,"friendIds":friend_ids(&c,&u.id)?}))
        }
        "friends" => {
            // Accepted friendships have reciprocal rows. Return one visible
            // relationship per person; another user's block is private.
            let mut q = c.prepare("SELECT f.user,f.other,f.status FROM chat_friends f JOIN chat_users person ON person.id=CASE WHEN f.user=?1 THEN f.other ELSE f.user END WHERE person.disabled=0 AND (f.user=?1 OR (f.other=?1 AND f.status!='blocked' AND NOT EXISTS(SELECT 1 FROM chat_friends own WHERE own.user=?1 AND own.other=f.user))) ORDER BY person.username")?;
            let rows=q.query_map([&u.id],|r|Ok(json!({"user":r.get::<_,String>(0)?,"other":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
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
            let tx = c.transaction()?;
            let (space, kind): (String, String) = tx.query_row(
                "SELECT space,kind FROM chat_rooms WHERE id=?", [&room], |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if !tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND disabled=0)", [&target], |r| r.get::<_, bool>(0))? {
                return Err(bad("Unknown account"));
            }
            let existing: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_members WHERE room=? AND user=? AND banned=0)", params![room,target], |r|r.get(0))?;
            // A DM cannot silently become a group conversation. Create a new
            // group with an explicit participant list instead.
            if kind == "dm" && !existing { return Err(denied()); }
            if space.is_empty() {
                let blocked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends f JOIN chat_members m ON m.room=? AND m.banned=0 WHERE f.status='blocked' AND ((f.user=m.user AND f.other=?) OR (f.user=? AND f.other=m.user)))", params![room,target,target], |r|r.get(0))?;
                if blocked { return Err(denied()); }
            } else if tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members WHERE space=? AND user=? AND banned=1)", params![space,target], |r|r.get::<_,bool>(0))? {
                return Err(denied());
            }
            if !existing && tx.query_row("SELECT COUNT(*) FROM chat_members WHERE room=? AND banned=0", [&room], |r|r.get::<_,i64>(0))? >= 256 {
                return Err(bad("Conversation participant limit reached"));
            }
            tx.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,?) ON CONFLICT(room,user) DO UPDATE SET box=excluded.box,banned=0", params![room,target,box_value])?;
            if !space.is_empty() {
                tx.execute("INSERT OR IGNORE INTO chat_space_members(space,user) VALUES(?,?)", params![space,target])?;
            }
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "room.access" => {
            let room = text(&v, "room");
            room_permission(&c, &u, &room, 1)?;
            let (space, creator): (String, String) = c.query_row("SELECT space,creator FROM chat_rooms WHERE id=?", [&room], |r|Ok((r.get(0)?,r.get(1)?)))?;
            if space.is_empty() { return Err(denied()); }
            let boxes = v["members"].as_array().filter(|items| !items.is_empty() && items.len() <= 4096).ok_or(bad("Invalid channel participants"))?;
            let sealed = ciphertext(&v, "sealed", 65536)?;
            let tx = c.transaction()?;
            let mut ids = std::collections::HashSet::new();
            for entry in boxes {
                let id = text(entry, "user");
                if !ids.insert(id.clone()) || !tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members m JOIN chat_users u ON u.id=m.user WHERE m.space=? AND m.user=? AND m.banned=0 AND u.disabled=0)", params![space,id], |r|r.get::<_,bool>(0))? { return Err(bad("Choose active members of this Space")); }
                ciphertext(entry, "box", 32768)?;
            }
            if !ids.contains(&creator) || !ids.contains(&u.id) { return Err(bad("Keep the channel creator and yourself in the channel")); }
            tx.execute("UPDATE chat_members SET banned=1 WHERE room=?", [&room])?;
            for entry in boxes {
                tx.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,?) ON CONFLICT(room,user) DO UPDATE SET box=excluded.box,banned=0,timeout=0", params![room,text(entry,"user"),ciphertext(entry,"box",32768)?])?;
            }
            tx.execute("UPDATE chat_rooms SET sealed=?,needs_rekey=1 WHERE id=?", params![sealed,room])?;
            tx.commit()?;
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
            let included:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members WHERE space=? AND user=? AND banned=0)",params![space,u.id],|r|r.get(0))?;
            if !included {
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
            let deleted_member: bool = c.query_row("SELECT needs_rekey=2 FROM chat_rooms WHERE id=?", [&room], |r| r.get(0))?;
            if deleted_member { member(&c, &u, &room)?; } else if room_permission(&c, &u, &room, 2).is_err() { room_permission(&c, &u, &room, 1)?; }
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
        "status" => {
            let status = text(&v, "status");
            if !["online", "idle", "dnd", "invisible"].contains(&status.as_str()) {
                return Err(bad("Invalid status"));
            }
            c.execute("UPDATE chat_users SET status=? WHERE id=?", params![status,u.id])?;
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
        "admin.storage" => {
            owner(&u)?;
            let (max_upload, quota) = chat_limits(&c)?;
            Ok(json!({"maxUpload":max_upload,"quota":quota,"used":chat_storage_used(&c)?}))
        }
        "policy" => {
            owner(&u)?;
            let (old_upload, old_quota) = chat_limits(&c)?;
            let max_upload = match v.get("maxUpload") {
                Some(value) => value.as_i64().filter(|n| (1..=MAX_CHAT_UPLOAD).contains(n)).ok_or(bad("Maximum upload must be between 1 byte and 100 GiB"))?,
                None => old_upload,
            };
            let chat_quota = match v.get("chatQuota") {
                Some(value) => value.as_i64().filter(|n| (0..=MAX_CHAT_QUOTA).contains(n)).ok_or(bad("Invalid Chat storage allowance"))?,
                None => old_quota,
            };
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
                &json!({"signupUntil":until,"createSpaces":create,"title":title,"ready":true,"maxUpload":max_upload,"chatQuota":chat_quota}),
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
            let tx = c.transaction()?;
            tx.execute(
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
                tx.execute("DELETE FROM chat_sessions WHERE user=?", [&id])?;
                tx.execute("UPDATE chat_rooms SET needs_rekey=2 WHERE id IN (SELECT room FROM chat_members WHERE user=?)", [&id])?;
                tx.execute("UPDATE chat_members SET banned=1 WHERE user=?", [&id])?;
            }
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "admin.user.delete" => {
            owner(&u)?;
            let id = text(&v, "user");
            let (node_owner, identity, username): (Option<i64>, String, String) = c.query_row(
                "SELECT node_owner,identity,username FROM chat_users WHERE id=?", [&id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ).optional()?.ok_or(bad("Account not found"))?;
            if node_owner.is_some() || id == u.id { return Err(denied()); }
            let certificates = devices(&c, &id)?;
            let certificates = certificates.as_array().unwrap().iter().map(|d| json!({"id":d["id"],"certificate":d["certificate"]})).collect::<Vec<_>>();
            let tx = c.transaction()?;
            tx.execute("INSERT INTO chat_deleted_users(id,identity,devices) VALUES(?,?,?)", params![id,identity,json!(certificates).to_string()])?;
            tx.execute("UPDATE chat_rooms SET needs_rekey=2 WHERE id IN(SELECT room FROM chat_members WHERE user=?)", [&id])?;
            tx.execute("DELETE FROM chat_key_packages WHERE device IN(SELECT id FROM chat_devices WHERE user=?)", [&id])?;
            // Keep a durable cleanup record until ciphertext is physically removed.
            tx.execute("UPDATE chat_objects SET complete=0,created=0 WHERE sender=?", [&id])?;
            tx.execute("DELETE FROM chat_friends WHERE user=? OR other=?", params![id,id])?;
            tx.execute("DELETE FROM chat_notices WHERE room=? AND kind IN ('friend.request','friend.accept')", [&id])?;
            tx.execute("DELETE FROM chat_space_invites WHERE sender=? OR recipient=?", params![id,id])?;
            tx.execute("DELETE FROM chat_auth WHERE username=?", [&username])?;
            tx.execute("DELETE FROM chat_invites WHERE creator=?", [&id])?;
            tx.execute("DELETE FROM chat_node_emoji WHERE creator=?", [&id])?;
            for table in ["chat_sessions", "chat_devices", "chat_activity", "chat_presence", "chat_push", "chat_notices", "chat_login_policy", "chat_preferences", "chat_mutes", "chat_totp", "chat_recovery", "chat_members", "chat_space_members"] {
                tx.execute(&format!("DELETE FROM {table} WHERE user=?"), [&id])?;
            }
            tx.execute("DELETE FROM chat_users WHERE id=?", [&id])?;
            tx.commit()?;
            cleanup(&c, a)?;
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
        "mute" => {
            let scope = text(&v, "scope");
            if let Some(room) = scope.strip_prefix("room:") {
                member(&c, &u, room)?;
            } else if let Some(space) = scope.strip_prefix("space:") {
                let yes:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members WHERE space=? AND user=? AND banned=0)",params![space,u.id],|r|r.get(0))?;
                if !yes {
                    return Err(denied());
                }
            } else {
                return Err(bad("Invalid notification scope"));
            }
            let until = v["until"]
                .as_i64()
                .unwrap_or(0)
                .clamp(0, now() + 366 * 86400 * 10);
            c.execute("INSERT INTO chat_mutes VALUES(?,?,?) ON CONFLICT(user,scope) DO UPDATE SET until=excluded.until",params![u.id,scope,until])?;
            Ok(json!({"ok":true}))
        }
        "space.invites" => {
            let mut q=c.prepare("SELECT id,space,sender,recipient,body,status,created FROM chat_space_invites WHERE (recipient=? OR sender=?) AND created>? ORDER BY created DESC LIMIT 100")?;
            let invites=q.query_map(params![u.id,u.id,now()-30*86400],|r|Ok(json!({"id":r.get::<_,String>(0)?,"space":r.get::<_,String>(1)?,"sender":r.get::<_,String>(2)?,"recipient":r.get::<_,String>(3)?,"body":serde_json::from_str::<Value>(&r.get::<_,String>(4)?).unwrap_or(Value::Null),"status":r.get::<_,String>(5)?,"created":r.get::<_,i64>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"invites":invites}))
        }
        "space.invite" => {
            let space = text(&v, "space");
            if !permission(&c, &u, &space, 2)? {
                return Err(denied());
            }
            let target = text(&v, "user");
            let id = text(&v, "id");
            if !valid_id(&id) || target == u.id {
                return Err(bad("Invalid invitation"));
            }
            let body = &v["body"];
            let rooms = body["rooms"].as_array().ok_or(bad("Choose channels"))?;
            if rooms.is_empty() || rooms.len() > 256 || body.to_string().len() > 4 * 1024 * 1024 {
                return Err(bad("Invalid invitation"));
            }
            let active: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM chat_users WHERE id=? AND disabled=0)",
                [&target],
                |r| r.get(0),
            )?;
            if !active {
                return Err(bad("Unknown username"));
            }
            let blocked:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members WHERE space=? AND user=? AND banned=1)",params![space,target],|r|r.get(0))?;
            if blocked {
                return Err(denied());
            }
            for item in rooms {
                let room = text(item, "room");
                room_permission(&c, &u, &room, 2)?;
                let (actual, base): (String, String) = c.query_row(
                    "SELECT space,sealed FROM chat_rooms WHERE id=?",
                    [&room],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let creator: String =
                    c.query_row("SELECT creator FROM chat_rooms WHERE id=?", [&room], |r| {
                        r.get(0)
                    })?;
                if actual != space || base != text(item, "base") || creator != text(item, "creator")
                {
                    return Err(conflict());
                }
                ciphertext(item, "box", 32768)?;
                ciphertext(item, "sealed", 65536)?;
            }
            ciphertext(body, "label", 32768)?;
            decode(body, "signature", 256)?;
            let retained: i64 = c.query_row(
                "SELECT COALESCE(SUM(length(body)),0) FROM chat_space_invites WHERE sender=?",
                [&u.id],
                |r| r.get(0),
            )?;
            if retained.saturating_add(body.to_string().len() as i64) > 64 * 1024 * 1024 {
                return Err(bad("Invitation storage limit reached. Try again later."));
            }
            let tx = c.transaction()?;
            reserve(&tx, a, body.to_string().len() as u64)?;
            tx.execute("UPDATE chat_space_invites SET status='superseded' WHERE space=? AND recipient=? AND status='pending'",params![space,target])?;
            tx.execute("INSERT INTO chat_space_invites(id,space,sender,recipient,body,created) VALUES(?,?,?,?,?,?)",params![id,space,u.id,target,body.to_string(),now()])?;
            notify(&tx, &target, "space.invite", &id)?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "space.invite.respond" => {
            let id = text(&v, "id");
            let (space,recipient,raw,status,created,sender):(String,String,String,String,i64,String)=c.query_row("SELECT space,recipient,body,status,created,sender FROM chat_space_invites WHERE id=?",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
            if recipient != u.id || status != "pending" || created < now() - 7 * 86400 {
                return Err(denied());
            }
            let accept = v["accept"].as_bool().unwrap_or(false);
            let body: Value = serde_json::from_str(&raw).map_err(|_| bad("Invalid invitation"))?;
            let tx = c.transaction()?;
            if accept {
                let inviter_owner: bool = tx
                    .query_row(
                        "SELECT node_owner IS NOT NULL FROM chat_users WHERE id=? AND disabled=0",
                        [&sender],
                        |r| r.get(0),
                    )
                    .optional()?
                    .ok_or(denied())?;
                let inviter = User {
                    id: sender.clone(),
                    owner: inviter_owner,
                    session: String::new(),
                };
                if !permission(&tx, &inviter, &space, 2)? {
                    return Err(denied());
                }
                let blocked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members WHERE space=? AND user=? AND banned=1)",params![space,u.id],|r|r.get(0))?;
                if blocked {
                    return Err(denied());
                }
                for item in body["rooms"].as_array().ok_or(bad("Invalid invitation"))? {
                    let room = text(item, "room");
                    room_permission(&tx, &inviter, &room, 2)?;
                    let (actual, base): (String, String) = tx.query_row(
                        "SELECT space,sealed FROM chat_rooms WHERE id=?",
                        [&room],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    if actual != space || base != text(item, "base") {
                        return Err(bad("This invitation needs to be refreshed. Ask the sender to invite you again."));
                    }
                    tx.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,?) ON CONFLICT(room,user) DO UPDATE SET box=excluded.box WHERE banned=0",params![room,u.id,text(item,"box")])?;
                    tx.execute(
                        "UPDATE chat_rooms SET sealed=? WHERE id=?",
                        params![text(item, "sealed"), room],
                    )?;
                }
                tx.execute(
                    "INSERT OR IGNORE INTO chat_space_members(space,user) VALUES(?,?)",
                    params![space, u.id],
                )?;
            }
            tx.execute(
                "UPDATE chat_space_invites SET status=? WHERE id=?",
                params![if accept { "accepted" } else { "declined" }, id],
            )?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        "presence" => {
            let instance = text(&v, "instance");
            if instance.len() > 96 {
                return Err(bad("Invalid browser instance"));
            }
            if v["leave"] == true {
                c.execute("DELETE FROM chat_activity WHERE user=? AND session=? AND instance=?", params![u.id,u.session,instance])?;
            } else {
                c.execute("INSERT INTO chat_activity(user,session,instance,at,idle,viewing) VALUES(?,?,?,?,?,?) ON CONFLICT(user,session,instance) DO UPDATE SET at=excluded.at,idle=excluded.idle,viewing=excluded.viewing",params![u.id,u.session,instance,now(),v["idle"].as_bool().unwrap_or(false) as i32,v["viewing"].as_bool().unwrap_or(true) as i32])?;
            }
            c.execute("DELETE FROM chat_activity WHERE at<?", [now() - 300])?;
            Ok(json!({"ok":true,"users":directory(&c)?,"formerUsers":former_users(&c)?,"friendIds":friend_ids(&c,&u.id)?}))
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
            if target == creator || target == u.id {
                return Err(denied());
            }
            let mine: i64 = if creator == u.id {
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
            let tx = c.transaction()?;
            tx.execute("INSERT INTO chat_space_members VALUES(?,?,?,?,?,?) ON CONFLICT(space,user) DO UPDATE SET permissions=excluded.permissions,role=excluded.role,color=excluded.color,banned=excluded.banned",params![space,target,perms,role,color,v["banned"].as_bool().unwrap_or(false) as i32])?;
            if v["banned"] == true {
                tx.execute("UPDATE chat_rooms SET needs_rekey=2 WHERE space=? AND id IN (SELECT room FROM chat_members WHERE user=? AND banned=0)", params![space,target])?;
                tx.execute("UPDATE chat_members SET banned=1 WHERE user=? AND room IN (SELECT id FROM chat_rooms WHERE space=?)", params![target,space])?;
            }
            tx.commit()?;
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
            if kind == "dm" {
                if !space.is_empty() || users.len()!=2 || users[0]["user"]==users[1]["user"] {
                    return Err(bad("Direct messages require exactly two people"));
                }
                for person in users {
                    let other = text(person,"user");
                    if other!=u.id && !are_friends(&c,&u.id,&other)? {
                        return Err(Fault(StatusCode::FORBIDDEN,"Become friends before starting a direct message"));
                    }
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
            let space: String = c.query_row("SELECT space FROM chat_rooms WHERE id=?", [&room], |r|r.get(0))?;
            if space.is_empty() { return Err(denied()); }
            room_permission(&c, &u, &room, 2)?;
            let target = text(&v, "user");
            let creator: String =
                c.query_row("SELECT creator FROM chat_rooms WHERE id=?", [&room], |r| {
                    r.get(0)
                })?;
            if target == creator || target == u.id {
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
            if space.is_empty() && kind_room=="dm" && c.query_row("SELECT EXISTS(SELECT 1 FROM chat_members m JOIN chat_friends f ON ((f.user=?2 AND f.other=m.user) OR (f.other=?2 AND f.user=m.user)) WHERE m.room=?1 AND m.user!=?2 AND f.status='blocked')",params![room,u.id],|r|r.get::<_,bool>(0))? {return Err(denied())}
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
            if kind=="message" || kind=="call" { require_dm_friend(&c,&u.id,&room)?; }
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
            reserve_chat(&tx, body.len() as i64)?;
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
            let mut q=c.prepare("SELECT id,kind,room,at,push_ok AND NOT EXISTS(SELECT 1 FROM chat_mutes m WHERE m.user=chat_notices.user AND m.until>unixepoch() AND (m.scope='room:'||chat_notices.room OR m.scope='space:'||COALESCE((SELECT space FROM chat_rooms WHERE id=chat_notices.room),''))) FROM chat_notices WHERE user=? AND id>? ORDER BY id LIMIT 100")?;
            let rows=q.query_map(params![u.id,after],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"room":r.get::<_,String>(2)?,"at":r.get::<_,i64>(3)?,"pushAllowed":r.get::<_,bool>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
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
        "push.list" => {
            let mut q = c.prepare("SELECT endpoint FROM chat_push WHERE user=?")?;
            let endpoints = q.query_map([&u.id], |r| r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"endpoints":endpoints}))
        }
        "push.remove" => {
            c.execute("DELETE FROM chat_push WHERE user=? AND endpoint=?", params![u.id,text(&v,"endpoint")])?;
            Ok(json!({"ok":true}))
        }
        "push" => {
            let endpoint = text(&v, "endpoint");
            let parsed = reqwest::Url::parse(&endpoint).map_err(|_| bad("Invalid push service"))?;
            let host = parsed.host_str().unwrap_or("");
            if parsed.scheme() != "https" || parsed.port().is_some_and(|port| port != 443)
                || !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some()
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
            if decode(&v,"p256dh",65)?.len()!=65 || decode(&v,"auth",16)?.len()!=16 { return Err(bad("Invalid push keys")); }
            let count: i64 = c.query_row("SELECT COUNT(*) FROM chat_push WHERE user=? AND endpoint!=?", params![u.id,endpoint], |r| r.get(0))?;
            if count >= 32 { return Err(bad("Remove an old push subscription first")); }
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
        require_dm_friend(&c,&u.id,&room)?;
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
    let identity = if v["client"] == "fluxer" {
        let connection = text(&v,"connection");
        if connection.len() < 16 || connection.len() > 80 || !connection.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'-' || b==b'_') {
            return Err(bad("Invalid call connection"));
        }
        let id = fluxer_user_id(&u.id);
        format!("user_{id}_{connection}")
    } else { format!("{}:{}",u.id,device) };
    // The Vortex client encrypts its codec negotiation and screen-share control
    // packets with the same participant-owned key provider as its media tracks.
    let claims = json!({"iss":cfg.key,"sub":identity,"nbf":now()-5,"exp":now()+120,"video":{"roomJoin":true,"room":room,"canPublish":true,"canSubscribe":true,"canPublishData":v["client"] == "fluxer"}});
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
    require_dm_friend(&tx,&u.id,&room)?;
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
    let (max_upload, _) = chat_limits(&tx)?;
    let encrypted_limit = max_upload + ((max_upload + BLOCK as i64 - 1) / BLOCK as i64) * 28;
    if bytes > encrypted_limit {
        return Err(bad("This file exceeds the Node's maximum upload size"));
    }
    reserve_chat(&tx, bytes)?;
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
    c.execute("DELETE FROM chat_activity WHERE at<?", [now() - 300])?;
    c.execute(
        "DELETE FROM chat_space_invites WHERE created<?",
        [now() - 30 * 86400],
    )?;
    c.execute("DELETE FROM chat_mutes WHERE until<?", [now()])?;
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
            if let Err(error) = fs::remove_dir_all(a.cfg.data_dir.join("chat").join(&id)) {
                if error.kind() != std::io::ErrorKind::NotFound { continue; }
            }
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
            let mut q=c.prepare("SELECT MAX(n.id),p.endpoint FROM chat_notices n JOIN chat_push p ON p.user=n.user WHERE n.id>? AND n.at>? AND n.push_ok=1 AND NOT EXISTS(SELECT 1 FROM chat_activity a WHERE a.user=n.user AND a.at>unixepoch()-45 AND a.idle=0) AND (EXISTS(SELECT 1 FROM sessions s WHERE s.hash=p.session AND s.expires>unixepoch()) OR EXISTS(SELECT 1 FROM chat_sessions s WHERE s.hash=p.session AND s.expires>unixepoch())) GROUP BY p.endpoint ORDER BY MAX(n.id) ASC LIMIT 128")?;
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
            ("iiurlwidth", "240"),
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
        Some(json!({"title":title,"url":url,"preview":info["thumburl"].as_str().filter(|u|allowed_gif_url(u)).unwrap_or(url),"source":info["descriptionurl"],"attribution":format!("{} — {} · {}",title,plain_metadata(meta["Artist"]["value"].as_str().unwrap_or("Wikimedia Commons")),plain_metadata(meta["LicenseShortName"]["value"].as_str().unwrap_or("See source for license")))}))
    }).collect::<Vec<_>>()).unwrap_or_default();
    Ok(Json(json!({"items":items,"provider":"Wikimedia Commons"})))
}
fn allowed_gif_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    let host = url.host_str().unwrap_or("");
    let provider = host == "i.giphy.com"
        || host == "media.giphy.com"
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
        .user_agent("VortexNode/1.0 (https://github.com/MagnetosphereLabs/VortexNode; self-hosted encrypted chat)")
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| bad("GIF unavailable"))?;
    let out = fetch_gif_bytes(&client, url.as_str()).await?;
    Ok(([(header::CONTENT_TYPE, "image/gif")], out).into_response())
}
async fn fetch_gif_bytes(client: &reqwest::Client, raw: &str) -> Api<Vec<u8>> {
    if !allowed_gif_url(raw) {
        return Err(bad("Unsupported GIF source"));
    }
    let mut next = reqwest::Url::parse(raw).map_err(|_| bad("Invalid GIF"))?;
    let mut redirects = 0;
    let mut r = loop {
        let response = client
            .get(next.clone())
            .send()
            .await
            .map_err(|_| bad("GIF provider could not be reached. Try again."))?;
        if response.status().is_redirection() {
            if redirects >= 3 {
                return Err(bad("GIF provider redirected too many times"));
            }
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(bad("GIF unavailable"))?;
            let target = next
                .join(location)
                .map_err(|_| bad("Unsupported GIF source"))?;
            if !allowed_gif_url(target.as_str()) {
                return Err(bad("Unsupported GIF source"));
            }
            next = target;
            redirects += 1;
            continue;
        }
        if !response.status().is_success() {
            return Err(bad(
                "GIF provider could not load this animation. Try another result or retry.",
            ));
        }
        if response
            .content_length()
            .is_some_and(|n| n > 16 * 1024 * 1024)
        {
            return Err(bad("Choose a smaller GIF"));
        }
        break response;
    };
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
    Ok(out)
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
fn fluxer_user_id(user: &str) -> u64 {
    let digest = Sha256::digest(format!("vortex-fluxer-v1:user:{user}").as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes")) & 0x7fffffffffffffff
}
fn media_identity_belongs_to(identity: &str, user: &str) -> bool {
    identity.strip_prefix(user).is_some_and(|suffix| suffix.starts_with(':'))
        || identity.starts_with(&format!("user_{}_", fluxer_user_id(user)))
}
async fn kick_media(a: &App, room: &str, target: &str) {
    kick_media_users(a, room, &[target.to_owned()]).await;
}
async fn kick_media_users(a: &App, room: &str, targets: &[String]) {
    use futures_util::StreamExt;
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
        let mut requests = Vec::new();
        for participant in list {
            let identity = text(participant, "identity");
            if !targets.iter().any(|target| media_identity_belongs_to(&identity, target)) { continue; }
            let request = client.post(format!("{}/twirp/livekit.RoomService/RemoveParticipant", cfg.http))
                .bearer_auth(&token).json(&json!({"room":room,"identity":identity}));
            requests.push(async move { let _ = request.send().await; });
        }
        futures_util::stream::iter(requests).buffer_unordered(8).collect::<Vec<_>>().await;
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
                vault_enabled: true,
                public_url: Some("http://127.0.0.1:4242".into()),
                chat_web_dir: None,
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
    #[tokio::test]
    async fn chat_only_mode_unmounts_vault_without_removing_accounts_or_chat() {
        use tower::ServiceExt;
        let (_dir, mut app, _, _, _, _, _) = fixture();
        Arc::get_mut(&mut app).unwrap().cfg.vault_enabled = false;
        let gate = format!("/gate/{}/vaults", app.cfg.bridge);
        let router = router(app).layer(axum::Extension(ConnectInfo(
            "127.0.0.1:4242".parse::<SocketAddr>().unwrap(),
        )));
        for path in ["/vault", "/vault/", "/receive/", &gate] {
            let response = router.clone().oneshot(axum::http::Request::builder()
                .uri(path).body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        for path in ["/", "/chat", "/health", "/connect"] {
            let response = router.clone().oneshot(axum::http::Request::builder()
                .uri(path).body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn bundled_chat_entry_redirects_to_a_supported_client_route() {
        use tower::ServiceExt;
        let (dir, mut app, _, _, _, _, _) = fixture();
        let web = dir.path().join("web");
        fs::create_dir(&web).unwrap();
        fs::write(web.join("index.html"), "<!doctype html><title>Vortex Chat</title>").unwrap();
        Arc::get_mut(&mut app).unwrap().cfg.chat_web_dir = Some(web);
        let router = router(app).layer(axum::Extension(ConnectInfo(
            "127.0.0.1:4242".parse::<SocketAddr>().unwrap(),
        )));
        for path in ["/chat", "/chat/"] {
            let response = router.clone().oneshot(axum::http::Request::builder()
                .uri(path).body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
            assert_eq!(response.headers()[header::LOCATION], "/channels/@me");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let target = response.headers()[header::LOCATION].clone();
            let landing = router.clone().oneshot(axum::http::Request::builder()
                .uri(target.to_str().unwrap()).body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(landing.status(), StatusCode::OK);
            let html = axum::body::to_bytes(landing.into_body(), 4096).await.unwrap();
            assert!(String::from_utf8_lossy(&html).contains("<title>Vortex Chat</title>"));
        }
        for path in ["/chat/not-an-api", "/vortex/api/not-an-api"] {
            let response = router.clone().oneshot(axum::http::Request::builder()
                .uri(path).body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
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
    fn direct_messages_require_an_accepted_friendship_and_history_survives_unfriending() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let room=random(24);let box_value=B64.encode([7u8;64]);
        let create=json!({"action":"room.create","id":room,"kind":"dm","space":"","sealed":box_value,"members":[{"user":owner_id,"box":box_value},{"user":reader_id,"box":box_value}]});
        assert_eq!(run(&app,&owner,create.clone()).unwrap_err().0,StatusCode::FORBIDDEN);
        run(&app,&owner,json!({"action":"friend","user":reader_id,"kind":"request"})).unwrap();
        assert_eq!(run(&app,&owner,create.clone()).unwrap_err().0,StatusCode::FORBIDDEN);
        let accepted=run(&app,&reader,json!({"action":"friend","user":owner_id,"kind":"accept"})).unwrap();
        assert_eq!(accepted["friendIds"],json!([owner_id]));
        run(&app,&owner,create).unwrap();
        assert!(require_dm_friend(&db(&app).unwrap(),&owner_id,&room).is_ok());
        let fresh=run(&app,&owner,json!({"action":"presence","idle":false})).unwrap();assert_eq!(fresh["friendIds"],json!([reader_id]));
        run(&app,&owner,json!({"action":"friend","user":reader_id,"kind":"remove"})).unwrap();
        assert_eq!(require_dm_friend(&db(&app).unwrap(),&owner_id,&room).unwrap_err().0,StatusCode::FORBIDDEN);
        let device=random(24);db(&app).unwrap().execute("INSERT INTO chat_devices VALUES(?,?,'certificate','package',?,0)",params![device,owner_id,now()]).unwrap();
        let send=json!({"action":"event","room":room,"kind":"message","device":device,"id":random(24),"body":{}});
        let error=run(&app,&owner,send).unwrap_err();assert!(error.1.contains("Become friends"));
        assert!(run(&app,&owner,json!({"action":"events","room":room})).is_ok());
        assert!(run(&app,&owner,json!({"action":"rooms"})).unwrap()["rooms"].as_array().unwrap().iter().any(|r|r["id"]==room));
        db(&app).unwrap().execute("UPDATE chat_rooms SET kind='group' WHERE id=?",[&room]).unwrap();
        assert!(require_dm_friend(&db(&app).unwrap(),&owner_id,&room).is_ok());
    }

    #[test]
    fn adding_participants_preserves_dm_boundaries_blocks_and_account_status() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let room=random(24); let encrypted=B64.encode([7u8;64]);
        {
            let c=db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','dm',?,'cipher',?)",params![room,owner_id,now()]).unwrap();
            c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",params![room,owner_id]).unwrap();
        }
        let add=json!({"action":"room.member","room":room,"user":reader_id,"box":encrypted});
        assert_eq!(run(&app,&owner,add.clone()).unwrap_err().0,StatusCode::FORBIDDEN);
        db(&app).unwrap().execute("UPDATE chat_rooms SET kind='group' WHERE id=?",[&room]).unwrap();
        assert!(run(&app,&reader,add.clone()).is_err());
        run(&app,&reader,json!({"action":"friend","user":owner_id,"kind":"block"})).unwrap();
        assert_eq!(run(&app,&owner,add.clone()).unwrap_err().0,StatusCode::FORBIDDEN);
        {
            let c=db(&app).unwrap();c.execute("DELETE FROM chat_friends",[]).unwrap();
            c.execute("UPDATE chat_users SET disabled=1 WHERE id=?",[&reader_id]).unwrap();
        }
        assert!(run(&app,&owner,add.clone()).is_err());
        db(&app).unwrap().execute("UPDATE chat_users SET disabled=0 WHERE id=?",[&reader_id]).unwrap();
        run(&app,&owner,add.clone()).unwrap();
        let space=random(24);
        {
            let c=db(&app).unwrap();
            c.execute("INSERT INTO chat_spaces(id,creator,sealed,created) VALUES(?,?,'cipher',?)",params![space,owner_id,now()]).unwrap();
            c.execute("INSERT INTO chat_space_members(space,user,permissions) VALUES(?,?,255)",params![space,owner_id]).unwrap();
            c.execute("INSERT INTO chat_space_members(space,user,banned) VALUES(?,?,1)",params![space,reader_id]).unwrap();
            c.execute("UPDATE chat_rooms SET space=?,kind='text' WHERE id=?",params![space,room]).unwrap();
            c.execute("UPDATE chat_members SET banned=1 WHERE room=? AND user=?",params![room,reader_id]).unwrap();
        }
        assert_eq!(run(&app,&owner,add).unwrap_err().0,StatusCode::FORBIDDEN);
        assert_eq!(db(&app).unwrap().query_row("SELECT banned FROM chat_members WHERE room=? AND user=?",params![room,reader_id],|r|r.get::<_,bool>(0)).unwrap(),true);
    }

    #[tokio::test]
    async fn nonfriends_cannot_join_dm_calls_or_upload_dm_attachments() {
        let (_dir, app, owner, _reader, _key, owner_id, reader_id) = fixture();
        let room=random(24);let device=random(24);
        {
            let c=db(&app).unwrap();c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','dm',?,'cipher',?)",params![room,owner_id,now()]).unwrap();
            for id in [&owner_id,&reader_id]{c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",params![room,id]).unwrap();}
            c.execute("INSERT INTO chat_devices VALUES(?,?,'certificate','package',?,0)",params![device,owner_id,now()]).unwrap();
        }
        let media=media_token(State(app.clone()),owner.clone(),Json(json!({"room":room,"device":device}))).await.unwrap_err();assert_eq!(media.0,StatusCode::FORBIDDEN);assert!(media.1.contains("Become friends"));
        let upload=begin_object(State(app.clone()),owner,Json(json!({"room":room,"bytes":64}))).await.unwrap_err();assert_eq!(upload.0,StatusCode::FORBIDDEN);assert!(upload.1.contains("Become friends"));
    }

    #[test]
    fn reciprocal_friendships_are_returned_once_and_other_peoples_blocks_are_private() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        run(&app, &owner, json!({"action":"friend","user":reader_id,"kind":"request"})).unwrap();
        let incoming = run(&app, &reader, json!({"action":"friends"})).unwrap();
        assert_eq!(incoming["friends"].as_array().unwrap().len(), 1);
        run(&app, &reader, json!({"action":"friend","user":owner_id,"kind":"accept"})).unwrap();
        for headers in [&owner, &reader] {
            let result = run(&app, headers, json!({"action":"friends"})).unwrap();
            assert_eq!(result["friends"].as_array().unwrap().len(), 1);
            assert_eq!(result["friends"][0]["status"], "friend");
        }
        run(&app, &reader, json!({"action":"friend","user":owner_id,"kind":"remove"})).unwrap();
        run(&app, &reader, json!({"action":"friend","user":owner_id,"kind":"block"})).unwrap();
        assert!(run(&app, &owner, json!({"action":"friends"})).unwrap()["friends"].as_array().unwrap().is_empty());
    }

    #[test]
    fn status_and_presence_refresh_do_not_overwrite_profiles_and_leave_is_per_tab() {
        let (_dir, app, owner, _reader, _key, owner_id, _reader_id) = fixture();
        db(&app).unwrap().execute("UPDATE chat_users SET profile='encrypted-profile' WHERE id=?", [&owner_id]).unwrap();
        run(&app, &owner, json!({"action":"status","status":"dnd"})).unwrap();
        run(&app, &owner, json!({"action":"presence","instance":"one","idle":false})).unwrap();
        let value = run(&app, &owner, json!({"action":"presence","instance":"two","idle":true})).unwrap();
        assert_eq!(value["users"].as_array().unwrap().iter().find(|u| u["id"]==owner_id).unwrap()["status"], "dnd");
        assert_eq!(run(&app, &owner, json!({"action":"profile.get","user":owner_id})).unwrap()["profile"], "encrypted-profile");
        run(&app, &owner, json!({"action":"presence","instance":"two","leave":true})).unwrap();
        assert!(active_now(&db(&app).unwrap(), &owner_id).unwrap());
        run(&app, &owner, json!({"action":"presence","instance":"one","leave":true})).unwrap();
        assert!(!active_now(&db(&app).unwrap(), &owner_id).unwrap());
        run(&app, &owner, json!({"action":"status","status":"online"})).unwrap();
        let background = run(&app, &owner, json!({"action":"presence","instance":"one","idle":false,"viewing":false})).unwrap();
        assert_eq!(background["users"].as_array().unwrap().iter().find(|u| u["id"]==owner_id).unwrap()["status"], "online");
        assert!(!active_now(&db(&app).unwrap(), &owner_id).unwrap());
        assert!(run(&app, &owner, json!({"action":"status","status":"invalid"})).is_err());
    }

    #[test]
    fn optional_authenticator_enrollment_requires_confirmation_then_returns_recovery_codes() {
        let (_dir, app, _owner, reader, _key, _owner_id, reader_id) = fixture();
        let seed = run(&app, &reader, json!({"action":"totp.start"})).unwrap()["seed"].as_str().unwrap().to_owned();
        assert_eq!(db(&app).unwrap().query_row("SELECT totp FROM chat_users WHERE id=?", [&reader_id], |r| r.get::<_, String>(0)).unwrap(), "");
        assert!(run(&app, &reader, json!({"action":"totp.finish","otp":"invalid"})).is_err());
        let code = totp(&seed, now()/30).unwrap();
        let result = run(&app, &reader, json!({"action":"totp.finish","otp":code})).unwrap();
        assert_eq!(result["recovery"].as_array().unwrap().len(), 10);
        assert_eq!(db(&app).unwrap().query_row("SELECT totp FROM chat_users WHERE id=?", [&reader_id], |r| r.get::<_, String>(0)).unwrap(), seed);
    }

    #[test]
    fn push_subscriptions_are_account_scoped_and_reject_redirect_authority_tricks() {
        let (_dir, app, owner, reader, _key, _owner_id, _reader_id) = fixture();
        let endpoint = "https://web.push.apple.com/test-subscription";
        let request = json!({"action":"push","endpoint":endpoint,"p256dh":B64.encode([4u8;65]),"auth":B64.encode([1u8;16])});
        run(&app, &reader, request.clone()).unwrap();
        assert_eq!(run(&app, &reader, json!({"action":"push.list"})).unwrap()["endpoints"], json!([endpoint]));
        assert_eq!(run(&app, &owner, json!({"action":"push.list"})).unwrap()["endpoints"], json!([]));
        run(&app, &owner, json!({"action":"push.remove","endpoint":endpoint})).unwrap();
        assert_eq!(run(&app, &reader, json!({"action":"push.list"})).unwrap()["endpoints"], json!([endpoint]));
        for invalid in ["https://web.push.apple.com:8443/test", "https://name@web.push.apple.com/test", "https://web.push.apple.com.evil.invalid/test"] {
            let mut body = request.clone();body["endpoint"] = json!(invalid);
            assert!(run(&app, &reader, body).is_err());
        }
        run(&app, &reader, json!({"action":"push.remove","endpoint":endpoint})).unwrap();
        assert_eq!(run(&app, &reader, json!({"action":"push.list"})).unwrap()["endpoints"], json!([]));
    }

    #[test]
    fn disabling_an_account_revokes_sessions_and_requires_fresh_room_keys() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let room = random(24);
        {
            let c = db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','group',?,'cipher',?)", params![room,owner_id,now()]).unwrap();
            for id in [&owner_id,&reader_id] {
                c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')", params![room,id]).unwrap();
            }
        }
        run(&app, &owner, json!({"action":"admin.user","user":reader_id,"disabled":true})).unwrap();
        assert!(user(&app, &reader).is_err());
        let c = db(&app).unwrap();
        assert_eq!(c.query_row("SELECT needs_rekey FROM chat_rooms WHERE id=?", [&room], |r| r.get::<_,i64>(0)).unwrap(), 2);
        assert_eq!(c.query_row("SELECT banned FROM chat_members WHERE room=? AND user=?", params![room,reader_id], |r| r.get::<_,i64>(0)).unwrap(), 1);
        assert_eq!(c.query_row("SELECT banned FROM chat_members WHERE room=? AND user=?", params![room,owner_id], |r| r.get::<_,i64>(0)).unwrap(), 0);
        drop(c);
        run(&app, &owner, json!({"action":"admin.user","user":reader_id,"disabled":false})).unwrap();
        assert!(user(&app, &reader).is_err(), "Re-enabling an account must not revive old tokens");
    }

    #[test]
    fn permanent_account_deletion_revokes_access_and_retains_only_public_history_verification() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let room = random(24); let device = random(24); let object = random(24);
        {
            let c = db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','dm',?,'cipher',?)", params![room,reader_id,now()]).unwrap();
            for id in [&owner_id,&reader_id] { c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')", params![room,id]).unwrap(); }
            c.execute("INSERT INTO chat_devices VALUES(?,?,'{}','public-package',?,0)", params![device,reader_id,now()]).unwrap();
            c.execute("INSERT INTO chat_preferences VALUES(?,'private-preferences')", [&reader_id]).unwrap();
            c.execute("INSERT INTO chat_objects VALUES(?,?,?,?,?,?,1)", params![object,room,reader_id,64,64,now()]).unwrap();
            c.execute("INSERT INTO chat_parts VALUES(?,0,'digest',64)", [&object]).unwrap();
            c.execute("INSERT INTO chat_events(room,sender,device,id,kind,body,at) VALUES(?,?,?,?,'message','{}',?)", params![room,reader_id,device,random(24),now()]).unwrap();
        }
        let folder = app.cfg.data_dir.join("chat").join(&object);fs::create_dir_all(&folder).unwrap();fs::write(folder.join("0"), b"ciphertext").unwrap();
        assert_eq!(run(&app, &reader, json!({"action":"admin.user.delete","user":owner_id})).unwrap_err().0, StatusCode::FORBIDDEN);
        assert_eq!(run(&app, &owner, json!({"action":"admin.user.delete","user":owner_id})).unwrap_err().0, StatusCode::FORBIDDEN);
        run(&app, &owner, json!({"action":"admin.user.delete","user":reader_id})).unwrap();
        assert!(user(&app,&reader).is_err());assert!(!folder.exists());
        let c = db(&app).unwrap();
        for table in ["chat_users","chat_sessions","chat_devices","chat_preferences","chat_members"] {
            let column = if table=="chat_users" {"id"} else {"user"};
            assert_eq!(c.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE {column}=?"), [&reader_id], |r| r.get::<_, i64>(0)).unwrap(), 0);
        }
        assert_eq!(c.query_row("SELECT needs_rekey FROM chat_rooms WHERE id=?", [&room], |r| r.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(c.query_row("SELECT COUNT(*) FROM chat_events WHERE sender=?", [&reader_id], |r| r.get::<_, i64>(0)).unwrap(), 1);
        let former = former_users(&c).unwrap();assert_eq!(former[0]["id"],reader_id);assert_eq!(former[0]["devices"][0]["id"],device);assert!(former[0]["devices"][0]["keyPackage"].is_null());
        assert!(!directory(&c).unwrap().as_array().unwrap().iter().any(|u| u["id"]==reader_id));
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
    fn chat_storage_policy_is_owner_only_validated_and_backward_compatible() {
        let (_dir, app, owner, reader, _key, _owner_id, _reader_id) = fixture();
        assert_eq!(run(&app, &reader, json!({"action":"admin.storage"})).unwrap_err().0, StatusCode::FORBIDDEN);
        let policy = json!({"action":"policy","title":"Node","signupUntil":0,"createSpaces":"owner","maxUpload":MAX_CHAT_UPLOAD,"chatQuota":5*1024i64.pow(4)});
        run(&app, &owner, policy.clone()).unwrap();
        let limits = run(&app, &owner, json!({"action":"admin.storage"})).unwrap();
        assert_eq!(limits["quota"], 5*1024i64.pow(4));
        assert_eq!(limits["maxUpload"], MAX_CHAT_UPLOAD);
        let mut invalid = policy.clone(); invalid["maxUpload"] = json!(MAX_CHAT_UPLOAD+1);
        assert!(run(&app, &owner, invalid).is_err());
        let mut invalid = policy.clone(); invalid["chatQuota"] = json!(-1);
        assert!(run(&app, &owner, invalid).is_err());
        run(&app, &owner, json!({"action":"policy","title":"Renamed","signupUntil":0,"createSpaces":"owner"})).unwrap();
        assert_eq!(chat_limits(&db(&app).unwrap()).unwrap(), (MAX_CHAT_UPLOAD,5*1024i64.pow(4)));
    }

    #[test]
    fn chat_storage_counts_pending_reservations_messages_and_catalog() {
        let (_dir, app, owner, _reader, _key, owner_id, _reader_id) = fixture();
        run(&app, &owner, json!({"action":"policy","title":"Node","signupUntil":0,"createSpaces":"owner","chatQuota":100})).unwrap();
        let c = db(&app).unwrap();
        c.execute("INSERT INTO chat_objects VALUES('pending','room',?,60,0,?,0)",params![owner_id,now()]).unwrap();
        c.execute("INSERT INTO chat_events(room,sender,device,id,kind,body,at) VALUES('room',?,'device','event','message','1234567890',?)",params![owner_id,now()]).unwrap();
        c.execute("INSERT INTO chat_node_emoji VALUES('emoji',?,'1234567890','[]')",[owner_id]).unwrap();
        assert_eq!(chat_storage_used(&c).unwrap(),80);
        assert!(reserve_chat(&c,20).is_ok());
        assert_eq!(reserve_chat(&c,21).unwrap_err().0,StatusCode::INSUFFICIENT_STORAGE);
        drop(c);
        run(&app, &owner, json!({"action":"policy","title":"Node","signupUntil":0,"createSpaces":"owner","chatQuota":0})).unwrap();
        assert!(reserve_chat(&db(&app).unwrap(),MAX_CHAT_UPLOAD).is_ok());
    }

    #[tokio::test]
    async fn file_size_and_node_limits_are_enforced_before_upload_reservation() {
        let (_dir, app, owner, _reader, _key, owner_id, _reader_id) = fixture();
        let room=random(24);
        {let c=db(&app).unwrap();c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'','group',?,'cipher',?)",params![room,owner_id,now()]).unwrap();c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",params![room,owner_id]).unwrap();}
        run(&app,&owner,json!({"action":"policy","title":"Node","signupUntil":0,"createSpaces":"owner","maxUpload":1024,"chatQuota":100})).unwrap();
        let error=begin_object(State(app.clone()),owner.clone(),Json(json!({"room":room,"bytes":1053}))).await.unwrap_err();assert!(error.1.contains("maximum upload"));
        let error=begin_object(State(app.clone()),owner,Json(json!({"room":room,"bytes":101}))).await.unwrap_err();assert_eq!(error.0,StatusCode::INSUFFICIENT_STORAGE);
        assert_eq!(db(&app).unwrap().query_row("SELECT COUNT(*) FROM chat_objects",[],|r|r.get::<_,i64>(0)).unwrap(),0);
    }

    #[test]
    fn private_chats_reject_moderation_and_channel_access_changes() {
        let (_dir, app, owner, _reader, _key, owner_id, reader_id) = fixture();
        for kind in ["dm","group"] {
            let room=random(24);let c=db(&app).unwrap();c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,'',?,?,'cipher',?)",params![room,kind,owner_id,now()]).unwrap();
            for user in [&owner_id,&reader_id]{c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",params![room,user]).unwrap();}drop(c);
            assert_eq!(run(&app,&owner,json!({"action":"room.moderate","room":room,"user":reader_id,"banned":true})).unwrap_err().0,StatusCode::FORBIDDEN);
            assert_eq!(run(&app,&owner,json!({"action":"room.access","room":room})).unwrap_err().0,StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn channel_access_updates_atomically_and_preserves_required_members() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let room=random(24);let space=random(24);let stranger=random(24);let encrypted=B64.encode([7u8;64]);
        {let c=db(&app).unwrap();c.execute("INSERT INTO chat_spaces(id,creator,sealed,created) VALUES(?,?,'cipher',?)",params![space,owner_id,now()]).unwrap();c.execute("INSERT INTO chat_rooms(id,space,kind,creator,sealed,created) VALUES(?,?,'text',?,'cipher',?)",params![room,space,owner_id,now()]).unwrap();for id in [&owner_id,&reader_id]{c.execute("INSERT INTO chat_space_members(space,user) VALUES(?,?)",params![space,id]).unwrap();c.execute("INSERT INTO chat_members(room,user,box) VALUES(?,?,'cipher')",params![room,id]).unwrap();}}
        let request=json!({"action":"room.access","room":room,"sealed":encrypted,"members":[{"user":owner_id,"box":encrypted}]});
        assert_eq!(run(&app,&reader,request.clone()).unwrap_err().0,StatusCode::FORBIDDEN);
        let mut invalid=request.clone();invalid["members"]=json!([{"user":owner_id,"box":encrypted},{"user":stranger,"box":encrypted}]);assert!(run(&app,&owner,invalid).is_err());
        let reader_user=user(&app,&reader).unwrap();let owner_user=user(&app,&owner).unwrap();assert!(member(&db(&app).unwrap(),&reader_user,&room).is_ok());
        db(&app).unwrap().execute("UPDATE chat_space_members SET permissions=1 WHERE space=? AND user=?",params![space,reader_id]).unwrap();
        let keep_both=json!({"action":"room.access","room":room,"sealed":encrypted,"members":[{"user":owner_id,"box":encrypted},{"user":reader_id,"box":encrypted}]});
        run(&app,&reader,keep_both.clone()).unwrap();
        let mut rekey=keep_both;rekey["action"]=json!("room.rekey");run(&app,&reader,rekey).unwrap();
        run(&app,&owner,request).unwrap();assert!(member(&db(&app).unwrap(),&reader_user,&room).is_err());
        let c=db(&app).unwrap();assert!(member(&c,&owner_user,&room).is_ok());assert_eq!(c.query_row("SELECT needs_rekey FROM chat_rooms WHERE id=?",[room],|r|r.get::<_,i64>(0)).unwrap(),1);
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
    #[test]
    fn media_identity_revocation_covers_both_clients_without_prefix_collisions() {
        assert!(media_identity_belongs_to("alice:device", "alice"));
        assert!(!media_identity_belongs_to("alice-other:device", "alice"));
        let identity = format!("user_{}_connection", fluxer_user_id("alice"));
        assert!(media_identity_belongs_to(&identity, "alice"));
        assert!(!media_identity_belongs_to(&identity, "bob"));
        assert!(!media_identity_belongs_to(&identity.replacen("_connection", "0_connection", 1), "alice"));
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
        let fluxer = media_token(State(app.clone()), reader.clone(), Json(json!({
            "room":room,"device":device,"client":"fluxer","connection":"test-connection-1234"
        }))).await.unwrap().0;
        let claims: Value = serde_json::from_slice(&B64.decode(fluxer["token"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(claims["video"]["canPublishData"], true);
        assert_eq!(claims["sub"], format!("user_{}_test-connection-1234", fluxer_user_id(&reader_id)));
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
        for item in items.iter().take(2) {
            let bytes = fetch_gif_bytes(&client, item["preview"].as_str().unwrap())
                .await
                .unwrap();
            assert!(bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"));
        }
        let original = fetch_gif_bytes(&client, items[0]["url"].as_str().unwrap())
            .await
            .unwrap();
        assert!(original.len() > 6);
    }
    #[test]
    fn presence_uses_each_tab_and_suppresses_push_when_any_instance_is_active() {
        let (_dir, app, _owner, reader, _key, _owner_id, reader_id) = fixture();
        run(
            &app,
            &reader,
            json!({"action":"presence","instance":"foreground","idle":false}),
        )
        .unwrap();
        run(
            &app,
            &reader,
            json!({"action":"presence","instance":"background","idle":true}),
        )
        .unwrap();
        {
            let c = db(&app).unwrap();
            assert!(active_now(&c, &reader_id).unwrap());
            notify(&c, &reader_id, "message", "none").unwrap();
            assert!(!c
                .query_row(
                    "SELECT push_ok FROM chat_notices ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap());
        }
        run(
            &app,
            &reader,
            json!({"action":"presence","instance":"foreground","idle":true}),
        )
        .unwrap();
        {
            let c = db(&app).unwrap();
            assert!(!active_now(&c, &reader_id).unwrap());
            let entry = directory(&c)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .find(|user| user["id"] == reader_id)
                .unwrap()
                .clone();
            assert_eq!(entry["status"], "idle");
            notify(&c, &reader_id, "message", "none").unwrap();
            assert!(c
                .query_row(
                    "SELECT push_ok FROM chat_notices ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap());
        }
        run(&app, &reader, json!({"action":"logout"})).unwrap();
        assert!(!active_now(&db(&app).unwrap(), &reader_id).unwrap());
    }
    #[test]
    fn friend_requests_create_one_notice_and_muted_rooms_suppress_browser_push() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        for _ in 0..2 {
            run(
                &app,
                &owner,
                json!({"action":"friend","user":reader_id,"kind":"request"}),
            )
            .unwrap();
        }
        let notices = run(&app, &reader, json!({"action":"notices","after":0})).unwrap();
        assert_eq!(
            notices["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|notice| notice["kind"] == "friend.request")
                .count(),
            1
        );
        let room = random(24);
        {
            let c = db(&app).unwrap();
            c.execute("INSERT INTO chat_rooms(id,space,creator,kind,sealed,created) VALUES(?,'',?,'dm','sealed',?)",params![room,owner_id,now()]).unwrap();
            c.execute(
                "INSERT INTO chat_members(room,user,box) VALUES(?,?,'box')",
                params![room, reader_id],
            )
            .unwrap();
        }
        run(
            &app,
            &reader,
            json!({"action":"mute","scope":format!("room:{room}"),"until":now()+3600}),
        )
        .unwrap();
        {
            let c = db(&app).unwrap();
            notify(&c, &reader_id, "message", &room).unwrap();
            assert!(!c
                .query_row(
                    "SELECT push_ok FROM chat_notices ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap());
        }
        assert_eq!(
            run(
                &app,
                &reader,
                json!({"action":"mute","scope":"room:unjoined","until":now()+3600})
            )
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
    }
    fn invite_fixture(app: &App, owner_id: &str, reader_id: &str) -> (String, String, Value) {
        let space = random(24);
        let room = random(24);
        let base = B64.encode([1u8; 64]);
        let c = db(app).unwrap();
        c.execute(
            "INSERT INTO chat_spaces(id,creator,sealed,created) VALUES(?,?,'sealed',?)",
            params![space, owner_id, now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO chat_space_members(space,user,permissions) VALUES(?,?,255)",
            params![space, owner_id],
        )
        .unwrap();
        c.execute(
            "INSERT INTO chat_rooms(id,space,creator,kind,sealed,created) VALUES(?,?,?,'text',?,?)",
            params![room, space, owner_id, base, now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO chat_members(room,user,box) VALUES(?,?,'box')",
            params![room, owner_id],
        )
        .unwrap();
        let body = json!({"rooms":[{"room":room,"creator":owner_id,"base":base,"box":B64.encode([2u8;64]),"sealed":B64.encode([3u8;64])}],"label":B64.encode([4u8;64]),"signature":B64.encode([5u8;64])});
        assert_ne!(reader_id, owner_id);
        (space, room, body)
    }
    #[test]
    fn invitations_require_permission_and_recipient_acceptance_before_sharing_channels() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let (space, room, body) = invite_fixture(&app, &owner_id, &reader_id);
        let id = random(24);
        let request =
            json!({"action":"space.invite","space":space,"id":id,"user":reader_id,"body":body});
        assert_eq!(
            run(&app, &reader, request.clone()).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        run(&app, &owner, request).unwrap();
        assert_eq!(
            run(&app, &reader, json!({"action":"events","room":room}))
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            run(
                &app,
                &owner,
                json!({"action":"space.invite.respond","id":id,"accept":true})
            )
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        run(
            &app,
            &reader,
            json!({"action":"space.invite.respond","id":id,"accept":true}),
        )
        .unwrap();
        assert!(run(&app, &reader, json!({"action":"events","room":room})).is_ok());
        assert_eq!(
            run(
                &app,
                &reader,
                json!({"action":"space.invite.respond","id":id,"accept":true})
            )
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
    }
    #[test]
    fn stale_or_revoked_space_invitations_cannot_overwrite_membership_or_metadata() {
        let (_dir, app, owner, reader, _key, owner_id, reader_id) = fixture();
        let (space, room, body) = invite_fixture(&app, &owner_id, &reader_id);
        let id = random(24);
        run(
            &app,
            &owner,
            json!({"action":"space.invite","space":space,"id":id,"user":reader_id,"body":body}),
        )
        .unwrap();
        {
            let c = db(&app).unwrap();
            c.execute("UPDATE chat_rooms SET sealed='changed' WHERE id=?", [&room])
                .unwrap();
        }
        assert!(run(
            &app,
            &reader,
            json!({"action":"space.invite.respond","id":id,"accept":true})
        )
        .is_err());
        let account = user(&app, &reader).unwrap();
        assert!(member(&db(&app).unwrap(), &account, &room).is_err());
        {
            let c = db(&app).unwrap();
            c.execute(
                "UPDATE chat_rooms SET sealed=? WHERE id=?",
                params![B64.encode([1u8; 64]), room],
            )
            .unwrap();
            c.execute("UPDATE chat_users SET disabled=1 WHERE id=?", [owner_id])
                .unwrap();
        }
        assert!(run(
            &app,
            &reader,
            json!({"action":"space.invite.respond","id":id,"accept":true})
        )
        .is_err());
    }
}
