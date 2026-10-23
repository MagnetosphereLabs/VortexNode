//! Account credentials remain separate from conversation keys. WebAuthn stores
//! public credentials and PRF-encrypted root bundles; the PRF output stays local.
use super::*;
use webauthn_rs::prelude::*;

pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS chat_passkeys(id TEXT PRIMARY KEY,user TEXT NOT NULL,name TEXT NOT NULL,credential TEXT NOT NULL,wrapped TEXT NOT NULL,salt TEXT NOT NULL,created INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS chat_passkey_user ON chat_passkeys(user);
        CREATE TABLE IF NOT EXISTS chat_security_pending(id TEXT PRIMARY KEY,user TEXT NOT NULL,session TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL,expires INTEGER NOT NULL,ip TEXT NOT NULL);")?;
    Ok(())
}
fn fresh_proof(c: &Connection, u: &User, value: &Value) -> Api<()> {
    let proof = hash(text(value, "proof"));
    if proof == u.session {
        return Err(denied());
    }
    let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM chat_sessions WHERE hash=?1 AND user=?2 AND created>?3 AND expires>?4) OR EXISTS(SELECT 1 FROM sessions s JOIN chat_users u ON u.node_owner=s.owner WHERE s.hash=?1 AND u.id=?2 AND s.created>?3 AND s.expires>?4)",params![proof,u.id,now()-300,now()],|r|r.get(0))?;
    if !valid {
        return Err(Fault(
            StatusCode::UNAUTHORIZED,
            "Confirm your current password and authenticator code",
        ));
    }
    Ok(())
}
fn webauthn(a: &App) -> Api<Webauthn> {
    let origin = Url::parse(
        a.cfg
            .public_url
            .as_deref()
            .ok_or(bad("Passkeys require a configured Node HTTPS address"))?,
    )
    .map_err(|_| bad("Invalid Node address"))?;
    let host = origin.host_str().ok_or(bad("Invalid Node address"))?;
    if origin.scheme() != "https"
        && !(origin.scheme() == "http" && ["localhost", "127.0.0.1", "[::1]"].contains(&host))
    {
        return Err(bad("Passkeys require HTTPS"));
    }
    WebauthnBuilder::new(host, &origin)
        .map_err(|_| bad("Invalid passkey origin"))?
        .rp_name("Vortex Chat")
        .build()
        .map_err(|_| bad("Passkeys could not be initialized"))
}
fn credentials(c: &Connection, id: &str) -> Api<Vec<Passkey>> {
    let mut q = c.prepare("SELECT credential FROM chat_passkeys WHERE user=? LIMIT 20")?;
    let rows = q
        .query_map([id], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| serde_json::from_str(&row).map_err(|_| bad("Stored passkey is invalid")))
        .collect()
}
fn pending(
    c: &Connection,
    user: &str,
    session: &str,
    kind: &str,
    state: Value,
    addr: &str,
) -> Api<String> {
    c.execute("DELETE FROM chat_security_pending WHERE expires<?", [now()])?;
    let count: i64 = c.query_row(
        "SELECT COUNT(*) FROM chat_security_pending WHERE user=? AND kind=?",
        params![user, kind],
        |r| r.get(0),
    )?;
    if count >= 20 {
        return Err(Fault(
            StatusCode::TOO_MANY_REQUESTS,
            "Wait before starting another credential request",
        ));
    }
    let id = random(24);
    c.execute(
        "INSERT INTO chat_security_pending VALUES(?,?,?,?,?,?,?)",
        params![
            id,
            user,
            session,
            kind,
            state.to_string(),
            now() + 120,
            addr
        ],
    )?;
    Ok(id)
}
fn take(c: &mut Connection, id: &str, kind: &str, addr: &str) -> Api<(String, String, Value)> {
    let tx = c.transaction()?;
    let row:(String,String,String)=tx.query_row("SELECT user,session,state FROM chat_security_pending WHERE id=? AND kind=? AND expires>? AND ip=?",params![id,kind,now(),addr],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or(denied())?;
    tx.execute("DELETE FROM chat_security_pending WHERE id=?", [id])?;
    tx.commit()?;
    Ok((
        row.0,
        row.1,
        serde_json::from_str(&row.2).map_err(|_| bad("Invalid authentication state"))?,
    ))
}
pub(super) fn handles(op: &str) -> bool {
    op.starts_with("auth.passkey.") || op.starts_with("passkey.") || op.starts_with("password.")
}
pub(super) fn dispatch(a: &App, h: &HeaderMap, addr: &str, v: &Value) -> Api<Value> {
    let op = text(v, "action");
    let authenticated = if op.starts_with("auth.") {
        None
    } else {
        Some(user(a, h)?)
    };
    let mut c = db(a)?;
    if op == "auth.passkey.start" {
        let username = normalize_name(&text(v, "username"));
        let id: String = c
            .query_row(
                "SELECT id FROM chat_users WHERE username=? AND disabled=0",
                [username],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(denied())?;
        let keys = credentials(&c, &id)?;
        if keys.is_empty() {
            return Err(bad(
                "Use your password to sign in and add a passkey in account security",
            ));
        }
        let (options, state) = webauthn(a)?
            .start_passkey_authentication(&keys)
            .map_err(|_| denied())?;
        let challenge = pending(
            &c,
            &id,
            "",
            "login",
            serde_json::to_value(state).map_err(|_| bad("Invalid passkey state"))?,
            addr,
        )?;
        let mut salts = serde_json::Map::new();
        let mut q = c.prepare("SELECT id,salt FROM chat_passkeys WHERE user=?")?;
        for row in q.query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })? {
            let (id, salt) = row?;
            salts.insert(id, json!(salt));
        }
        return Ok(json!({"id":challenge,"options":options,"salts":salts}));
    }
    if op == "auth.passkey.finish" {
        let (id, _, state) = take(&mut c, &text(v, "id"), "login", addr)?;
        let state: PasskeyAuthentication = serde_json::from_value(state).map_err(|_| denied())?;
        let credential: PublicKeyCredential = serde_json::from_value(v["credential"].clone())
            .map_err(|_| bad("Invalid passkey response"))?;
        let result = webauthn(a)?
            .finish_passkey_authentication(&credential, &state)
            .map_err(|_| denied())?;
        if !result.user_verified() {
            return Err(denied());
        }
        let credential_id = serial(result.cred_id());
        let (raw, wrapped, salt): (String, String, String) = c
            .query_row(
                "SELECT credential,wrapped,salt FROM chat_passkeys WHERE user=? AND id=?",
                params![id, credential_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(denied())?;
        let mut key: Passkey = serde_json::from_str(&raw).map_err(|_| denied())?;
        key.update_credential(&result).ok_or(denied())?;
        let (owner, username, identity): (Option<i64>, String, String) = c
            .query_row(
                "SELECT node_owner,username,identity FROM chat_users WHERE id=? AND disabled=0",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(denied())?;
        let token = random(32);
        let months = v["months"].as_u64().unwrap_or(12).clamp(1, 12);
        let expires = Utc::now()
            .checked_add_months(Months::new(months as u32))
            .ok_or(bad("Clock unavailable"))?
            .timestamp();
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE chat_passkeys SET credential=?,used=? WHERE id=? AND user=?",
            params![
                serde_json::to_string(&key).map_err(|_| denied())?,
                now(),
                credential_id,
                id
            ],
        )?;
        if let Some(owner) = owner {
            tx.execute(
                "INSERT INTO sessions VALUES(?,?,?,?,?)",
                params![hash(&token), owner, expires, now(), text(v, "device")],
            )?;
        } else {
            tx.execute(
                "INSERT INTO chat_sessions VALUES(?,?,?,?,?)",
                params![hash(&token), id, text(v, "device"), expires, now()],
            )?;
        }
        notify(&tx, &id, "login", "")?;
        tx.commit()?;
        return Ok(
            json!({"token":token,"id":id,"username":username,"owner":owner.is_some(),"expires":expires,"months":months,"identity":serde_json::from_str::<Value>(&identity).map_err(|_|denied())?,"wrapped":wrapped,"salt":salt}),
        );
    }
    let u = authenticated.ok_or_else(denied)?;
    match op.as_str() {
        "passkey.list" => {
            let mut q = c.prepare(
                "SELECT id,name,created,used FROM chat_passkeys WHERE user=? ORDER BY created",
            )?;
            let keys=q.query_map([u.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"created":r.get::<_,i64>(2)?,"used":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
            Ok(json!({"keys":keys}))
        }
        "passkey.start" => {
            fresh_proof(&c, &u, v)?;
            let keys = credentials(&c, &u.id)?;
            if keys.len() >= 20 {
                return Err(bad("Remove a passkey before adding another"));
            }
            let name: String =
                c.query_row("SELECT username FROM chat_users WHERE id=?", [&u.id], |r| {
                    r.get(0)
                })?;
            let uuid =
                Uuid::from_slice(&Sha256::digest(u.id.as_bytes())[..16]).map_err(|_| denied())?;
            let (options, state) = webauthn(a)?
                .start_passkey_registration(
                    uuid,
                    &name,
                    &name,
                    Some(keys.iter().map(|key| key.cred_id().clone()).collect()),
                )
                .map_err(|_| bad("Could not start passkey registration"))?;
            let id = pending(
                &c,
                &u.id,
                &u.session,
                "register",
                serde_json::to_value(state).map_err(|_| denied())?,
                addr,
            )?;
            Ok(json!({"id":id,"options":options}))
        }
        "passkey.finish" => {
            fresh_proof(&c, &u, v)?;
            let (id, session, state) = take(&mut c, &text(v, "id"), "register", addr)?;
            if id != u.id || session != u.session {
                return Err(denied());
            }
            let state: PasskeyRegistration = serde_json::from_value(state).map_err(|_| denied())?;
            let response: RegisterPublicKeyCredential =
                serde_json::from_value(v["credential"].clone())
                    .map_err(|_| bad("Invalid passkey response"))?;
            let key = webauthn(a)?
                .finish_passkey_registration(&response, &state)
                .map_err(|_| bad("Passkey could not be verified"))?;
            let wrapped = ciphertext(v, "wrapped", 16 * 1024)?;
            if decode(v, "salt", 64)?.len() != 32 {
                return Err(bad("Invalid passkey encryption salt"));
            }
            let name = text(v, "name");
            if !bounded(&name, 1, 80) {
                return Err(bad("Choose a passkey name"));
            }
            c.execute("INSERT INTO chat_passkeys(id,user,name,credential,wrapped,salt,created) VALUES(?,?,?,?,?,?,?)",params![serial(key.cred_id()),u.id,name,serde_json::to_string(&key).map_err(|_|denied())?,wrapped,text(v,"salt"),now()])?;
            Ok(json!({"ok":true}))
        }
        "passkey.delete" => {
            fresh_proof(&c, &u, v)?;
            c.execute(
                "DELETE FROM chat_passkeys WHERE id=? AND user=?",
                params![text(v, "id"), u.id],
            )?;
            Ok(json!({"ok":true}))
        }
        "password.start" => {
            fresh_proof(&c, &u, v)?;
            let username: String =
                c.query_row("SELECT username FROM chat_users WHERE id=?", [&u.id], |r| {
                    r.get(0)
                })?;
            let response = ServerRegistration::<Suite>::start(
                &setup(&c)?,
                RegistrationRequest::deserialize(&decode(v, "request", 4096)?)
                    .map_err(|_| bad("Invalid password registration"))?,
                username.as_bytes(),
            )
            .map_err(|_| bad("Could not start password change"))?;
            let current: String = c.query_row(
                "SELECT registration FROM chat_users WHERE id=?",
                [&u.id],
                |r| r.get(0),
            )?;
            let id = pending(
                &c,
                &u.id,
                &u.session,
                "password",
                json!({"version":hash(current)}),
                addr,
            )?;
            Ok(json!({"id":id,"response":serial(response.message.serialize())}))
        }
        "password.finish" => {
            fresh_proof(&c, &u, v)?;
            let (id, session, state) = take(&mut c, &text(v, "id"), "password", addr)?;
            if id != u.id || session != u.session {
                return Err(denied());
            }
            let registration = ServerRegistration::<Suite>::finish(
                RegistrationUpload::deserialize(&decode(v, "record", 8192)?)
                    .map_err(|_| bad("Invalid password registration"))?,
            );
            let bundle = ciphertext(v, "bundle", 1024 * 1024)?;
            let tx = c.transaction()?;
            let current: String = tx.query_row(
                "SELECT registration FROM chat_users WHERE id=?",
                [&u.id],
                |r| r.get(0),
            )?;
            if hash(current) != text(&state, "version") {
                return Err(conflict());
            }
            tx.execute(
                "UPDATE chat_users SET registration=?,bundle=? WHERE id=?",
                params![serial(registration.serialize()), bundle, u.id],
            )?;
            tx.execute(
                "DELETE FROM chat_sessions WHERE user=? AND hash!=?",
                params![u.id, u.session],
            )?;
            tx.execute("DELETE FROM sessions WHERE owner=(SELECT node_owner FROM chat_users WHERE id=?) AND hash!=?",params![u.id,u.session])?;
            tx.execute("DELETE FROM chat_security_pending WHERE user=?", [u.id])?;
            tx.commit()?;
            Ok(json!({"ok":true}))
        }
        _ => Err(bad("Unknown credential operation")),
    }
}
