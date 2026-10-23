//! Communication policies use relationship metadata only, never message content.
use super::*;

pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS chat_privacy(user TEXT PRIMARY KEY,friend INTEGER NOT NULL DEFAULT 7,group_add INTEGER NOT NULL DEFAULT 4,incoming INTEGER NOT NULL DEFAULT 8);")?;
    Ok(())
}
pub(super) fn view(c: &Connection, user: &str) -> Api<Value> {
    Ok(c.query_row("SELECT friend,group_add,incoming FROM chat_privacy WHERE user=?", [user], |r| Ok(json!({"friend_source_flags":r.get::<_,i64>(0)?,"group_dm_add_permission_flags":r.get::<_,i64>(1)?,"incoming_call_flags":r.get::<_,i64>(2)?}))).optional()?.unwrap_or(json!({"friend_source_flags":7,"group_dm_add_permission_flags":4,"incoming_call_flags":8})))
}
pub(super) fn update(c: &mut Connection, user: &str, value: &Value) -> Api<Value> {
    let old = view(c, user)?;
    let read = |key: &str, max: i64| -> Api<i64> {
        let number = if value.get(key).is_some() {
            value[key].as_i64().ok_or(bad("Invalid privacy setting"))?
        } else {
            old[key].as_i64().unwrap_or(0)
        };
        if !(0..=max).contains(&number) {
            return Err(bad("Invalid privacy setting"));
        }
        Ok(number)
    };
    let friend = read("friend_source_flags", 7)?;
    let group = read("group_dm_add_permission_flags", 31)?;
    let incoming = read("incoming_call_flags", 63)?;
    c.execute("INSERT INTO chat_privacy VALUES(?,?,?,?) ON CONFLICT(user) DO UPDATE SET friend=excluded.friend,group_add=excluded.group_add,incoming=excluded.incoming",params![user,friend,group,incoming])?;
    view(c, user)
}
fn mutual_friend(c: &Connection, sender: &str, recipient: &str) -> Api<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends a JOIN chat_friends b ON a.other=b.other WHERE a.user=? AND b.user=? AND a.status='friend' AND b.status='friend' AND EXISTS(SELECT 1 FROM chat_friends ar WHERE ar.user=a.other AND ar.other=a.user AND ar.status='friend') AND EXISTS(SELECT 1 FROM chat_friends br WHERE br.user=b.other AND br.other=b.user AND br.status='friend') AND EXISTS(SELECT 1 FROM chat_users u WHERE u.id=a.other AND u.disabled=0))",params![sender,recipient],|r|r.get(0))?)
}
fn mutual_server(c: &Connection, sender: &str, recipient: &str) -> Api<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM chat_space_members a JOIN chat_space_members b ON a.space=b.space WHERE a.user=? AND b.user=? AND a.banned=0 AND b.banned=0)",params![sender,recipient],|r|r.get(0))?)
}
pub(super) fn allowed(c: &Connection, sender: &str, recipient: &str, kind: &str) -> Api<bool> {
    if sender == recipient {
        return Ok(true);
    }
    if c.query_row("SELECT EXISTS(SELECT 1 FROM chat_friends WHERE ((user=? AND other=?) OR (user=? AND other=?)) AND status='blocked')",params![sender,recipient,recipient,sender],|r|r.get::<_,bool>(0))? {return Ok(false);}
    let flags = view(c, recipient)?[kind].as_i64().unwrap_or(0);
    if kind == "friend_source_flags" {
        return Ok(flags & 4 != 0
            || flags & 1 != 0 && mutual_friend(c, sender, recipient)?
            || flags & 2 != 0 && mutual_server(c, sender, recipient)?);
    }
    if flags & 16 != 0 {
        return Ok(false);
    }
    // Ring suppression is distinct from permission to join an encrypted call.
    if kind == "incoming_call_flags" && flags & 32 != 0 {
        return Ok(false);
    }
    Ok(flags & 4 != 0
        || are_friends(c, sender, recipient)?
        || flags & 1 != 0 && mutual_friend(c, sender, recipient)?
        || flags & 2 != 0 && mutual_server(c, sender, recipient)?)
}
