//! Portable encrypted archives. This code only concatenates ciphertext and opaque hashes.
use super::*;

pub(super) fn initialize(c: &Connection) -> Result<()> {
    c.execute_batch("CREATE TABLE IF NOT EXISTS encrypted_exports(hash TEXT PRIMARY KEY,session TEXT NOT NULL,owner INTEGER NOT NULL,vault TEXT NOT NULL,revision INTEGER NOT NULL,claim_until INTEGER NOT NULL,deadline INTEGER NOT NULL,claimed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS export_revision ON encrypted_exports(vault,revision);
CREATE TABLE IF NOT EXISTS export_pins(ticket TEXT NOT NULL,vault TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(ticket,vault,revision));
CREATE TRIGGER IF NOT EXISTS delete_export_pins AFTER DELETE ON encrypted_exports BEGIN DELETE FROM export_pins WHERE ticket=old.hash; END;")?;
    Ok(())
}
pub(super) async fn ticket(
    State(a): State<App>,
    ConnectInfo(p): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    RoutePath(id): RoutePath<String>,
    Json(v): Json<Value>,
) -> Api<Json<Value>> {
    let s = session(&a, &h, p)?;
    rate(&a, format!("export:{}", s.owner), 30)?;
    let mut c = db(&a)?;
    let tx = c.transaction()?;
    let (current, _) = owned(&tx, &s, &id)?;
    let rev = v["revision"].as_i64().unwrap_or(current);
    if rev < 1
        || rev > current
        || !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revisions WHERE vault=? AND number=?)",
            params![id, rev],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Err(Fault(
            StatusCode::NOT_FOUND,
            "Encrypted revision unavailable",
        ));
    }
    if rev == 0 {
        return Err(bad("Save this vault first"));
    }
    let token = random(32);
    tx.execute("INSERT INTO encrypted_exports(hash,session,owner,vault,revision,claim_until,deadline) VALUES(?,?,?,?,?,?,?)",params![hash(&token),s.hash,s.owner,id,rev,now()+60,now()+RECEIVE_SECONDS])?;
    tx.execute("INSERT INTO export_pins SELECT ?,vault,number FROM revisions WHERE vault=? AND number<=? ORDER BY number DESC LIMIT 3",params![hash(&token),id,rev])?;
    tx.commit()?;
    Ok(Json(json!({"ticket":token})))
}
struct Pin {
    app: App,
    ticket: String,
}
impl Drop for Pin {
    fn drop(&mut self) {
        if let Ok(c) = self.app.db.lock() {
            let _ = c.execute("DELETE FROM encrypted_exports WHERE hash=?", [&self.ticket]);
        }
    }
}
struct Output {
    app: App,
    ticket: String,
    owner: i64,
    vault: String,
    revision: i64,
    root: Vec<u8>,
    paged: bool,
    phase: u8,
    cursor: String,
    last_number: i64,
    parts: Vec<Part>,
    index: usize,
    offset: u64,
    directory: u64,
    count: u64,
    last_auth: Instant,
}
impl Output {
    fn next_page(&mut self) -> io::Result<()> {
        let c = db(&self.app).map_err(|_| io::Error::other("Storage unavailable"))?;
        self.parts = if self.paged {
            let mut st=c.prepare("SELECT hash,size FROM revision_objects WHERE vault=? AND revision=? AND hash>? ORDER BY hash LIMIT 256").map_err(io::Error::other)?;
            let rows = st
                .query_map(params![self.vault, self.revision, self.cursor], |r| {
                    Ok(Part {
                        hash: r.get(0)?,
                        size: r.get::<_, i64>(1)? as u64,
                    })
                })
                .map_err(io::Error::other)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            rows
        } else {
            let mut st=c.prepare("SELECT number,hash,size FROM revision_parts WHERE vault=? AND revision=? AND number>? ORDER BY number LIMIT 256").map_err(io::Error::other)?;
            let rows = st
                .query_map(params![self.vault, self.revision, self.last_number], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        Part {
                            hash: r.get(1)?,
                            size: r.get::<_, i64>(2)? as u64,
                        },
                    ))
                })
                .map_err(io::Error::other)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            if let Some((n, _)) = rows.last() {
                self.last_number = *n;
            }
            rows.into_iter().map(|(_, p)| p).collect()
        };
        self.index = 0;
        if let Some(p) = self.parts.last() {
            self.cursor = p.hash.clone();
        }
        Ok(())
    }
    fn authorize(&mut self) -> io::Result<()> {
        if self.last_auth.elapsed() < Duration::from_secs(1) {
            return Ok(());
        }
        let c = db(&self.app).map_err(|_| io::Error::other("Storage unavailable"))?;
        let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM encrypted_exports e JOIN sessions s ON s.hash=e.session WHERE e.hash=? AND e.deadline>? AND s.expires>?)",params![self.ticket,now(),now()],|r|r.get(0)).map_err(io::Error::other)?;
        if !live {
            return Err(io::Error::other("Encrypted download authorization expired"));
        }
        self.last_auth = Instant::now();
        Ok(())
    }
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        self.authorize()?;
        loop {
            match self.phase {
                0 => {
                    self.phase = 1;
                    if self.paged {
                        return Ok(Some(Bytes::from(self.root.clone())));
                    }
                }
                1 => {
                    if self.index >= self.parts.len() {
                        self.next_page()?;
                        if self.parts.is_empty() {
                            if !self.paged {
                                self.phase = 4;
                                return Ok(None);
                            }
                            self.phase = 2;
                            self.cursor.clear();
                            self.index = 0;
                            self.offset = self.root.len() as u64;
                            continue;
                        }
                    }
                    let part = self.parts[self.index].clone();
                    self.index += 1;
                    let _permit = self
                        .app
                        .io_slots
                        .acquire()
                        .await
                        .map_err(|_| io::Error::other("Storage busy"))?;
                    let bytes =
                        tokio::fs::read(block_path(&self.app, self.owner, &part.hash)).await?;
                    if bytes.len() as u64 != part.size || hash(&bytes) != part.hash {
                        return Err(io::Error::other("Encrypted archive integrity check failed"));
                    }
                    return Ok(Some(Bytes::from(bytes)));
                }
                2 => {
                    self.next_page()?;
                    if self.parts.is_empty() {
                        self.phase = 3;
                        continue;
                    }
                    let mut bytes = Vec::with_capacity(self.parts.len() * 44);
                    for part in &self.parts {
                        for i in (0..64).step_by(2) {
                            bytes.push(
                                u8::from_str_radix(&part.hash[i..i + 2], 16)
                                    .map_err(io::Error::other)?,
                            );
                        }
                        bytes.extend_from_slice(&self.offset.to_le_bytes());
                        bytes.extend_from_slice(&(part.size as u32).to_le_bytes());
                        self.offset = self
                            .offset
                            .checked_add(part.size)
                            .ok_or_else(|| io::Error::other("Archive too large"))?;
                    }
                    return Ok(Some(Bytes::from(bytes)));
                }
                3 => {
                    self.phase = 4;
                    if self.offset != self.directory {
                        return Err(io::Error::other("Encrypted directory length mismatch"));
                    }
                    let mut bytes = Vec::with_capacity(32);
                    bytes.extend_from_slice(b"VXPGD004");
                    bytes.extend_from_slice(&self.directory.to_le_bytes());
                    bytes.extend_from_slice(&self.count.to_le_bytes());
                    bytes.extend_from_slice(&(self.root.len() as u64).to_le_bytes());
                    return Ok(Some(Bytes::from(bytes)));
                }
                _ => return Ok(None),
            }
        }
    }
}
fn output(
    app: App,
    ticket: &str,
    owner: i64,
    vault: &str,
    revision: i64,
    format: &str,
    root: &str,
    stored: i64,
    count: i64,
) -> Api<Output> {
    let paged = format == "paged";
    let root = if paged {
        B64.decode(root)
            .map_err(|_| bad("Encrypted root is damaged"))?
    } else {
        Vec::new()
    };
    if paged && root.len() < 208 {
        return Err(bad("Encrypted root is damaged"));
    }
    let directory = (root.len() as u64)
        .checked_add(stored as u64)
        .ok_or(bad("Encrypted archive is too large"))?;
    Ok(Output {
        app,
        ticket: ticket.into(),
        owner,
        vault: vault.into(),
        revision,
        root,
        paged,
        phase: 0,
        cursor: String::new(),
        last_number: -1,
        parts: Vec::new(),
        index: 0,
        offset: 0,
        directory,
        count: count as u64,
        last_auth: Instant::now(),
    })
}
struct Archive {
    _pin: Pin,
    outputs: Vec<Output>,
    index: usize,
    trailer: Option<Vec<u8>>,
}
impl Archive {
    async fn next(&mut self) -> io::Result<Option<Bytes>> {
        while self.index < self.outputs.len() {
            if let Some(b) = self.outputs[self.index].next().await? {
                return Ok(Some(b));
            }
            self.index += 1;
        }
        Ok(self.trailer.take().map(Bytes::from))
    }
}
pub(super) async fn download(
    State(a): State<App>,
    RoutePath(token): RoutePath<String>,
) -> Api<Response> {
    if token.len() != 43 {
        return Err(bad("Invalid encrypted download"));
    }
    let digest = hash(token);
    let (owner, id, revision, rows) = {
        let mut c = db(&a)?;
        let tx = c.transaction()?;
        let row:Option<(i64,String,i64)>=tx.query_row("SELECT e.owner,e.vault,e.revision FROM encrypted_exports e JOIN sessions s ON s.hash=e.session WHERE e.hash=? AND e.claim_until>? AND e.claimed=0 AND s.expires>?",params![digest,now(),now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (owner, id, revision) = row.ok_or(Fault(
            StatusCode::UNAUTHORIZED,
            "Encrypted download link expired",
        ))?;
        let mut query=tx.prepare("SELECT r.number,COALESCE(json_extract(r.manifest,'$.format'),''),COALESCE(json_extract(r.manifest,'$.root'),''),r.bytes,(SELECT COUNT(*) FROM revision_objects o WHERE o.vault=r.vault AND o.revision=r.number),COALESCE(json_extract(r.manifest,'$.copies'),2),COALESCE(json_extract(r.manifest,'$.history'),1),r.created FROM revisions r JOIN export_pins p ON p.vault=r.vault AND p.revision=r.number WHERE p.ticket=? ORDER BY r.number DESC")?;
        let rows = query
            .query_map([&digest], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(query);
        tx.execute(
            "UPDATE encrypted_exports SET claimed=1 WHERE hash=?",
            [&digest],
        )?;
        tx.commit()?;
        (owner, id, revision, rows)
    };
    let pin = Pin {
        app: a.clone(),
        ticket: digest.clone(),
    };
    let first = rows.first().ok_or(Fault(
        StatusCode::NOT_FOUND,
        "Encrypted revision unavailable",
    ))?;
    if first.0 != revision {
        return Err(Fault(
            StatusCode::NOT_FOUND,
            "Encrypted revision unavailable",
        ));
    }
    let paged = first.1 == "paged";
    let copies = if paged { first.5.clamp(1, 3) } else { 1 };
    let history = if paged { first.6.clamp(0, 3) } else { 0 };
    let first_root = B64.decode(&first.2).unwrap_or_default();
    let epoch = key_epoch(&first_root);
    let mut outputs = Vec::new();
    let mut entries = Vec::new();
    let mut total = 0u64;
    for (index, row) in rows.iter().enumerate() {
        if index > 0
            && (outputs.len() >= copies as usize + history as usize
                || row.1 != "paged"
                || key_epoch(&B64.decode(&row.2).unwrap_or_default()) != epoch)
        {
            continue;
        }
        let repeats = if index == 0 { copies } else { 1 };
        for copy in 0..repeats {
            let out = output(
                a.clone(),
                &digest,
                owner,
                &id,
                row.0,
                &row.1,
                &row.2,
                row.3,
                row.4,
            )?;
            let size = if out.paged {
                out.directory + out.count * 44 + 32
            } else {
                row.3 as u64
            };
            if paged {
                entries.push(json!({"kind":if index==0{"current"}else{"previous"},"copy":copy+1,"offset":total,"length":size,"savedAtHour":row.7/3600*3600000,"headerLen":192,"headerHash":base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&out.root[..192]))}));
            }
            total = total
                .checked_add(size)
                .ok_or(bad("Encrypted archive is too large"))?;
            outputs.push(out);
        }
    }
    let trailer = if paged {
        let value = json!({"v":1,"savedAtHour":first.7/3600*3600000,"settings":{"currentCopies":copies,"previousVersions":history},"entries":entries});
        let bytes = value.to_string().into_bytes();
        let mut footer = [0u8; 64];
        footer[..8].copy_from_slice(b"VVRS2201");
        footer[8..12].copy_from_slice(&1u32.to_le_bytes());
        footer[12..16].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        footer[16..48].copy_from_slice(&Sha256::digest(&bytes));
        footer[48..52].copy_from_slice(&64u32.to_le_bytes());
        footer[56..64].copy_from_slice(b"ENDVVRS!");
        let mut trailer = Vec::new();
        for _ in 0..3 {
            trailer.extend_from_slice(&bytes);
            trailer.extend_from_slice(&footer);
        }
        total += trailer.len() as u64;
        Some(trailer)
    } else {
        None
    };
    let archive = Archive {
        _pin: pin,
        outputs,
        index: 0,
        trailer,
    };
    let stream = futures_util::stream::try_unfold(archive, |mut archive| async move {
        match archive.next().await? {
            Some(bytes) => Ok::<_, io::Error>(Some((bytes, archive))),
            None => Ok(None),
        }
    });
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"Vortex.vault\""),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&total.to_string())
            .map_err(|_| bad("Encrypted archive is too large"))?,
    );
    Ok(response)
}
