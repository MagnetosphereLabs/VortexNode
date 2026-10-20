/* Recovery and portable-file adapters for the paged format. */
window.VortexPagedRecovery = (() => {
  "use strict";
  const W = VortexWire,
    P = VortexStorePrimitives,
    CH = P.CH,
    N = VortexNode.state;
  const contexts = new WeakMap();
  function store(loaded) {
    let v = contexts.get(loaded);
    if (!v) {
      const source =
        loaded.blob.vortexSource || new VortexPaged.PackedSource(loaded.blob);
      v = new VortexPaged.Vault(loaded.index, state.v2.key, source);
      contexts.set(loaded, v);
    }
    return v;
  }
  async function item(loaded, id) {
    return store(loaded).item(id);
  }
  async function* plain(loaded, it) {
    yield* store(loaded).reader(it).stream();
  }
  async function bytes(loaded, it) {
    if (it.size > 128 * 1024 ** 2)
      throw Error(
        "Use Restore file or streaming Download version for this large file",
      );
    const out = new Uint8Array(it.size);
    let at = 0;
    for await (const b of plain(loaded, it)) {
      out.set(b, at);
      at += b.length;
    }
    return out;
  }
  async function history() {
    const v = VortexPaged.state.vault;
    if (!v || !N.pair) return;
    const data = await VortexNode.api(
      "/vault/" + N.remote + "/history",
      undefined,
      "GET",
    );
    v.live();
    if (VortexPaged.state.vault !== v) return;
    const rows = data.revisions.filter((r) => r.epoch === v.root.epoch),
      current = rows.find((r) => r.revision === N.revision);
    if (!current) return;
    const cfg = resilienceSettings(),
      entries = [];
    for (let n = 0; n < cfg.currentCopies; n++)
      entries.push({
        kind: "current",
        copy: n + 1,
        nodeDescriptor: current,
        savedAtHour: Math.floor(current.created / 3600) * 3600000,
      });
    for (const r of rows
      .filter((r) => r.revision < N.revision)
      .slice(0, cfg.previousVersions))
      entries.push({
        kind: "previous",
        copy: 1,
        nodeDescriptor: r,
        savedAtHour: Math.floor(r.created / 3600) * 3600000,
      });
    state.resilience.manifest = { v: 1, settings: cfg, entries };
  }
  async function downloadRevision(descriptor) {
    const result = await VortexNode.api("/vault/" + N.remote + "/export", {
        revision: descriptor.revision,
      }),
      a = document.createElement("a");
    a.href = N.pair.url + "/download/" + result.ticket;
    a.referrerPolicy = "no-referrer";
    a.click();
  }
  async function restore(loaded, old, id) {
    const current = getItemById(id);
    if (
      !current ||
      !confirm("Restore the previous contents of “" + current.name + "”?")
    )
      return;
    const next = {
      ...old,
      id,
      folderId: current.folderId,
      updated: Date.now(),
    };
    await VortexPaged.state.vault.encrypt(next, plain(loaded, old));
    Object.assign(current, next);
    state.v2.pendingRecords.delete(id);
    state.v2.pendingText.delete(id);
    state.dirty = true;
    closeOverlay("ovVersions");
    render();
    toast("Previous file version restored");
  }
  async function preview(loaded, it, stage) {
    const card = document.createElement("div");
    card.className = "previewCard";
    const title = document.createElement("div");
    title.className = "metaRow";
    title.textContent = "Previous version · " + it.name;
    const box = document.createElement("div");
    box.className = "previewMedia";
    let video;
    if (it.kind === "video") {
      video = document.createElement("video");
      video.controls = true;
      box.append(video);
    } else {
      const hint = document.createElement("div");
      hint.className = "hintBox";
      hint.textContent = "Download this version to open the full file.";
      box.append(hint);
    }
    const actions = document.createElement("div");
    actions.className = "previewTools";
    const download = document.createElement("button");
    download.className = "btn";
    download.textContent = "Download version";
    download.onclick = async () => {
      try {
        async function* owned() {
          for await (const b of plain(loaded, it)) yield b.slice();
        }
        await VortexNode.output(W.stream(owned()), it.name, it.size);
      } catch (e) {
        toast(e.message, true);
      }
    };
    actions.append(download);
    card.append(title, box, actions);
    stage.replaceChildren(card);
    if (video) await VortexMedia.attach(video, it, store(loaded));
  }
  async function catalog() {
    const name = "VortexOpaqueExport-" + W.b64(W.random(12)),
      db = await new Promise((ok, no) => {
        const r = indexedDB.open(name, 1);
        r.onupgradeneeded = () =>
          r.result.createObjectStore("objects", { keyPath: "hash" });
        r.onsuccess = () => ok(r.result);
        r.onerror = () => no(r.error);
      });
    const write = (rows) =>
      new Promise((ok, no) => {
        const tx = db.transaction("objects", "readwrite"),
          s = tx.objectStore("objects");
        for (const row of rows) s.put(row);
        tx.oncomplete = ok;
        tx.onerror = () => no(tx.error);
      });
    const page = (after) =>
      new Promise((ok, no) => {
        const tx = db.transaction("objects"),
          rows = [],
          r = tx
            .objectStore("objects")
            .openCursor(
              after ? IDBKeyRange.lowerBound(after, true) : undefined,
            );
        r.onsuccess = () => {
          const c = r.result;
          if (!c || rows.length >= 256) return;
          c && rows.push(c.value);
          c.continue();
        };
        r.onerror = () => no(r.error);
        tx.oncomplete = () => ok(rows);
        tx.onerror = () => no(tx.error);
      });
    return {
      write,
      page,
      close() {
        db.close();
        indexedDB.deleteDatabase(name);
      },
    };
  }
  async function localExport(logout = false) {
    const v = VortexPaged.state.vault;
    if (!v) throw Error("Unlock a vault first");
    let handle;
    if (window.showSaveFilePicker)
      handle = await showSaveFilePicker({
        suggestedName: timestampedVaultName(state.fileName || "vortex.vault"),
      });
    await encryptPendingTextRecordsNow();
    return v.exclusive(async () => {
      const version = N.generation;
      await VortexPaged.flushWindow();
      const logical = await v.prepareRoot(),
        index = await v.sealIndex(logical),
        { iv, cipher } = await v2EncryptIndex(v.key, index),
        s = state.v2,
        header = v3WriteHeader({
          cipherSuite: 2,
          cascadeCount: s.cascadeCount,
          kdfIter: s.kdfIter,
          vaultId: s.vaultId,
          cascadeSalts: s.cascadeSalts,
          indexLen: cipher.length,
          indexIv: iv,
        }),
        root = new Uint8Array(header.length + cipher.length);
      root.set(header);
      root.set(cipher, header.length);
      const directory = await catalog();
      let writer,
        temporary,
        count = 0,
        total = 0;
      try {
        let batch = [];
        for await (const ref of v.references()) {
          batch.push(ref);
          if (batch.length === 256) {
            await directory.write(batch);
            batch = [];
          }
        }
        if (batch.length) await directory.write(batch);
        let after = "";
        for (;;) {
          const rows = await directory.page(after);
          if (!rows.length) break;
          for (const row of rows) {
            total += row.size;
            count++;
          }
          after = rows.at(-1).hash;
        }
        const size = root.length + total + count * 44 + 32,
          cfg = resilienceSettings(),
          previous = resiliencePreviousEntries()
            .map(resilienceEntryBlob)
            .filter(Boolean)
            .slice(0, cfg.previousVersions),
          prior = resiliencePriorBaseForHistory();
        if (prior && cfg.previousVersions) previous.unshift(prior);
        previous.splice(cfg.previousVersions);
        const entries = [];
        let offset = 0;
        const hour = Math.floor(Date.now() / 3600000) * 3600000;
        for (let n = 0; n < cfg.currentCopies; n++) {
          entries.push({
            kind: "current",
            copy: n + 1,
            offset,
            length: size,
            savedAtHour: hour,
            headerLen: 192,
            headerHash: bytesToB64(await sha256Bytes(header)),
          });
          offset += size;
        }
        for (let n = 0; n < previous.length; n++) {
          entries.push({
            kind: "previous",
            copy: n + 1,
            offset,
            length: previous[n].size,
            savedAtHour: 0,
          });
          offset += previous[n].size;
        }
        const manifest = { v: 1, savedAtHour: hour, settings: cfg, entries },
          manifestBytes = W.encode(JSON.stringify(manifest)),
          footer = await resilienceBuildFooter(manifestBytes);
        const outputSize = offset + (manifestBytes.length + footer.length) * 3;
        if (handle) writer = await handle.createWritable();
        else {
          const estimate = await navigator.storage.estimate();
          if (estimate.quota - estimate.usage < outputSize * 1.02)
            throw Error(
              "This browser needs more local storage to save this encrypted archive. Use a browser with a native file picker.",
            );
          const dir = await navigator.storage.getDirectory();
          temporary = await dir.getFileHandle(
            "vortex-export-" + W.b64(W.random(12)) + ".vault",
            { create: true },
          );
          writer = await temporary.createWritable();
        }
        const pack = async () => {
          await writer.write(root);
          let cursor = "",
            at = root.length;
          for (;;) {
            const rows = await directory.page(cursor);
            if (!rows.length) break;
            for (const row of rows) {
              v.live();
              const cipher = await v.read(row.hash);
              if (
                cipher.length !== row.size ||
                (await W.sha(cipher)) !== row.hash
              )
                throw Error("Encrypted archive integrity check failed");
              await writer.write(cipher);
              row.offset = at;
              at += row.size;
            }
            await directory.write(rows);
            cursor = rows.at(-1).hash;
          }
          cursor = "";
          for (;;) {
            const rows = await directory.page(cursor);
            if (!rows.length) break;
            const bytes = new Uint8Array(rows.length * 44),
              view = new DataView(bytes.buffer);
            rows.forEach((r, n) => {
              bytes.set(
                Uint8Array.from(r.hash.match(/../g), (x) => parseInt(x, 16)),
                n * 44,
              );
              view.setBigUint64(n * 44 + 32, BigInt(r.offset), true);
              view.setUint32(n * 44 + 40, r.size, true);
            });
            await writer.write(bytes);
            cursor = rows.at(-1).hash;
          }
          const tail = new Uint8Array(32),
            view = new DataView(tail.buffer);
          tail.set(W.encode("VXPGD004"));
          view.setBigUint64(8, BigInt(root.length + total), true);
          view.setBigUint64(16, BigInt(count), true);
          view.setBigUint64(24, BigInt(root.length), true);
          await writer.write(tail);
        };
        for (let n = 0; n < cfg.currentCopies; n++) await pack();
        for (const file of previous)
          for (let at = 0; at < file.size; at += CH)
            await writer.write(
              new Uint8Array(
                await file
                  .slice(at, Math.min(file.size, at + CH))
                  .arrayBuffer(),
              ),
            );
        for (let n = 0; n < 3; n++) {
          await writer.write(manifestBytes);
          await writer.write(footer);
        }
        await writer.close();
        writer = null;
        const file = await (handle || temporary).getFile();
        state.resilience.sourceFile = file;
        state.resilience.manifest = manifest;
        state.resilience.activeBaseBlob = file.slice(0, size);
        state.resilience.recoveredRecords = new Set();
        state.v2.index.paged = index.paged;
        state.dirty = N.generation !== version;
        if (!handle) {
          const url = URL.createObjectURL(file),
            a = document.createElement("a");
          a.href = url;
          a.download = timestampedVaultName(state.fileName || "vortex.vault");
          a.click();
          setTimeout(() => URL.revokeObjectURL(url), 60000);
        }
        if (logout) hardLogout(false);
        toast("Encrypted vault downloaded");
      } catch (e) {
        try {
          await writer?.abort();
        } catch {}
        throw e;
      } finally {
        directory.close();
      }
    });
  }
  return {
    store,
    item,
    plain,
    bytes,
    history,
    downloadRevision,
    restore,
    preview,
    localExport,
  };
})();
