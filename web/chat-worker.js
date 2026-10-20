"use strict";
// This worker never receives message bodies or decryption keys.
const DB = "VortexChatNotifications";
function config(value) {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore("config");
    r.onerror = () => reject(r.error);
    r.onsuccess = () => {
      const d = r.result,
        t = d.transaction("config", value ? "readwrite" : "readonly"),
        s = t.objectStore("config");
      let v;
      if (value) s.put(value, "current");
      else {
        const q = s.get("current");
        q.onsuccess = () => (v = q.result);
      }
      t.oncomplete = () => {
        d.close();
        resolve(v);
      };
      t.onerror = () => reject(t.error);
    };
  });
}
self.addEventListener("message", (e) => {
  if (e.data?.type === "configure") e.waitUntil(config(e.data.value));
  if (e.data?.type === "clear") e.waitUntil(config({}));
});
self.addEventListener("push", (e) =>
  e.waitUntil(
    (async () => {
      const c = await config();
      if (!c?.token) return;
      const r = await fetch("/chat/action", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + c.token,
        },
        body: JSON.stringify({ action: "notices", after: c.cursor || 0 }),
      });
      if (!r.ok) return;
      const { notices } = await r.json();
      if (!notices?.length) return;
      const n = notices.at(-1);
      await config({ ...c, cursor: n.id });
      const title =
        n.kind === "call"
          ? "Incoming call"
          : n.kind === "login"
            ? "New login on your account"
            : "New message";
      await self.registration.showNotification(title, {
        body: "Vortex Chat",
        icon: "/chat/icon.svg",
        badge: "/chat/icon.svg",
        tag: n.kind === "call" ? "vortex-call" : "vortex-activity",
        data: { room: n.room },
        renotify: true,
      });
    })(),
  ),
);
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(
    (async () => {
      const all = await clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });
      const existing = all.find((c) =>
        new URL(c.url).pathname.startsWith("/chat"),
      );
      if (existing) {
        existing.postMessage({
          type: "open-room",
          room: e.notification.data?.room,
        });
        await existing.focus();
      } else await clients.openWindow("/chat/");
    })(),
  );
});
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

const pending = new Map();
self.addEventListener("install", (event) =>
  event.waitUntil(self.skipWaiting()),
);
self.addEventListener("activate", (event) =>
  event.waitUntil(self.clients.claim()),
);
self.addEventListener("message", (event) => {
  const { begin, name, size } = event.data || {},
    port = event.ports[0];
  if (
    !port ||
    typeof begin !== "string" ||
    !/^[A-Za-z0-9_-]{32}$/.test(begin) ||
    typeof name !== "string" ||
    name.length > 4096 ||
    !Number.isSafeInteger(size) ||
    size < 0
  )
    return;
  if (pending.size >= 8) {
    port.postMessage({ error: "Finish a download before starting another." });
    port.close();
    return;
  }
  const clean = name.replace(/[\x00-\x1f\x7f\"\\/]/g, "_"),
    dot = clean.lastIndexOf("."),
    suffix = dot > 0 && clean.length - dot <= 16 ? clean.slice(dot) : "",
    short =
      clean.length > 200 ? clean.slice(0, 200 - suffix.length) + suffix : clean;
  const timer = setTimeout(() => {
    pending.delete(begin);
    port.postMessage({
      error:
        "Your browser did not start the download. Allow downloads and retry.",
    });
    port.close();
  }, 60000);
  pending.set(begin, { port, name: short, size, timer });
  port.postMessage({ ready: true });
});
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (
    url.origin !== self.location.origin ||
    !url.pathname.startsWith("/chat/download/")
  )
    return;
  const id = url.pathname.slice("/chat/download/".length),
    p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  clearTimeout(p.timer);
  let waiting = false,
    controller;
  const stream = new ReadableStream(
    {
      start(c) {
        controller = c;
        p.port.onmessage = (e) => {
          waiting = false;
          if (e.data?.bytes instanceof ArrayBuffer)
            c.enqueue(new Uint8Array(e.data.bytes));
          else if (e.data?.done) {
            c.close();
            p.port.postMessage({ complete: true });
            p.port.close();
          } else {
            c.error(Error("Download interrupted"));
            p.port.close();
          }
        };
      },
      pull() {
        if (!waiting) {
          waiting = true;
          p.port.postMessage({ pull: true });
        }
      },
      cancel() {
        p.port.postMessage({ cancel: true });
        p.port.close();
      },
    },
    { highWaterMark: 0 },
  );
  const headers = {
    "Content-Type": "application/octet-stream",
    "Content-Disposition": `attachment; filename="${p.name.replace(/[^\x20-\x7e]/g, "_")}"; filename*=UTF-8''${encodeURIComponent(p.name).replace(/['()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase())}`,
    "Content-Length": String(p.size),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  event.respondWith(new Response(stream, { headers }));
});
