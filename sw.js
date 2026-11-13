/* JB KU service worker: halaman dari internet dulu, cadangan dari cache saat offline */
const CACHE = "jbku-v1";
const CORE = ["/", "/manifest.webmanifest", "/icon-192.png", "/icon-512.png"];
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const r = e.request;
  if (r.method !== "GET") return;
  const u = new URL(r.url);
  if (u.origin !== location.origin) return; // Supabase, font, dll. tidak disentuh
  if (r.mode === "navigate") {
    e.respondWith(
      fetch(r).then(res => { const cp = res.clone(); caches.open(CACHE).then(c => c.put("/", cp)); return res; })
        .catch(() => caches.match("/").then(m => m || new Response("<h1>Offline</h1><p>Sambungkan internet lalu buka lagi JB KU.</p>", { headers: { "Content-Type": "text/html; charset=utf-8" } })))
    );
    return;
  }
  e.respondWith(caches.match(r).then(m => m || fetch(r).then(res => { if (res.ok) { const cp = res.clone(); caches.open(CACHE).then(c => c.put(r, cp)); } return res; })));
});
/* ketuk notifikasi = buka JB KU */
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(ws => {
    for (const w of ws) if ("focus" in w) return w.focus();
    return self.clients.openWindow("/");
  }));
});
