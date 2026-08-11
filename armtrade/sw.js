/* ArmTrade service worker — R4.
   The app ships a standalone PWA manifest, so a shopkeeper who installs it expects it to OPEN
   without signal. Before this, a relaunch or a tab close in a basement gave a browser error page.

   Strategy:
   - the app shell (one HTML file + the manifest) is precached on install and served
     stale-while-revalidate, so a cold start offline paints the last good build;
   - /api/room/* is NEVER cached — sync must fail honestly, never replay a stale room;
   - anything else falls through to the network untouched.
   Bump CACHE when the shell changes. */
const CACHE = 'armtrade-shell-v4';
const SHELL = ['./', './index.html', './manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.all(SHELL.map(u => c.add(u).catch(() => {}))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (err) { return; }
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf('/api/') === 0) return;   // the room is live data or it is nothing

  const isShell = req.mode === 'navigate' || url.pathname.endsWith('/armtrade/') ||
                  url.pathname.endsWith('/index.html') || url.pathname.endsWith('/manifest.json');
  if (!isShell) return;

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const cached = await cache.match(req, { ignoreSearch: true }) ||
                   await cache.match('./index.html', { ignoreSearch: true });
    const net = fetch(req).then(r => {
      if (r && r.ok) cache.put(req, r.clone()).catch(() => {});
      return r;
    }).catch(() => null);
    // fresh if the network answers quickly, last-known-good otherwise — never an error page
    const fresh = await Promise.race([net, new Promise(r => setTimeout(() => r(null), 2500))]);
    return fresh || cached || net.then(r => r || Response.error());
  })());
});
