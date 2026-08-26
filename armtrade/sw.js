/* ArmTrade service worker — R4.
   The app ships a standalone PWA manifest, so a shopkeeper who installs it expects it to OPEN
   without signal. Before this, a relaunch or a tab close in a basement gave a browser error page.

   Strategy:
   - the app shell (one HTML file + the manifest) is precached on install and served
     stale-while-revalidate, so a cold start offline paints the last good build;
   - /api/room/* is NEVER cached — sync must fail honestly, never replay a stale room;
   - anything else falls through to the network untouched.
   Bump CACHE when the shell changes. */
const CACHE = 'armtrade-shell-v27';
   /* v27: apple-design polish on the glass layer. touch-action removes the tap-recognition
      delay before :active can paint; controls on #top/#nav no longer stack translucency on
      translucency; nav labels gain vibrancy weight; the modal scrim's blur builds and unwinds
      instead of snapping; a soft scroll edge replaces the hard collision under the chrome; and
      prefers-contrast is answered. A cached v26 shell would keep the compounded translucency. */
  
   /* v26: the glass touch layer. Buttons, chips, the header, the bottom nav, the toast and
      the sheet are translucent, rounded and tinted in the product's own hue; reading surfaces are
      untouched. A cached v25 shell would paint the old flat Ledger controls beside the new ones
      on the hub and the other two apps, which is the one thing a shared house style cannot survive. */
  
   /* v25: motion pass against Emil Kowalski's emil-design-eng skill. The full-screen fade
      on every tab switch is gone (the most repeated action in the app must not animate), sheets
      now leave on a 160ms exit instead of vanishing, the toast exits faster than it enters, the
      1.6s and 0.9s attention flashes are cut to 260ms, and the progress bar no longer promises a
      transition on `width`. A cached v24 shell would keep fading the screen on every nav tap. */
     /* round H: the demo's deterministic ids are content-addressed, so two paired demo phones can no longer hand one uuid to two different ledger rows, and a merge that rewrites a surviving row now throws; the Cyrillic face is no longer precached for an Armenian-only user; an incomplete shell no longer counts as installed; round G: the display fonts are self-hosted and precached, so the offline app is the same product as the online one; the count act's CSV names its scope in the shopkeeper's language; the demo simulator mints deterministic ids, so a demo bug report replays; round F: the migration question no longer publishes before the other device agrees, a distributor can no longer evict the shop's own messages or wedge the room with an oversized half, batches and swap requests merge by id, the pre-split snapshot expires; round E: the sync rooms are split — one room per distributor plus the shop's own `self` room, a whitelisted supplier contribution channel that the shop audits and rolls back, the twelve private keys merged at last, key rotation and revocation, and a sync sheet that is a list of named connections */
/* R16 · the display-font subsets are part of the SHELL, not of /vendor/'s fetch-on-first-use
   policy. The ZXing reader is genuinely optional (most Androids have a native barcode detector)
   and 824 KB; there is no such thing as an optional typeface — an app that opens offline in
   fallback fonts is a different product from the one that was designed and reviewed.

   R17 · BUT «THE SHELL» IS NOT THE SAME SET IN EVERY LANGUAGE. The page has always requested
   only latin + armenian in hy/en — the Cyrillic face is behind a unicode-range and a Russian
   user is the only one who paints a character from it — and the argument for keeping Cyrillic at
   all was that it costs the Armenian shopkeeper nothing. It did not: SHELL listed all three, so
   an `hy` install unconditionally downloaded and stored the 18,748-byte Cyrillic file. It is now
   in neither the install nor the cache of a shopkeeper who never reads Russian:
     - CORE (latin + armenian, 75,068 B) is precached in every language. Inter latin carries the
       digits of every money figure and Noto Sans Armenian carries ֏ itself, so both are needed
       on any screen in any language, and their absence is what «fallback fonts» means.
     - the Cyrillic face is pulled into the same cache the first time it is actually wanted:
       either by the /vendor/ cache-first branch below when the page requests it, or ahead of
       that by the {type:'shellfont'} message the page posts when its language IS ru — so a
       Russian user who installs in Russian has it offline from the first run, and everyone else
       never fetches it at all. Exactly the ZXing policy, for exactly the ZXing reason.

   R17 · AND AN INCOMPLETE SHELL IS NOT AN INSTALL. `Promise.all(SHELL.map(u => c.add(u).catch()))`
   resolved whatever happened, so a partial deploy (index.html live, one woff2 not yet uploaded)
   activated a service worker whose cache was missing a face — and the offline app rendered in the
   system stack with no signal to anyone, which is the exact defect precaching exists to close.
   addAll() is all-or-nothing: one retry for a flaky first byte, then the install FAILS, the old
   worker stays in charge, and the next load tries again. */
const F_LATIN = './vendor/fonts/inter-latin-wght-normal.woff2';
const F_ARM   = './vendor/fonts/noto-sans-armenian-armenian-wght-normal.woff2';
const F_CYR   = './vendor/fonts/inter-cyrillic-wght-normal.woff2';
const SHELL = ['./', './index.html', './manifest.json', F_LATIN, F_ARM];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    try {
      try { await c.addAll(SHELL); }
      catch (err) {
        await new Promise(r => setTimeout(r, 1200));
        await c.addAll(SHELL);        // still failing: rethrow, so this worker never activates
      }
    } catch (err) {
      /* and leave nothing half-built behind: caches.open() created the bucket, so an aborted
         install would otherwise hand the NEXT worker a cache that looks like this version's. */
      await caches.delete(CACHE).catch(() => {});
      throw err;
    }
    await self.skipWaiting();
  })());
});

/* the page asks for the Cyrillic face when — and only when — it is showing Russian. Narrow by
   construction: one hard-coded URL, no path travels from the message into the cache. */
self.addEventListener('message', e => {
  const d = e.data;
  if (!d || d.type !== 'shellfont' || d.subset !== 'cyrillic') return;
  const job = caches.open(CACHE)
    .then(c => c.match(F_CYR, { ignoreSearch: true }).then(hit => hit ? null : c.add(F_CYR)))
    .catch(() => {});
  if (e.waitUntil) e.waitUntil(job);
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

  /* R9 · the ZXing reader is NOT precached — 824 KB on install would be charged to a shopkeeper
     who may never need it (his Android Chrome has the native detector). It is fetched the first
     time he actually opens the camera on a browser without one, and kept forever after: a
     cache-first immutable asset, so the basement scan works offline from the second time on. */
  if (url.pathname.indexOf('/vendor/') >= 0) {
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(req, { ignoreSearch: true });
      if (hit) return hit;
      const r = await fetch(req);
      if (r && r.ok) cache.put(req, r.clone()).catch(() => {});
      return r;
    })());
    return;
  }

  const isShell = req.mode === 'navigate' || url.pathname.endsWith('/armtrade/') ||
                  url.pathname.endsWith('/index.html') || url.pathname.endsWith('/manifest.json');
  if (!isShell) return;

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    /* The app shell is the fallback for the APP, and only for the app. req.mode==='navigate'
       above catches every navigation in scope, which now includes /armtrade/about/ and its guide
       and one-pager — and handing an offline reader who asked for the explainer the application
       instead is worse than telling him the truth, which is that we do not have it. */
    const isAppRoot = url.pathname === '/armtrade/' || url.pathname.endsWith('/armtrade/index.html');
    const cached = await cache.match(req, { ignoreSearch: true }) ||
                   (isAppRoot ? await cache.match('./index.html', { ignoreSearch: true }) : null);
    const net = fetch(req).then(r => {
      if (r && r.ok) cache.put(req, r.clone()).catch(() => {});
      return r;
    }).catch(() => null);
    // fresh if the network answers quickly, last-known-good otherwise — never an error page
    const fresh = await Promise.race([net, new Promise(r => setTimeout(() => r(null), 2500))]);
    return fresh || cached || net.then(r => r || Response.error());
  })());
});
