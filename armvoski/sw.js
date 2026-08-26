/* ArmVoski service worker.

   The app ships a standalone PWA manifest, so a jeweller who installs it expects it to OPEN
   without signal — in a shop with thick walls, in a basement, on a cheap Android. Without a
   precached shell, a relaunch offline gives a browser error page.

   Strategy, following ArmTrade's:
   - the app shell (one HTML file + the manifest) is precached on install and served
     stale-while-revalidate, so a cold start offline paints the last good build;
   - /api/* is NEVER cached — sync must fail honestly, never replay a stale room;
   - anything else falls through to the network untouched.
   Bump CACHE when the shell changes. */
const CACHE = 'armvoski-shell-v11';
   /* v11: the glass touch layer. Buttons, chips, the header, the bottom nav, the toast and
      the sheet are translucent, rounded and tinted in the product's own hue; reading surfaces are
      untouched. A cached v10 shell would paint the old flat Ledger controls beside the new ones
      on the hub and the other two apps, which is the one thing a shared house style cannot survive. */
  
   /* v10: motion pass against Emil Kowalski's emil-design-eng skill. The full-screen fade
      on every tab switch is gone (the most repeated action in the app must not animate), sheets
      now leave on a 160ms exit instead of vanishing, the toast exits faster than it enters, the
      1.6s and 0.9s attention flashes are cut to 260ms, and the progress bar no longer promises a
      transition on `width`. A cached v9 shell would keep fading the screen on every nav tap. */
     /* v8: the ledger skin — ruled blocks instead of cards, ink
      instead of a palette, square corners, and no pictographs left in the product. A cached v7
      shell would keep painting the old skin beside the new one on the hub and the other two
      apps, which is the one thing a shared house style cannot survive. v5: the count no longer posts a movement against a book figure read AFTER the weighing (a
      mid-session buy-in read as a shortage and the correction destroyed the metal), unvisited
      subjects no longer print as counted on the act, a zero metal rate is refused instead of
      being sold on, and five signed documents keep their sub-line data on paper. A cached v4
      shell would go on drawing acts that assert what nobody counted and selling metal for
      nothing, which is exactly the class of thing an offline cache must not preserve. */

/* THE DISPLAY FONTS ARE PART OF THE SHELL, not optional assets. An app that opens offline in
   fallback fonts is a different product from the one that was designed and reviewed: different
   metrics, different digit widths, and — because the dram sign ֏ (U+058F) lives in the Armenian
   range — a money figure whose currency mark may not render at all.

   TWO FILES, NOT THREE. Inter latin carries the digits of every money and every gram figure, and
   Noto Sans Armenian carries ֏ itself, so both are needed on any screen in any language. The
   Cyrillic face is behind a unicode-range and only a Russian reader ever paints a character from
   it; precaching it would charge an Armenian-only install 18,748 bytes it will never use. It is
   pulled in on first use by the /vendor/ cache-first branch below, or ahead of that by the
   {type:'shellfont'} message the page can post when its language is ru.

   THE PATHS POINT INTO /armtrade/. The two products share one typeface and one set of files
   rather than shipping two copies — one download, one cache entry, and a browser that already
   has ArmTrade installed pays nothing at all.

   KNOWN LIMIT, stated rather than hidden: this worker's SCOPE is /armvoski/, so it does not
   receive fetch events for /armtrade/vendor/fonts/*. The precache below still puts the two faces
   in this cache (addAll accepts any same-origin URL), which is what the shell contract asks for,
   but serving them from it offline needs either a Service-Worker-Allowed header widening the
   scope to '/' or a copy of the two woff2 files under /armvoski/vendor/. That is a deployment
   decision for the owner, not something to paper over here. */
const F_LATIN = '../armtrade/vendor/fonts/inter-latin-wght-normal.woff2';
const F_ARM   = '../armtrade/vendor/fonts/noto-sans-armenian-armenian-wght-normal.woff2';
const F_CYR   = '../armtrade/vendor/fonts/inter-cyrillic-wght-normal.woff2';
const SHELL = ['./', './index.html', './manifest.json', F_LATIN, F_ARM];

/* AN INCOMPLETE SHELL IS NOT AN INSTALL. `Promise.all(SHELL.map(u => c.add(u).catch()))` resolves
   whatever happens, so a partial deploy (index.html live, one woff2 not yet uploaded) would
   activate a worker whose cache is missing a face — and the offline app renders in the system
   stack with no signal to anyone, which is the exact defect precaching exists to close.
   addAll() is all-or-nothing: one retry for a flaky first byte, then the install FAILS, the old
   worker stays in charge, and the next load tries again. */
self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    try {
      try { await c.addAll(SHELL); }
      catch (err) {
        await new Promise(r => setTimeout(r, 1200));
        await c.addAll(SHELL);      // still failing: rethrow, so this worker never activates
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

  /* vendor assets are immutable: cache-first, kept forever after the first fetch */
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

  const isShell = req.mode === 'navigate' || url.pathname.endsWith('/armvoski/') ||
                  url.pathname.endsWith('/index.html') || url.pathname.endsWith('/manifest.json');
  if (!isShell) return;

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    /* The app shell is the fallback for the APP, and only for the app. req.mode==='navigate'
       above catches every navigation in scope, which now includes /armvoski/about/ and its guide
       and one-pager — and handing an offline reader who asked for the explainer the application
       instead is worse than telling him the truth, which is that we do not have it. */
    const isAppRoot = url.pathname === '/armvoski/' || url.pathname.endsWith('/armvoski/index.html');
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
