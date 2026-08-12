// ArmTrade sync API — Cloudflare Pages Function backed by D1.
// Requires a D1 database bound to the Pages project as "DB".
// Tables auto-create on first use.
//
// R8 · SECURITY REWRITE. The previous version performed exactly one check on any request — a
// regex on the room code — and every real customer was pointed at one room code that was a
// constant in the served HTML. `curl /api/room/ARM-MAIN` returned every order, every unit
// purchase price, both parties' ՀՎՀՀ, all debts, the whole stock ledger, every chat transcript
// and every գույքագրման ակտ, to anyone, with no credential; a POST replaced all of it.
//
// Now: a room is (code, key). The code addresses the row. The key is minted on the device that
// creates the room, is 16 characters of client-side CSPRNG entropy (R13 — it used to be
// Math.random), is never present in any served file, and is verified here —
// SHA-256(key + ':' + code), compared in constant time — on every verb including the probe.
// Rooms bind to the first key that writes them and never change owner. Rows untouched for 180
// days are purged.
//
// R13 · WHAT THIS ROUND CHANGED, AND WHY THE FAILURE COUNTER IS GONE.
//
// 1. ONE ANSWER FOR EVERY REFUSAL, WITH THE SAME WORK BEHIND IT. R8 answered an unbound code
//    with 404 and a bound code with a wrong key with 403, so a stranger holding only a code
//    learned whether that shop was a customer. R12 made both bodies `404 {v:0}` — but the two
//    branches still did different work: the wrong-key branch hashed, read the rate-limit table
//    and wrote to it, and the unbound branch returned before any of that. The remaining budget
//    was readable (eleven requests told you which branch you had hit) and so was the clock
//    (three extra D1 round trips on one side only). Both branches now run the SAME statements
//    in the SAME order — SELECT the row, hash the key, compare, refuse — and end in noRoom().
//    Nothing but a correct key distinguishes any two codes, by body, status, header, stored
//    state or elapsed time.
//
// 2. NO UNAUTHENTICATED REQUEST HAS A SIDE EFFECT. R8/R12 DELETED a pre-R8 row (keyh IS NULL)
//    on the read path, before any credential had been checked, and reported the code as free —
//    so a stranger holding nothing but the string 'ARM-MAIN' (which was a constant in the
//    served HTML, i.e. public) could destroy a shop's ledger with one GET and then bind the
//    freed code to their own key with the POST that followed. A legacy row is now inert: it is
//    never read (no key can match a NULL hash), never written, never bound and never deleted by
//    anyone. It answers 404 {v:0} like everything else and ages out with the 180-day purge. The
//    two devices re-pair on a fresh code, which is one 🎲 tap and costs nothing.
//
// 3. THE FAILURE COUNTER IS DELETED. R12 counted failures against a hash of the client IP and
//    locked the caller out for fifteen minutes. In Armenia most mobile customers sit behind
//    carrier-grade NAT, so that lock was a denial of service anyone who overheard a code could
//    inflict on every shopkeeper sharing an address — the same DoS R12 set out to remove, moved
//    one hop. It also refused legitimate room creation, counted a caller's own SUCCESSFUL binds
//    against them, and cost two D1 writes for every refusal, so the limiter amplified exactly
//    the load it existed to shed. And it bought nothing: the key is 79 bits of CSPRNG entropy,
//    so online guessing is hopeless with or without a limiter, and enumeration is answered by
//    point 1. Request floods belong to Cloudflare's edge (WAF / rate-limiting rules), which
//    sheds them before a Function or a D1 statement is ever billed.
//
//    ONE meter survives, and only because it is the one thing an anonymous caller can make the
//    operator pay for: creating rows. A caller may bind at most BIND_MAX new rooms per hour. A
//    human pairs a phone once. Over the budget the answer is the ordinary noRoom() — never a
//    distinct status — because «this code was free» is precisely the fact point 1 exists to
//    hide.
//
// 4. A MALFORMED `base` IS NO LONGER A BLIND OVERWRITE. `typeof body.base === 'number'` treated
//    a string "0" as «no base supplied» and skipped the version check entirely, so one device
//    whose S.v had come back from localStorage as a string would silently overwrite the other
//    device's un-merged writes. `base` is now either absent or a finite number; anything else
//    is 400.
//
// A 404 on GET still means "either it is free or it is not yours", and the POST that follows
// resolves it — it binds a free code, and is refused with the same 404 on a code owned by
// someone else. That is what keeps «create a room» and «join a room» one button in the client.

const TTL_MS = 180 * 24 * 60 * 60 * 1000;
const BIND_MAX = 30;                       // new rooms one caller may create per window
const BIND_WINDOW_MS = 60 * 60 * 1000;
const PURGE_EVERY_MS = 10 * 60 * 1000;     // per isolate, not per request

// per-isolate, so the DDL and the housekeeping stop being a per-request tax (R13)
let SCHEMA_OK = false;
let LAST_PURGE = 0;

async function ensureTable(db){
  if(SCHEMA_OK) return;
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS rooms (code TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0, data TEXT, updated INTEGER, keyh TEXT, fails INTEGER DEFAULT 0, lock INTEGER DEFAULT 0)"
  ).run();
  // pre-R8 databases: add the three columns, ignore "duplicate column name"
  for(const sql of [
    "ALTER TABLE rooms ADD COLUMN keyh TEXT",
    "ALTER TABLE rooms ADD COLUMN fails INTEGER DEFAULT 0",
    "ALTER TABLE rooms ADD COLUMN lock INTEGER DEFAULT 0"
  ]){ try{ await db.prepare(sql).run(); }catch(e){} }
  /* R13 · the same table R12 created, now holding one thing only: how many rooms this caller
     has created in the current window. `k` is a hash of the client address, never the address
     itself. Column names are kept so a deployed database needs no migration: `fails` is the
     bind count and `lock` is the end of the window. */
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS ratelimit (k TEXT PRIMARY KEY, fails INTEGER DEFAULT 0, lock INTEGER DEFAULT 0, seen INTEGER)"
  ).run();
  SCHEMA_OK = true;
}

function bad(status, msg){
  return new Response(JSON.stringify({error: msg}), {status, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
}

function ok(obj, status){
  return new Response(JSON.stringify(obj), {status: status||200, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
}

/* R12 · the ONE answer for "this code is not yours", "this code is nobody's", "this code is a
   dead pre-R8 row" and "you have created too many rooms this hour". Every verb uses this same
   object so the cases cannot be told apart by status, body or header. */
function noRoom(){
  return ok({v: 0}, 404);
}

function validCode(code){
  return typeof code === 'string' && /^[A-Z0-9-]{4,24}$/.test(code);
}
function validKey(k){
  return typeof k === 'string' && /^[A-Za-z0-9_-]{10,64}$/.test(k);
}

async function sha256hex(s){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('');
}

async function keyHash(key, code){
  return sha256hex(key + ':' + code);
}

// length-independent, value-independent comparison
function sameHash(a, b){
  if(typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for(let i=0;i<a.length;i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function readKey(request){
  const h = request.headers.get('X-Room-Key');
  return h ? h.trim() : '';
}

/* who is calling, as a hash. Cloudflare sets CF-Connecting-IP on every request that reaches a
   Pages Function and it cannot be spoofed by the client; X-Forwarded-For is only a fallback for
   a non-Cloudflare front door. A caller we cannot identify shares the '?' bucket. Since R13 this
   identity is used for ONE thing — how many rooms you may create per hour — so an unidentifiable
   caller can still read and write every room whose key it holds. */
async function callerId(request){
  const ip = (request.headers.get('CF-Connecting-IP')
           || (request.headers.get('X-Forwarded-For') || '').split(',')[0]
           || '').trim();
  if(!ip) return '?';
  return (await sha256hex('armtrade-rl:' + ip)).slice(0, 32);
}

/* R13 · housekeeping is not free — it was two DELETEs on every single request, including every
   4-second poll of every paired device. Once per isolate per ten minutes is enough for rows that
   expire after 180 days. */
async function maybePurge(db, now){
  if(now - LAST_PURGE < PURGE_EVERY_MS) return;
  LAST_PURGE = now;
  try{ await db.prepare('DELETE FROM rooms WHERE updated IS NOT NULL AND updated < ?').bind(now - TTL_MS).run(); }catch(e){}
  try{ await db.prepare('DELETE FROM ratelimit WHERE seen IS NULL OR seen < ?').bind(now - 2*BIND_WINDOW_MS).run(); }catch(e){}
}

/* may this caller create one more room? Read-only; the count is written only after a bind
   actually succeeds, so a refused or losing attempt costs the caller nothing. */
async function bindAllowed(db, rl, now){
  try{
    const r = await db.prepare('SELECT fails, lock FROM ratelimit WHERE k = ?').bind(rl).first();
    if(!r) return true;
    if(!r.lock || r.lock <= now) return true;          // window expired: fresh budget
    return (r.fails || 0) < BIND_MAX;
  }catch(e){ return true; }                            // never let housekeeping block a pairing
}

async function bindNote(db, rl, now){
  try{
    const r = await db.prepare('SELECT fails, lock FROM ratelimit WHERE k = ?').bind(rl).first();
    const fresh = !r || !r.lock || r.lock <= now;
    const n = fresh ? 1 : (r.fails || 0) + 1;
    const until = fresh ? now + BIND_WINDOW_MS : r.lock;
    await db.prepare(
      'INSERT INTO ratelimit (k, fails, lock, seen) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(k) DO UPDATE SET fails = excluded.fails, lock = excluded.lock, seen = excluded.seen'
    ).bind(rl, n, until, now).run();
  }catch(e){}
}

/* resolve (code, key) -> {row} | {row:null} | {err: Response}
   {row:null} means "no room is bound to this code" — the caller may bind it.
   Every other outcome is the one identical refusal.

   R13 · the two refusals must be indistinguishable in WORK as well as in wording, so the hash is
   computed on every path — including for a code with no row and for a dead pre-R8 row — before
   anything branches on it. It is one SHA-256 of ~40 bytes; correctness is worth more than the
   microsecond. Nothing here writes to the database. */
async function authorize(code, key, row, hashPromise){
  if(!validKey(key)) return {err: bad(401, 'room key required')};
  const h = await hashPromise;
  // No room is bound to this code — the caller may create it (POST only). The hash has already
  // been computed and awaited above, so this branch has cost exactly what the next two cost.
  if(!row) return {row: null};
  /* a pre-R8 row: it was world-readable for its whole life and no key can match it now. R8 and
     R12 DELETED it here — on the read path, with no credential — which destroyed a shop's ledger
     for anyone who knew the code and, once R12 reported the code as free, let that same stranger
     re-bind it with the next POST. It is inert instead: unreadable, unwritable, undeletable,
     unbindable, and purged with everything else after 180 days. */
  if(!row.keyh) return {err: noRoom()};
  if(sameHash(h, row.keyh)) return {row};
  return {err: noRoom()};
}

export async function onRequestGet({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  const key = readKey(request);
  if(!validKey(key)) return bad(401, 'room key required');
  await ensureTable(env.DB);
  const now = Date.now();
  await maybePurge(env.DB, now);
  const hp = keyHash(key, code);
  const row = await env.DB.prepare('SELECT v, data, keyh FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(code, key, row, hp);
  if(a.err) return a.err;
  // an unbound code and a code that is not yours are the same answer: 404 {v:0}
  if(!a.row) return noRoom();
  const url = new URL(request.url);
  if(url.searchParams.has('probe')) return ok({v: a.row.v});
  let data = null;
  try{ data = JSON.parse(a.row.data); }catch(e){}
  return ok({v: a.row.v, data});
}

export async function onRequestPost({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  const key = readKey(request);
  if(!validKey(key)) return bad(401, 'room key required');
  let body;
  try{ body = await request.json(); }catch(e){ return bad(400, 'bad json'); }
  if(!body || typeof body.data !== 'object' || body.data === null || Array.isArray(body.data)) return bad(400, 'missing data');
  /* R13 · absent is the ONLY thing that may skip the version check. A string, a null or an
     object used to mean «no base supplied» and overwrote the room unconditionally, which is the
     one failure mode merge-by-uuid exists to prevent. */
  const hasBase = body.base !== undefined && body.base !== null;
  if(hasBase && (typeof body.base !== 'number' || !isFinite(body.base))) return bad(400, 'bad base');
  const payload = JSON.stringify(body.data);
  if(payload.length > 1_000_000) return bad(413, 'state too large');
  await ensureTable(env.DB);
  const now = Date.now();
  await maybePurge(env.DB, now);
  const hp = keyHash(key, code);
  const cur = await env.DB.prepare('SELECT v, data, keyh FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(code, key, cur, hp);
  if(a.err) return a.err;
  const h = await hp;
  if(!a.row){
    /* first write binds the room to this key, for good. This is the one path that treats an
       unbound code differently from someone else's code, and it has to: it is how a room comes
       into existence. It is also the only thing an anonymous caller can make the operator pay
       for, so it is the one thing still metered — and refusing it looks exactly like every other
       refusal, because «this code was free» is the fact we are hiding. */
    const rl = await callerId(request);
    if(!(await bindAllowed(env.DB, rl, now))) return noRoom();
    try{
      await env.DB.prepare(
        'INSERT INTO rooms (code, v, data, updated, keyh, fails, lock) VALUES (?, 1, ?, ?, ?, 0, 0)'
      ).bind(code, payload, now, h).first();
      await bindNote(env.DB, rl, now);
      return ok({v: 1});
    }catch(e){
      // lost the race to another device: fall through and treat it as a normal conflicting write
      const again = await env.DB.prepare('SELECT v, data, keyh FROM rooms WHERE code = ?').bind(code).first();
      if(!again || !sameHash(h, again.keyh || '')) return noRoom();
      let data = null; try{ data = JSON.parse(again.data); }catch(e2){}
      return new Response(JSON.stringify({v: again.v, data}), {status: 409, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
    }
  }
  // optimistic concurrency: if the client's base version is stale, hand back the current state
  if(hasBase && a.row.v !== body.base){
    let data = null; try{ data = JSON.parse(a.row.data); }catch(e){}
    return new Response(JSON.stringify({v: a.row.v, data}), {status: 409, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
  }
  const res = await env.DB.prepare(
    'UPDATE rooms SET v = v + 1, data = ?, updated = ? WHERE code = ? RETURNING v'
  ).bind(payload, now, code).first();
  return ok({v: res ? res.v : a.row.v + 1});
}

/* R8 · a customer must be able to remove their business from the server. R13 · reachable at
   last: ⚙ → 🔗 Համաժամացում → «Ջնջել սերվերից» calls it. Only the key that owns the room can
   delete it; every other caller gets the same 404 {v:0} as everywhere else. */
export async function onRequestDelete({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  const key = readKey(request);
  if(!validKey(key)) return bad(401, 'room key required');
  await ensureTable(env.DB);
  const now = Date.now();
  await maybePurge(env.DB, now);
  const hp = keyHash(key, code);
  const row = await env.DB.prepare('SELECT v, keyh FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(code, key, row, hp);
  if(a.err) return a.err;
  /* R12 · "there was nothing to delete" used to answer 200 {deleted:0} while someone else's room
     answered 403 — the same oracle by another verb. Both are noRoom() now. */
  if(!a.row) return noRoom();
  await env.DB.prepare('DELETE FROM rooms WHERE code = ? AND keyh = ?').bind(code, await hp).run();
  return ok({deleted: 1});
}
