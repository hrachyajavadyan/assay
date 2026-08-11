// ArmTrade sync API — Cloudflare Pages Function backed by D1.
// Requires a D1 database bound to the Pages project as "DB".
// Table auto-creates on first use.
//
// R8 · SECURITY REWRITE. The previous version performed exactly one check on any request — a
// regex on the room code — and every real customer was pointed at one room code that was a
// constant in the served HTML. `curl /api/room/ARM-MAIN` returned every order, every unit
// purchase price, both parties' ՀՎՀՀ, all debts, the whole stock ledger, every chat transcript
// and every գույքագրման ակտ, to anyone, with no credential; a POST replaced all of it.
//
// Now: a room is (code, key). The code addresses the row. The key is minted on the device that
// creates the room, is 16 characters of client-side entropy, is never present in any served
// file, and is verified here — SHA-256(key + ':' + code), compared in constant time — on every
// verb including the probe. Rooms bind to the first key that writes them and never change owner.
// Repeated bad keys lock the room for 15 minutes. Rows untouched for 180 days are purged.

const TTL_MS = 180 * 24 * 60 * 60 * 1000;
const MAX_FAILS = 10;
const LOCK_MS = 15 * 60 * 1000;

async function ensureTable(db){
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS rooms (code TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0, data TEXT, updated INTEGER, keyh TEXT, fails INTEGER DEFAULT 0, lock INTEGER DEFAULT 0)"
  ).run();
  // pre-R8 databases: add the three columns, ignore "duplicate column name"
  for(const sql of [
    "ALTER TABLE rooms ADD COLUMN keyh TEXT",
    "ALTER TABLE rooms ADD COLUMN fails INTEGER DEFAULT 0",
    "ALTER TABLE rooms ADD COLUMN lock INTEGER DEFAULT 0"
  ]){ try{ await db.prepare(sql).run(); }catch(e){} }
}

function bad(status, msg){
  return new Response(JSON.stringify({error: msg}), {status, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
}

function ok(obj, status){
  return new Response(JSON.stringify(obj), {status: status||200, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
}

function validCode(code){
  return typeof code === 'string' && /^[A-Z0-9-]{4,24}$/.test(code);
}
function validKey(k){
  return typeof k === 'string' && /^[A-Za-z0-9_-]{10,64}$/.test(k);
}

async function keyHash(key, code){
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key + ':' + code));
  return [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('');
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

async function purge(db, now){
  try{ await db.prepare('DELETE FROM rooms WHERE updated IS NOT NULL AND updated < ?').bind(now - TTL_MS).run(); }catch(e){}
}

async function noteFail(db, code, row, now){
  const fails = (row && row.fails ? row.fails : 0) + 1;
  const lock = fails >= MAX_FAILS ? now + LOCK_MS : 0;
  try{ await db.prepare('UPDATE rooms SET fails = ?, lock = ? WHERE code = ?').bind(fails >= MAX_FAILS ? 0 : fails, lock, code).run(); }catch(e){}
}

// resolve (code, key) -> {row} or an error Response
async function authorize(db, code, key, row, now){
  if(!validKey(key)) return {err: bad(401, 'room key required')};
  if(!row) return {row: null};                                   // room does not exist yet
  if(row.lock && row.lock > now) return {err: bad(429, 'too many attempts')};
  if(!row.keyh){
    /* a pre-R8 row: it was world-readable for its whole life, so its contents are already burned.
       Nobody can read it now (no key can match), which makes it dead weight holding a shop's
       ledger. Purge it on first touch and make the customers re-pair. */
    try{ await db.prepare('DELETE FROM rooms WHERE code = ? AND keyh IS NULL').bind(code).run(); }catch(e){}
    return {err: bad(403, 'room predates keys; re-pair the devices')};
  }
  const h = await keyHash(key, code);
  if(!sameHash(h, row.keyh)){ await noteFail(db, code, row, now); return {err: bad(403, 'bad room key')}; }
  if(row.fails) { try{ await db.prepare('UPDATE rooms SET fails = 0 WHERE code = ?').bind(code).run(); }catch(e){} }
  return {row};
}

export async function onRequestGet({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  const key = readKey(request);
  if(!validKey(key)) return bad(401, 'room key required');
  await ensureTable(env.DB);
  const now = Date.now();
  await purge(env.DB, now);
  const row = await env.DB.prepare('SELECT v, data, keyh, fails, lock FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(env.DB, code, key, row, now);
  if(a.err) return a.err;
  // an unbound code is not an oracle: it looks exactly like an empty room to a holder of any key
  if(!a.row) return ok({v: 0}, 404);
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
  const payload = JSON.stringify(body.data);
  if(payload.length > 1_000_000) return bad(413, 'state too large');
  await ensureTable(env.DB);
  const now = Date.now();
  await purge(env.DB, now);
  const cur = await env.DB.prepare('SELECT v, data, keyh, fails, lock FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(env.DB, code, key, cur, now);
  if(a.err) return a.err;
  const h = await keyHash(key, code);
  if(!a.row){
    // first write binds the room to this key, for good
    try{
      const res = await env.DB.prepare(
        'INSERT INTO rooms (code, v, data, updated, keyh, fails, lock) VALUES (?, 1, ?, ?, ?, 0, 0)'
      ).bind(code, payload, now, h).first();
      return ok({v: 1});
    }catch(e){
      // lost the race to another device: fall through and treat it as a normal conflicting write
      const again = await env.DB.prepare('SELECT v, data, keyh FROM rooms WHERE code = ?').bind(code).first();
      if(!again || !sameHash(h, again.keyh || '')) return bad(403, 'bad room key');
      let data = null; try{ data = JSON.parse(again.data); }catch(e2){}
      return new Response(JSON.stringify({v: again.v, data}), {status: 409, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
    }
  }
  // optimistic concurrency: if the client's base version is stale, hand back the current state
  if(typeof body.base === 'number' && a.row.v !== body.base){
    let data = null; try{ data = JSON.parse(a.row.data); }catch(e){}
    return new Response(JSON.stringify({v: a.row.v, data}), {status: 409, headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
  }
  const res = await env.DB.prepare(
    'UPDATE rooms SET v = v + 1, data = ?, updated = ? WHERE code = ? RETURNING v'
  ).bind(payload, now, code).first();
  return ok({v: res ? res.v : a.row.v + 1});
}

// R8 · a customer must be able to remove their business from the server.
export async function onRequestDelete({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  const key = readKey(request);
  if(!validKey(key)) return bad(401, 'room key required');
  await ensureTable(env.DB);
  const now = Date.now();
  const row = await env.DB.prepare('SELECT v, keyh, fails, lock FROM rooms WHERE code = ?').bind(code).first();
  const a = await authorize(env.DB, code, key, row, now);
  if(a.err) return a.err;
  if(!a.row) return ok({deleted: 0});
  await env.DB.prepare('DELETE FROM rooms WHERE code = ?').bind(code).run();
  return ok({deleted: 1});
}
