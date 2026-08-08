// ArmTrade sync API — Cloudflare Pages Function backed by D1.
// Requires a D1 database bound to the Pages project as "DB".
// Table auto-creates on first use.

async function ensureTable(db){
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS rooms (code TEXT PRIMARY KEY, v INTEGER NOT NULL DEFAULT 0, data TEXT, updated INTEGER)"
  ).run();
}

function bad(status, msg){
  return new Response(JSON.stringify({error: msg}), {status, headers:{'Content-Type':'application/json'}});
}

function ok(obj){
  return new Response(JSON.stringify(obj), {headers:{'Content-Type':'application/json', 'Cache-Control':'no-store'}});
}

function validCode(code){
  return typeof code === 'string' && /^[A-Z0-9-]{4,24}$/.test(code);
}

export async function onRequestGet({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  await ensureTable(env.DB);
  const url = new URL(request.url);
  const row = await env.DB.prepare('SELECT v, data FROM rooms WHERE code = ?').bind(code).first();
  if(!row) return ok({v: 0});
  if(url.searchParams.has('probe')) return ok({v: row.v});
  let data = null;
  try{ data = JSON.parse(row.data); }catch(e){}
  return ok({v: row.v, data});
}

export async function onRequestPost({request, env, params}){
  if(!env.DB) return bad(503, 'D1 binding "DB" is not configured');
  const code = (params.code || '').toUpperCase();
  if(!validCode(code)) return bad(400, 'bad room code');
  let body;
  try{ body = await request.json(); }catch(e){ return bad(400, 'bad json'); }
  if(!body || typeof body.data !== 'object') return bad(400, 'missing data');
  const payload = JSON.stringify(body.data);
  if(payload.length > 1_000_000) return bad(413, 'state too large');
  await ensureTable(env.DB);
  const now = Date.now();
  // last-write-wins with server-assigned version
  const res = await env.DB.prepare(
    `INSERT INTO rooms (code, v, data, updated) VALUES (?, 1, ?, ?)
     ON CONFLICT(code) DO UPDATE SET v = rooms.v + 1, data = excluded.data, updated = excluded.updated
     RETURNING v`
  ).bind(code, payload, now).first();
  return ok({v: res ? res.v : 1});
}
