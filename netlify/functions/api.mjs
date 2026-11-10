// GeoFront Online — серверная функция для Netlify.
// Аккаунты, комнаты, синхронизация карты, чат и таблица лидеров.
// Данные хранятся в Netlify Blobs (бесплатно, ничего настраивать не нужно).
import crypto from "node:crypto";

const MAX_EVENTS = 400;          // сколько последних событий хранить в комнате
const ONLINE_SEC = 45;           // игрок считается в комнате, если был активен за последние N секунд
const ROOM_TTL = 10 * 60 * 1000; // пустая комната исчезает из списка через 10 минут
const MAX_OP = 400_000;          // макс. размер одной операции (байт)
const MAX_SNAP = 3_000_000;      // макс. размер снимка карты (байт)

const now = () => Date.now();
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");
const clean = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, n);

class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const fail = (code, msg) => { throw new HttpError(code, msg); };

// ---------- хранилище: обёртка с повтором при одновременной записи
async function getJSON(store, key) {
  const r = await store.getWithMetadata(key, { type: "json" });
  return r ? { data: r.data, etag: r.etag } : { data: null, etag: null };
}
async function update(store, key, fn, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const { data, etag } = await getJSON(store, key);
    const next = await fn(data);
    if (next === undefined) return data;
    const opts = etag ? { onlyIfMatch: etag } : { onlyIfNew: true };
    const res = await store.setJSON(key, next, opts);
    if (!res || res.modified !== false) return next;
    await new Promise((r) => setTimeout(r, 30 + Math.random() * 90 * (i + 1)));
  }
  fail(409, "Сервер занят, попробуйте ещё раз");
}

// ---------- токены
async function secret(store, env) {
  if (env.GF_SECRET) return env.GF_SECRET;
  let s = await store.get("meta/secret");
  if (!s) {
    const fresh = crypto.randomBytes(32).toString("hex");
    await store.set("meta/secret", fresh, { onlyIfNew: true });
    s = (await store.get("meta/secret")) || fresh;
  }
  return s;
}
function sign(sec, payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", sec).update(body).digest("base64url");
  return body + "." + mac;
}
function verify(sec, token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  const good = crypto.createHmac("sha256", sec).update(body).digest("base64url");
  if (mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (p.exp < now()) return null;
    return p;
  } catch { return null; }
}
const hashPass = (pass, salt) => crypto.scryptSync(String(pass), salt, 32).toString("hex");

function publicUser(u) { return { nick: u.nick, sec: u.sec || 0, created: u.created }; }

// ---------- комнаты
function genCode() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let c = ""; for (let i = 0; i < 6; i++) c += A[crypto.randomInt(A.length)];
  return c;
}
const activePlayers = (meta) => Object.entries(meta.players || {})
  .filter(([, p]) => now() - p.last < ONLINE_SEC * 1000)
  .map(([uid, p]) => ({ uid, nick: p.nick, color: p.color, host: uid === meta.host }));

const COLORS = ["#e0b24f", "#5fb3ff", "#ff7a6b", "#7bd88f", "#c792ea", "#ffcb6b", "#82aaff", "#f78c6c", "#89ddff", "#c3e88d", "#ff5370", "#b2ccd6"];

async function touchIndex(store, meta) {
  const players = activePlayers(meta).length;
  await update(store, "rooms/index", (idx) => {
    idx = idx || { rooms: {} };
    const t = now();
    for (const [c, r] of Object.entries(idx.rooms)) if (t - r.updated > ROOM_TTL) delete idx.rooms[c];
    if (meta.closed) delete idx.rooms[meta.code];
    else idx.rooms[meta.code] = { code: meta.code, name: meta.name, host: meta.hostNick, max: meta.max, private: !!meta.private, players, scenario: meta.scenario || "", created: meta.created, updated: t };
    return idx;
  });
}

async function pushEvent(store, code, ev) {
  let seq = 0;
  await update(store, `room/${code}/ev`, (doc) => {
    doc = doc || { seq: 0, list: [] };
    seq = doc.seq + 1;
    doc.seq = seq;
    doc.list.push({ ...ev, seq, t: now() });
    if (doc.list.length > MAX_EVENTS) doc.list = doc.list.slice(-MAX_EVENTS);
    return doc;
  });
  return seq;
}

async function presence(store, code, user, force) {
  let meta = null, changed = false;
  await update(store, `room/${code}/meta`, (m) => {
    if (!m || m.closed) fail(404, "Комната не найдена или закрыта");
    const p = m.players[user.uid];
    const fresh = p && now() - p.last < ONLINE_SEC * 1000;
    if (!force && p && now() - p.last < 15000) { meta = m; return undefined; }
    if (!p) {
      if (activePlayers(m).length >= m.max) fail(403, "Комната заполнена");
      const used = new Set(Object.values(m.players).map((x) => x.color));
      m.players[user.uid] = { nick: user.nick, color: COLORS.find((c) => !used.has(c)) || COLORS[Object.keys(m.players).length % COLORS.length], last: now(), joined: now() };
      changed = true;
    } else {
      if (!fresh) changed = true;
      p.last = now(); p.nick = user.nick;
    }
    m.updated = now();
    meta = m;
    return m;
  });
  return { meta, changed };
}

// ---------- обработчик действий
export async function handle(body, { store, env = {}, ip = "" }) {
  const action = String(body.action || "");
  const sec = await secret(store, env);
  const auth = () => {
    const p = verify(sec, body.token);
    if (!p) fail(401, "Нужно войти в аккаунт");
    return p;
  };

  switch (action) {
    case "ping": return { ok: true, t: now() };

    case "register": {
      const email = clean(body.email, 120).toLowerCase();
      const nick = clean(body.nick, 20);
      const pass = String(body.password || "");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) fail(400, "Неверная почта");
      if (pass.length < 6) fail(400, "Пароль минимум 6 символов");
      if (nick.length < 3) fail(400, "Ник минимум 3 символа");
      if (!/^[\p{L}\p{N}_\-. ]+$/u.test(nick)) fail(400, "В нике только буквы, цифры, пробел, _ - .");
      const uid = sha("u:" + email).slice(0, 24);
      const nickKey = "nicks/" + sha(nick.toLowerCase()).slice(0, 32);
      if (await store.get("users/" + uid)) fail(409, "Эта почта уже зарегистрирована — войдите");
      const taken = await store.get(nickKey);
      if (taken && taken !== uid) fail(409, "Этот ник уже занят");
      const salt = crypto.randomBytes(16).toString("hex");
      const user = { uid, email, nick, salt, hash: hashPass(pass, salt), created: now(), sec: 0, lastBeat: 0 };
      const r = await store.setJSON("users/" + uid, user, { onlyIfNew: true });
      if (r && r.modified === false) fail(409, "Эта почта уже зарегистрирована — войдите");
      await store.set(nickKey, uid);
      const token = sign(sec, { uid, nick, exp: now() + 1000 * 3600 * 24 * 60 });
      return { token, user: publicUser(user) };
    }

    case "login": {
      const email = clean(body.email, 120).toLowerCase();
      const uid = sha("u:" + email).slice(0, 24);
      const user = await store.get("users/" + uid, { type: "json" });
      if (!user || hashPass(body.password || "", user.salt) !== user.hash) fail(401, "Неверная почта или пароль");
      const token = sign(sec, { uid, nick: user.nick, exp: now() + 1000 * 3600 * 24 * 60 });
      return { token, user: publicUser(user) };
    }

    case "me": {
      const p = auth();
      const user = await store.get("users/" + p.uid, { type: "json" });
      if (!user) fail(401, "Аккаунт не найден");
      return { user: publicUser(user) };
    }

    case "rooms": {
      const idx = (await store.get("rooms/index", { type: "json" })) || { rooms: {} };
      const t = now();
      const list = Object.values(idx.rooms).filter((r) => !r.private && t - r.updated < ROOM_TTL).sort((a, b) => b.players - a.players || b.updated - a.updated).slice(0, 60);
      return { rooms: list };
    }

    case "create": {
      const p = auth();
      const name = clean(body.name, 40) || `Комната ${p.nick}`;
      const max = Math.max(2, Math.min(16, parseInt(body.max, 10) || 8));
      const snap = body.snap;
      if (snap && JSON.stringify(snap).length > MAX_SNAP) fail(413, "Карта слишком большая");
      let code = "";
      for (let i = 0; i < 6; i++) { code = genCode(); if (!(await store.get(`room/${code}/meta`))) break; }
      const meta = { code, name, host: p.uid, hostNick: p.nick, max, private: !!body.private, scenario: clean(body.scenario, 30), created: now(), updated: now(), players: {} };
      await store.setJSON(`room/${code}/meta`, meta);
      await store.setJSON(`room/${code}/ev`, { seq: 0, list: [] });
      if (snap) await store.setJSON(`room/${code}/snap`, { seq: 0, upto: 0, by: p.uid, t: now(), state: snap });
      const { meta: m } = await presence(store, code, p, true);
      await pushEvent(store, code, { type: "sys", text: `${p.nick} создал(а) комнату` });
      await touchIndex(store, m);
      return { code, room: roomInfo(m) };
    }

    case "join": {
      const p = auth();
      const code = clean(body.code, 8).toUpperCase();
      if (!/^[A-Z0-9]{6}$/.test(code)) fail(400, "Код комнаты — 6 символов");
      const { meta, changed } = await presence(store, code, p, true);
      if (changed) await pushEvent(store, code, { type: "sys", text: `${p.nick} зашёл(ла) в комнату` });
      await touchIndex(store, meta);
      const snap = await store.get(`room/${code}/snap`, { type: "json" });
      const ev = (await store.get(`room/${code}/ev`, { type: "json" })) || { seq: 0, list: [] };
      const from = snap ? (snap.upto != null ? snap.upto : snap.seq) : 0;
      return { code, room: roomInfo(meta), snap: snap ? { seq: snap.seq, upto: snap.upto || 0, state: snap.state, by: snap.by } : null, events: ev.list.filter((e) => e.seq > from), seq: ev.seq, you: { uid: p.uid, color: meta.players[p.uid].color } };
    }

    case "poll": {
      const p = auth();
      const code = clean(body.code, 8).toUpperCase();
      const since = parseInt(body.since, 10) || 0;
      const { meta, changed } = await presence(store, code, p, false);
      if (changed) { await pushEvent(store, code, { type: "sys", text: `${p.nick} вернулся(ась)` }); await touchIndex(store, meta); }
      const ev = (await store.get(`room/${code}/ev`, { type: "json" })) || { seq: 0, list: [] };
      let events = ev.list.filter((e) => e.seq > since);
      let resync = false;
      if (since && ev.list.length && ev.list[0].seq > since + 1) resync = true; // пропустили события — нужен свежий снимок
      return { seq: ev.seq, events, resync, players: activePlayers(meta), room: roomInfo(meta) };
    }

    case "send": {
      const p = auth();
      const code = clean(body.code, 8).toUpperCase();
      const ev = body.ev || {};
      const meta = await store.get(`room/${code}/meta`, { type: "json" });
      if (!meta || meta.closed) fail(404, "Комната закрыта");
      if (!meta.players[p.uid]) fail(403, "Вы не в этой комнате");
      let out;
      if (ev.type === "chat") {
        const text = clean(ev.text, 300);
        if (!text) fail(400, "Пустое сообщение");
        out = { type: "chat", uid: p.uid, nick: p.nick, color: meta.players[p.uid].color, text };
      } else if (ev.type === "op") {
        const raw = JSON.stringify(ev.geom || []);
        if (raw.length > MAX_OP) fail(413, "Слишком большая операция");
        out = { type: "op", uid: p.uid, nick: p.nick, cid: clean(ev.cid, 40), side: clean(ev.side, 8), geom: ev.geom, kind: clean(ev.kind, 20), name: clean(ev.name, 80), hash: clean(ev.hash, 20) };
      } else if (ev.type === "snap") {
        if (!ev.state || JSON.stringify(ev.state).length > MAX_SNAP) fail(413, "Карта слишком большая");
        const upto = Math.max(0, parseInt(ev.upto, 10) || 0);
        const seq = await pushEvent(store, code, { type: "snap", uid: p.uid, nick: p.nick, cid: clean(ev.cid, 40), reason: clean(ev.reason, 40), hash: clean(ev.hash, 20), upto });
        await store.setJSON(`room/${code}/snap`, { seq, upto, by: p.uid, t: now(), state: ev.state });
        return { seq };
      } else if (ev.type === "hash") {
        out = { type: "hash", uid: p.uid, hash: clean(ev.hash, 20), ver: parseInt(ev.ver, 10) || 0 };
      } else fail(400, "Неизвестное событие");
      const seq = await pushEvent(store, code, out);
      return { seq };
    }

    case "snap": {
      auth();
      const code = clean(body.code, 8).toUpperCase();
      const snap = await store.get(`room/${code}/snap`, { type: "json" });
      return { snap };
    }

    case "leave": {
      const p = auth();
      const code = clean(body.code, 8).toUpperCase();
      let meta = null;
      await update(store, `room/${code}/meta`, (m) => {
        if (!m || !m.players[p.uid]) return undefined;
        m.players[p.uid].last = 0;
        if (m.host === p.uid) { const next = activePlayers(m)[0]; if (next) { m.host = next.uid; m.hostNick = next.nick; } }
        if (!activePlayers(m).length) m.closed = true;
        meta = m; return m;
      });
      if (meta) {
        if (!meta.closed) await pushEvent(store, code, { type: "sys", text: `${p.nick} вышел(ла) из комнаты` });
        await touchIndex(store, meta);
      }
      return { ok: true };
    }

    case "beat": {
      // учёт времени в онлайне для таблицы лидеров
      const p = auth();
      const want = Math.max(0, Math.min(60, parseInt(body.sec, 10) || 0));
      let total = 0, nick = p.nick, added = 0;
      await update(store, "users/" + p.uid, (u) => {
        if (!u) fail(401, "Аккаунт не найден");
        const since = u.lastBeat ? (now() - u.lastBeat) / 1000 : 60;
        added = Math.floor(Math.min(want, since + 5));
        if (added <= 0) { total = u.sec || 0; return undefined; }
        u.sec = (u.sec || 0) + added; u.lastBeat = now(); total = u.sec; nick = u.nick;
        return u;
      });
      if (added > 0) {
        await update(store, "leaderboard", (lb) => {
          lb = lb || { list: {} };
          lb.list[p.uid] = { nick, sec: total, t: now() };
          const arr = Object.entries(lb.list).sort((a, b) => b[1].sec - a[1].sec);
          if (arr.length > 500) lb.list = Object.fromEntries(arr.slice(0, 500));
          return lb;
        });
      }
      return { sec: total };
    }

    case "leaderboard": {
      const lb = (await store.get("leaderboard", { type: "json" })) || { list: {} };
      let me = null;
      const p = verify(sec, body.token);
      const arr = Object.entries(lb.list).sort((a, b) => b[1].sec - a[1].sec).map(([uid, x], i) => ({ rank: i + 1, nick: x.nick, sec: x.sec, me: !!(p && p.uid === uid) }));
      if (p) me = arr.find((x) => x.me) || null;
      return { top: arr.slice(0, 50), me, total: arr.length };
    }

    default: fail(400, "Неизвестное действие");
  }
}

function roomInfo(m) {
  return { code: m.code, name: m.name, host: m.host, hostNick: m.hostNick, max: m.max, private: !!m.private, players: activePlayers(m) };
}

// ---------- точка входа Netlify (Functions v2)
const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-allow-methods": "POST, OPTIONS" };

export default async (req, context) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
  if (req.method !== "POST") return Response.json({ ok: true, app: "GeoFront Online" }, { headers: CORS });
  let body;
  try { body = await req.json(); } catch { return Response.json({ error: "Плохой запрос" }, { status: 400, headers: CORS }); }
  try {
    const { getStore } = await import("@netlify/blobs");
    const store = getStore({ name: "geofront", consistency: "strong" });
    const out = await handle(body, { store, env: { GF_SECRET: process.env.GF_SECRET }, ip: context && context.ip });
    return Response.json(out, { headers: CORS });
  } catch (e) {
    const code = e instanceof HttpError ? e.code : 500;
    if (code === 500) console.error(e);
    return Response.json({ error: e instanceof HttpError ? e.message : "Ошибка сервера" }, { status: code, headers: CORS });
  }
};

export const config = { path: "/api" };
