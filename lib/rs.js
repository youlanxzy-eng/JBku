// JB KU · Sistem Reseller · helper server (dipakai api/rs.js dan api/webhook.js)
import crypto from "node:crypto";

const ENV = (k, d) => (process.env[k] ?? d);
export const SB_URL = () => String(ENV("SUPABASE_URL", "")).replace(/\/+$/, "");
const SB_KEY = () => ENV("SUPABASE_SERVICE_KEY", "");
const SECRET = () => ENV("SESSION_SECRET", "");

export class HttpErr extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}
export const fail = (status, msg) => { throw new HttpErr(status, msg); };

// ---------------------------------------------------------------- Supabase
export async function sb(path, { method = "GET", body, prefer, headers = {} } = {}) {
  if (!SB_URL() || !SB_KEY()) fail(500, "Server belum dikonfigurasi (SUPABASE_URL / SUPABASE_SERVICE_KEY).");
  const key = SB_KEY();
  const h = { apikey: key, "Content-Type": "application/json", ...headers };
  if (key.startsWith("eyJ")) h.Authorization = "Bearer " + key; // kunci JWT lama
  if (prefer) h.Prefer = prefer;
  const r = await fetch(SB_URL() + "/rest/v1/" + path, {
    method, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
  });
  const txt = await r.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; } catch { data = txt; }
  if (!r.ok) {
    const e = new HttpErr(r.status >= 500 ? 502 : r.status, (data && (data.message || data.hint)) || "Database error " + r.status);
    e.code = data && data.code;
    throw e;
  }
  return data;
}
export const enc = encodeURIComponent;

// ---------------------------------------------------------------- Token
const b64u = (s) => Buffer.from(s).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

export function signToken(payload, days = 14) {
  if (!SECRET()) fail(500, "SESSION_SECRET belum diisi.");
  const p = b64u(JSON.stringify({ ...payload, exp: Date.now() + days * 864e5 }));
  const s = crypto.createHmac("sha256", SECRET()).update(p).digest("hex");
  return p + "." + s;
}
export function readToken(req) {
  const raw = String(req.headers["authorization"] || "").replace(/^Bearer\s+/i, "");
  if (!raw || !raw.includes(".")) fail(401, "Sesi panel habis. Masukkan password lagi.");
  const [p, s] = raw.split(".");
  const want = crypto.createHmac("sha256", SECRET()).update(p).digest("hex");
  if (s.length !== want.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(want)))
    fail(401, "Token tidak sah.");
  const pl = JSON.parse(fromB64u(p));
  if (!pl.exp || pl.exp < Date.now()) fail(401, "Sesi panel habis. Masukkan password lagi.");
  return pl;
}

// ---------------------------------------------------------------- Password (sama persis dengan Auth.hash di index.html)
export function pbkdf2(pw, saltHex, iter = 150000) {
  return crypto.pbkdf2Sync(String(pw), Buffer.from(saltHex, "hex"), iter, 32, "sha256").toString("hex");
}
export function makeCred(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: pbkdf2(pw, salt, 150000), iter: 150000 };
}

// ---------------------------------------------------------------- Akun jb_rows
export const USERNAME_RE = /^[a-zA-Z0-9._@-]{3,40}$/;
export async function findUser(username) {
  const un = String(username || "").trim();
  if (!USERNAME_RE.test(un)) return null;
  const rows = await sb(`jb_rows?select=id,data&kind=eq.users&data->>username=ilike.${enc(un.replace(/[%_\\]/g, "\\$&"))}&limit=5`);
  const hit = (rows || []).map((r) => r.data).find((d) => d && String(d.username || "").toLowerCase() === un.toLowerCase());
  return hit || null;
}
export async function getUser(id) {
  const rows = await sb(`jb_rows?select=data&kind=eq.users&id=eq.${enc(id)}&limit=1`);
  return rows && rows[0] ? rows[0].data : null;
}
export async function putUser(u) {
  await sb("jb_rows?on_conflict=kind,id", {
    method: "POST", prefer: "resolution=merge-duplicates,return=minimal",
    body: [{ kind: "users", id: u.id, data: u }],
  });
}
export const newId = () => Date.now().toString(36) + crypto.randomBytes(4).toString("hex").slice(0, 5);

// ---------------------------------------------------------------- Waktu (WIB)
const WIB = 7 * 3600e3;
export const dayStartWIB = (t = Date.now()) => Math.floor((t + WIB) / 864e5) * 864e5 - WIB;
export const monthStartWIB = (t = Date.now()) => {
  const d = new Date(t + WIB);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1) - WIB;
};
export const iso = (t) => new Date(t).toISOString();

// ---------------------------------------------------------------- QRIS statis → dinamis
function crc16(str) {
  let crc = 0xffff;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}
function parseTLV(s) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    const tag = s.slice(i, i + 2), len = parseInt(s.slice(i + 2, i + 4), 10);
    if (!/^\d{2}$/.test(tag) || Number.isNaN(len)) throw new Error("Format QRIS tidak valid");
    out.push([tag, s.slice(i + 4, i + 4 + len)]);
    i += 4 + len;
  }
  return out;
}
export function qrisValid(s) {
  s = String(s || "").trim();
  if (!s.startsWith("000201") || s.length < 30) return false;
  if (crc16(s.slice(0, -4)) !== s.slice(-4).toUpperCase()) return false;
  try { const t = parseTLV(s); return t.some(([k]) => k === "53") && t.some(([k]) => k === "58"); } catch { return false; }
}
export function qrisDynamic(staticQris, amount) {
  const s = String(staticQris || "").trim();
  if (!s) fail(500, "QRIS_STATIC belum diisi di env Vercel.");
  let tlv = parseTLV(s).filter(([t]) => t !== "63" && t !== "54");
  tlv = tlv.map(([t, v]) => (t === "01" ? [t, "12"] : [t, v]));
  const amt = String(Math.round(amount));
  const at = tlv.findIndex(([t]) => t > "54");
  tlv.splice(at < 0 ? tlv.length : at, 0, ["54", amt]);
  const body = tlv.map(([t, v]) => t + String(v.length).padStart(2, "0") + v).join("") + "6304";
  return body + crc16(body);
}

// ---------------------------------------------------------------- Ambil nominal dari teks notifikasi
export function parseAmounts(text) {
  const t = String(text || "");
  const found = new Set();
  const norm = (raw) => {
    let x = raw.trim();
    if (/[.,]\d{2}$/.test(x) && /[.,]\d{3}[.,]\d{2}$|^\d+[.,]\d{2}$/.test(x)) x = x.slice(0, -3);
    const n = parseInt(x.replace(/[^\d]/g, ""), 10);
    return Number.isFinite(n) ? n : null;
  };
  for (const m of t.matchAll(/(?:rp|idr)\s*\.?\s*([0-9][0-9.,]*)/gi)) {
    const n = norm(m[1]);
    if (n && n >= 1000 && n < 1e9) found.add(n);
  }
  if (!found.size) {
    for (const m of t.matchAll(/\b\d{1,3}(?:[.,]\d{3})+(?:[.,]\d{2})?\b/g)) {
      const n = norm(m[0]);
      if (n && n >= 1000 && n < 1e9) found.add(n);
    }
  }
  return [...found];
}

// ---------------------------------------------------------------- Pengaturan & reseller
export async function settings() {
  const r = await sb("rs_settings?id=eq.1&select=*");
  return r && r[0] ? r[0] : { price: 25000, expire_minutes: 15, max_pending: 2 };
}
export function effectiveStatus(rs) {
  if (rs.status === "paused" && rs.paused_until && new Date(rs.paused_until).getTime() <= Date.now()) return "active";
  return rs.status;
}
export async function expireOld() {
  await sb(`rs_orders?status=eq.pending&expires_at=lt.${enc(new Date().toISOString())}`, {
    method: "PATCH", body: { status: "expired" }, prefer: "return=minimal",
  });
}

// ---------------------------------------------------------------- Pelunasan → buat akun otomatis
export async function fulfill(order, via, webhookId = null, allowError = false) {
  // kunci order: hanya satu proses yang berhasil mengubah status
  const lock = await sb(`rs_orders?id=eq.${enc(order.id)}&status=in.(pending,expired${allowError ? ",error" : ""})`, {
    method: "PATCH", prefer: "return=representation",
    body: { status: "paid", paid_at: new Date().toISOString(), paid_via: via, webhook_id: webhookId },
  });
  if (!lock || !lock.length) return { ok: false, reason: "sudah diproses" };
  const o = lock[0];
  try {
    const dup = await findUser(o.buyer_username);
    if (dup) throw new Error("Username sudah dipakai akun lain sebelum dibayar");
    const id = newId(), now = Date.now();
    const user = {
      id, username: o.buyer_username, name: o.buyer_name || o.buyer_store,
      role: "member", active: true, vipUi: false, maxDev: 0, exp: null, // permanen, paket free
      trialUsed: true, // tanpa trial Pro otomatis: Pro/VIP hanya dari admin
      createdAt: now,
      salt: o.pw_salt, hash: o.pw_hash, iter: o.pw_iter,
      profile: { store: o.buyer_store },
      createdBy: { rid: o.reseller_id, rname: o.reseller_name, at: now, order: o.id, sale: o.sale_price, paid: o.amount },
    };
    await putUser(user);
    await sb(`rs_orders?id=eq.${enc(o.id)}`, { method: "PATCH", prefer: "return=minimal", body: { created_user_id: id, error: null } });
    return { ok: true, userId: id, order: o };
  } catch (e) {
    await sb(`rs_orders?id=eq.${enc(o.id)}`, { method: "PATCH", prefer: "return=minimal", body: { status: "error", error: String(e.message || e).slice(0, 300) } });
    return { ok: false, reason: String(e.message || e) };
  }
}

// ---------------------------------------------------------------- HTTP kecil
export function body(req) {
  const b = req.body;
  if (b == null) return {};
  if (typeof b === "string") { try { return JSON.parse(b); } catch { return { text: b }; } }
  if (Buffer.isBuffer(b)) { const s = b.toString("utf8"); try { return JSON.parse(s); } catch { return { text: s }; } }
  return b;
}
export function send(res, status, data) {
  res.setHeader("Cache-Control", "no-store");
  res.status(status).json(data);
}
export const clampInt = (v, lo, hi) => {
  const t = String(v ?? "").replace(/[^\d-]/g, "");
  if (!t) return null;
  const n = Math.round(Number(t));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : null;
};
export const clean = (s, n = 40) => String(s ?? "").replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, n);
