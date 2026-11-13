// JB KU · Sistem Reseller · API utama
//   POST /api/rs?a=auth                 → login panel (admin / reseller)
//   GET  /api/rs?a=r_me                 → data panel reseller
//   POST /api/rs?a=r_create             → reseller membuat order akun (keluar QRIS)
//   GET  /api/rs?a=r_order&id=...       → cek status order milik sendiri
//   POST /api/rs?a=r_cancel             → batalkan order pending milik sendiri
//   GET  /api/rs?a=a_overview           → ringkasan admin
//   GET  /api/rs?a=a_orders             → semua order (filter reseller/status)
//   POST /api/rs?a=a_settings           → atur harga / batas waktu
//   POST /api/rs?a=a_reseller_save      → tambah / ubah reseller
//   POST /api/rs?a=a_reseller_status    → aktif / nonaktif sementara / berhentikan / banned
//   POST /api/rs?a=a_mark_paid          → tandai lunas manual (jika webhook gagal)
//   GET  /api/rs?a=a_webhooks           → 30 notifikasi terakhir dari MacroDroid
import QRCode from "qrcode";
import {
  sb, enc, fail, HttpErr, signToken, readToken, pbkdf2, makeCred, findUser, getUser, putUser, newId,
  USERNAME_RE, dayStartWIB, monthStartWIB, iso, qrisDynamic, qrisValid, settings, effectiveStatus,
  expireOld, fulfill, body, send, clampInt, clean,
} from "../lib/rs.js";

const ORDER_COLS = "id,reseller_id,reseller_name,status,base_price,unique_code,amount,sale_price,buyer_store,buyer_username,buyer_name,created_at,expires_at,paid_at,paid_via,created_user_id,error";
const STATUS_TXT = { active: "Aktif", paused: "Nonaktif sementara", stopped: "Diberhentikan", banned: "Diblokir" };

async function loadReseller(id) {
  const r = await sb(`rs_resellers?id=eq.${enc(id)}&select=*`);
  return r && r[0] ? r[0] : null;
}

async function asReseller(req) {
  const t = readToken(req);
  if (t.role !== "reseller") fail(403, "Khusus reseller.");
  const rs = await loadReseller(t.uid);
  if (!rs) fail(403, "Akun ini bukan reseller lagi.");
  const st = effectiveStatus(rs);
  if (st === "banned") fail(403, "Akun reseller diblokir admin.");
  if (st === "stopped") fail(403, "Kemitraan reseller sudah diberhentikan admin.");
  return { t, rs, st };
}
function asAdmin(req) {
  const t = readToken(req);
  if (t.role !== "admin") fail(403, "Khusus admin.");
  return t;
}

async function countToday(rid) {
  const rows = await sb(`rs_orders?select=id&reseller_id=eq.${enc(rid)}&status=in.(pending,paid)&created_at=gte.${enc(iso(dayStartWIB()))}`);
  return rows.length;
}

const A = {
  // ------------------------------------------------------------ login panel
  async auth(req) {
    const { username, password } = body(req);
    const u = await findUser(username);
    if (!u || !u.salt || pbkdf2(password || "", u.salt, u.iter || 150000) !== u.hash) fail(401, "Username atau password salah.");
    if (!u.active) fail(403, "Akun dinonaktifkan.");
    if (u.role === "admin") {
      return { role: "admin", token: signToken({ uid: u.id, role: "admin", un: u.username }) };
    }
    const rs = await loadReseller(u.id);
    if (!rs) fail(403, "Akun ini bukan reseller.");
    const st = effectiveStatus(rs);
    if (st === "banned") fail(403, "Akun reseller diblokir admin.");
    if (st === "stopped") fail(403, "Kemitraan reseller sudah diberhentikan admin.");
    return { role: "reseller", token: signToken({ uid: u.id, role: "reseller", un: u.username }) };
  },

  // ------------------------------------------------------------ reseller
  async r_me(req) {
    const { rs, st } = await asReseller(req);
    await expireOld();
    const S = await settings();
    const rows = await sb(`rs_orders?select=status,amount,sale_price,created_at&reseller_id=eq.${enc(rs.id)}&order=created_at.desc&limit=5000`);
    const d0 = dayStartWIB(), m0 = monthStartWIB();
    const paid = rows.filter((o) => o.status === "paid");
    const today = rows.filter((o) => (o.status === "paid" || o.status === "pending") && Date.parse(o.created_at) >= d0).length;
    return {
      reseller: { id: rs.id, username: rs.username, name: rs.name, status: st, statusText: STATUS_TXT[st], paused_until: rs.paused_until, daily_limit: rs.daily_limit },
      price: S.price, expire_minutes: S.expire_minutes,
      today, left: rs.daily_limit == null ? null : Math.max(0, rs.daily_limit - today),
      total: { accounts: paid.length, setor: paid.reduce((a, o) => a + o.amount, 0), sales: paid.reduce((a, o) => a + o.sale_price, 0) },
      month: { accounts: paid.filter((o) => Date.parse(o.created_at) >= m0).length },
      orders: await sb(`rs_orders?select=${ORDER_COLS}&reseller_id=eq.${enc(rs.id)}&order=created_at.desc&limit=40`),
    };
  },

  async r_create(req) {
    const { rs, st } = await asReseller(req);
    if (st !== "active") fail(403, st === "paused" ? "Akun reseller sedang dinonaktifkan sementara oleh admin." : "Akun reseller tidak aktif.");
    const b = body(req);
    const sale = clampInt(b.sale_price, 0, 1e9);
    if (!sale || sale < 1000) fail(400, "Isi nominal penjualan (minimal Rp 1.000).");
    if (b.honest !== true) fail(400, "Centang pernyataan bahwa nominal penjualan diisi dengan jujur.");
    const store = clean(b.store, 40), name = clean(b.name || b.store, 24), un = String(b.username || "").trim(), pw = String(b.password || "");
    if (store.length < 2) fail(400, "Nama store minimal 2 karakter.");
    if (!USERNAME_RE.test(un)) fail(400, "Username 3–40 karakter: huruf, angka, titik, garis bawah, @ atau -.");
    if (pw.length < 6 || pw.length > 64) fail(400, "Password minimal 6 karakter.");

    await expireOld();
    const S = await settings();
    if (await findUser(un)) fail(409, "Username sudah dipakai. Pilih yang lain.");
    const pend = await sb(`rs_orders?select=id&reseller_id=eq.${enc(rs.id)}&status=eq.pending`);
    if (pend.length >= S.max_pending) fail(429, `Masih ada ${pend.length} order menunggu pembayaran. Selesaikan atau batalkan dulu.`);
    if (rs.daily_limit != null && (await countToday(rs.id)) >= rs.daily_limit) fail(429, `Batas harian tercapai (${rs.daily_limit} akun/hari). Coba lagi besok.`);

    const cred = makeCred(pw);
    const expires = new Date(Date.now() + S.expire_minutes * 60e3).toISOString();
    let order = null;
    for (let i = 0; i < 12 && !order; i++) {
      const code = 1 + Math.floor(Math.random() * 999);
      const amount = S.price + code;
      try {
        const r = await sb("rs_orders", {
          method: "POST", prefer: "return=representation",
          body: {
            reseller_id: rs.id, reseller_name: rs.name || rs.username, base_price: S.price, unique_code: code, amount,
            sale_price: sale, buyer_store: store, buyer_username: un, buyer_name: name,
            pw_salt: cred.salt, pw_hash: cred.hash, pw_iter: cred.iter, expires_at: expires,
            qris: qrisDynamic(process.env.QRIS_STATIC, amount),
          },
        });
        order = r[0];
      } catch (e) {
        if (e.code !== "23505") throw e;
        if (/user_pending/.test(e.message)) fail(409, "Username ini sedang dipesan di order lain.");
      }
    }
    if (!order) fail(503, "Server sibuk, coba lagi sebentar.");
    const svg = await QRCode.toString(order.qris, { type: "svg", errorCorrectionLevel: "M", margin: 2, color: { dark: "#111111", light: "#ffffff" } });
    return { order: pick(order), svg };
  },

  async r_order(req) {
    const { rs } = await asReseller(req);
    await expireOld();
    const r = await sb(`rs_orders?select=${ORDER_COLS},qris&id=eq.${enc(req.query.id || "")}&reseller_id=eq.${enc(rs.id)}`);
    if (!r.length) fail(404, "Order tidak ditemukan.");
    const o = r[0];
    const out = { order: pick(o) };
    if (o.status === "pending" && req.query.qr === "1")
      out.svg = await QRCode.toString(o.qris, { type: "svg", errorCorrectionLevel: "M", margin: 2 });
    return out;
  },

  async r_cancel(req) {
    const { rs } = await asReseller(req);
    const r = await sb(`rs_orders?id=eq.${enc(body(req).id || "")}&reseller_id=eq.${enc(rs.id)}&status=eq.pending`, {
      method: "PATCH", prefer: "return=representation", body: { status: "cancelled" },
    });
    return { ok: !!r.length };
  },

  // ------------------------------------------------------------ admin
  async a_overview(req) {
    asAdmin(req);
    await expireOld();
    const S = await settings();
    const R = await sb("rs_resellers?select=*&order=created_at.desc");
    const O = await sb("rs_orders?select=reseller_id,status,amount,base_price,sale_price,created_at,paid_at&order=created_at.desc&limit=20000");
    const d0 = dayStartWIB(), m0 = monthStartWIB();
    const sum = (a, f) => a.reduce((x, o) => x + f(o), 0);
    const paid = O.filter((o) => o.status === "paid");
    const by = (from) => { const p = paid.filter((o) => Date.parse(o.paid_at || o.created_at) >= from); return { n: p.length, setor: sum(p, (o) => o.amount), sales: sum(p, (o) => o.sale_price) }; };
    const resellers = R.map((r) => {
      const mine = O.filter((o) => o.reseller_id === r.id), mp = mine.filter((o) => o.status === "paid");
      return {
        ...r, status: effectiveStatus(r), statusText: STATUS_TXT[effectiveStatus(r)],
        today: mine.filter((o) => (o.status === "paid" || o.status === "pending") && Date.parse(o.created_at) >= d0).length,
        accounts: mp.length, setor: sum(mp, (o) => o.amount), sales: sum(mp, (o) => o.sale_price),
        month: mp.filter((o) => Date.parse(o.paid_at || o.created_at) >= m0).length,
        pending: mine.filter((o) => o.status === "pending").length,
        last: mine[0] ? mine[0].created_at : null,
      };
    });
    return {
      settings: S,
      qris: { set: !!process.env.QRIS_STATIC, valid: qrisValid(process.env.QRIS_STATIC), webhook: !!process.env.WEBHOOK_KEY },
      totals: { today: by(d0), month: by(m0), all: by(0), pending: O.filter((o) => o.status === "pending").length, errors: O.filter((o) => o.status === "error").length },
      resellers,
    };
  },

  async a_orders(req) {
    asAdmin(req);
    await expireOld();
    let q = `rs_orders?select=${ORDER_COLS}&order=created_at.desc&limit=${clampInt(req.query.limit, 1, 500) || 150}`;
    if (req.query.rid) q += `&reseller_id=eq.${enc(req.query.rid)}`;
    if (req.query.status) q += `&status=eq.${enc(req.query.status)}`;
    return { orders: await sb(q) };
  },

  async a_settings(req) {
    asAdmin(req);
    const b = body(req), patch = { updated_at: new Date().toISOString() };
    if (b.price != null) { const v = clampInt(b.price, 1000, 1e8); if (!v) fail(400, "Harga minimal Rp 1.000."); patch.price = v; }
    if (b.expire_minutes != null) patch.expire_minutes = clampInt(b.expire_minutes, 5, 120);
    if (b.max_pending != null) patch.max_pending = clampInt(b.max_pending, 1, 10);
    const r = await sb("rs_settings?id=eq.1", { method: "PATCH", prefer: "return=representation", body: patch });
    return { settings: r[0] };
  },

  async a_reseller_save(req) {
    asAdmin(req);
    const b = body(req);
    const limit = b.daily_limit === "" || b.daily_limit == null ? null : clampInt(b.daily_limit, 0, 10000);
    const name = clean(b.name, 24), note = clean(b.note, 200);
    if (b.id) {
      const rs = await loadReseller(b.id);
      if (!rs) fail(404, "Reseller tidak ditemukan.");
      await sb(`rs_resellers?id=eq.${enc(rs.id)}`, { method: "PATCH", prefer: "return=minimal", body: { name: name || rs.name, daily_limit: limit, note, updated_at: new Date().toISOString() } });
      const u = await getUser(rs.id);
      if (u && name && u.name !== name) { u.name = name; await putUser(u); }
      if (b.password) {
        if (String(b.password).length < 6) fail(400, "Password minimal 6 karakter.");
        if (u) { Object.assign(u, makeCred(b.password)); await putUser(u); }
      }
      return { ok: true, id: rs.id };
    }
    const un = String(b.username || "").trim();
    if (!USERNAME_RE.test(un)) fail(400, "Username 3–40 karakter: huruf, angka, titik, garis bawah, @ atau -.");
    let u = await findUser(un);
    if (u && u.role === "admin") fail(400, "Akun admin tidak bisa dijadikan reseller.");
    if (u) {
      u.role = "reseller"; u.active = true; if (name) u.name = name;
      if (b.password) { if (String(b.password).length < 6) fail(400, "Password minimal 6 karakter."); Object.assign(u, makeCred(b.password)); }
    } else {
      if (!b.password || String(b.password).length < 6) fail(400, "Password minimal 6 karakter untuk akun baru.");
      u = { id: newId(), username: un, name: name || un, role: "reseller", active: true, vipUi: false, maxDev: 0, exp: null, createdAt: Date.now(), profile: { store: name || un }, ...makeCred(b.password) };
    }
    await putUser(u);
    await sb("rs_resellers?on_conflict=id", {
      method: "POST", prefer: "resolution=merge-duplicates,return=minimal",
      body: { id: u.id, username: u.username, name: name || u.name || u.username, status: "active", paused_until: null, daily_limit: limit, note, updated_at: new Date().toISOString() },
    });
    return { ok: true, id: u.id };
  },

  async a_reseller_status(req) {
    asAdmin(req);
    const b = body(req), st = String(b.status || "");
    if (!["active", "paused", "stopped", "banned"].includes(st)) fail(400, "Status tidak dikenal.");
    const rs = await loadReseller(b.id);
    if (!rs) fail(404, "Reseller tidak ditemukan.");
    const hours = clampInt(b.hours, 0, 24 * 365) || 0;
    await sb(`rs_resellers?id=eq.${enc(rs.id)}`, {
      method: "PATCH", prefer: "return=minimal",
      body: { status: st, paused_until: st === "paused" && hours ? new Date(Date.now() + hours * 3600e3).toISOString() : null, updated_at: new Date().toISOString() },
    });
    if (st !== "active") {
      await sb(`rs_orders?reseller_id=eq.${enc(rs.id)}&status=eq.pending`, { method: "PATCH", prefer: "return=minimal", body: { status: "cancelled" } });
    }
    const u = await getUser(rs.id);
    if (u) {
      if (st === "banned") { u.active = false; }                        // tidak bisa login sama sekali
      else if (st === "stopped") { u.role = "member"; u.active = true; } // jadi member biasa
      else { u.role = "reseller"; u.active = true; }
      await putUser(u);
    }
    return { ok: true };
  },

  async a_mark_paid(req) {
    const t = asAdmin(req);
    const r = await sb(`rs_orders?select=id&id=eq.${enc(body(req).id || "")}`);
    if (!r.length) fail(404, "Order tidak ditemukan.");
    const f = await fulfill(r[0], "manual:" + (t.un || "admin"), null, true);
    if (!f.ok) fail(409, "Gagal: " + f.reason);
    return { ok: true };
  },

  async a_webhooks(req) {
    asAdmin(req);
    return { logs: await sb("rs_webhook_log?select=id,received_at,source,raw,amounts,order_id,result&order=id.desc&limit=30") };
  },
};

function pick(o) {
  const { pw_salt, pw_hash, pw_iter, qris, ...rest } = o;
  return rest;
}

export default async function handler(req, res) {
  try {
    const fn = A[String(req.query.a || "")];
    if (!fn) fail(404, "Aksi tidak dikenal.");
    const write = /^(auth|r_create|r_cancel|a_settings|a_reseller_save|a_reseller_status|a_mark_paid)$/.test(req.query.a);
    if (write && req.method !== "POST") fail(405, "Gunakan POST.");
    send(res, 200, await fn(req));
  } catch (e) {
    const status = e instanceof HttpErr ? e.status : 500;
    if (status >= 500) console.error(e);
    send(res, status, { error: e.message || "Terjadi kesalahan." });
  }
}
