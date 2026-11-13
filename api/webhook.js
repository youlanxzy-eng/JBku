// JB KU · Sistem Reseller · penerima notifikasi pembayaran
//   POST /api/webhook?key=WEBHOOK_KEY
//   Body dari MacroDroid (JSON):  {"app":"[notification_app_name]","title":"[notification_title]","text":"[notification]"}
//   Teks biasa juga diterima.
//   Nominal di teks (mis. "Rp50.147") dicocokkan dengan order pending yang nominal uniknya sama,
//   lalu akun pembeli dibuat otomatis.
import crypto from "node:crypto";
import { sb, enc, parseAmounts, fulfill, body, send } from "../lib/rs.js";

const GRACE_MIN = 60; // pembayaran yang telat ≤ 60 menit setelah order kedaluwarsa tetap diterima

function keyOk(req) {
  const want = process.env.WEBHOOK_KEY || "";
  const got = String(req.query.key || req.headers["x-webhook-key"] || "");
  if (!want || got.length !== want.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want));
}

export default async function handler(req, res) {
  if (req.method === "GET") return send(res, 200, { ok: true, hint: "Kirim POST berisi teks notifikasi." });
  if (req.method !== "POST") return send(res, 405, { error: "Gunakan POST." });
  if (!keyOk(req)) return send(res, 401, { error: "Kunci webhook salah." });

  const b = body(req);
  const app = String(b.app || b.package || "").slice(0, 80);
  const raw = [b.title, b.text, b.message, b.body, b.notification].filter(Boolean).join(" · ").slice(0, 600)
    || JSON.stringify(b).slice(0, 600);

  // abaikan notifikasi dari aplikasi lain jika WEBHOOK_APPS diisi (mis. "DANA Bisnis,GoBiz")
  const allow = String(process.env.WEBHOOK_APPS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const amounts = parseAmounts(raw);
  const log = async (result, order_id = null) => {
    const r = await sb("rs_webhook_log", { method: "POST", prefer: "return=representation", body: { source: app || null, raw, amounts, order_id, result } });
    return r && r[0] ? r[0].id : null;
  };

  try {
    if (allow.length && app && !allow.some((a) => app.toLowerCase().includes(a))) {
      await log("diabaikan: aplikasi " + app);
      return send(res, 200, { ok: true, matched: false, reason: "aplikasi diabaikan" });
    }
    // notifikasi duplikat (MacroDroid kadang mengirim 2x)
    const since = new Date(Date.now() - 10 * 60e3).toISOString();
    const dup = await sb(`rs_webhook_log?select=id&raw=eq.${enc(raw)}&received_at=gte.${enc(since)}&result=like.lunas*&limit=1`);
    if (dup.length) {
      await log("duplikat");
      return send(res, 200, { ok: true, matched: false, reason: "duplikat" });
    }
    if (!amounts.length) {
      await log("tidak ada nominal");
      return send(res, 200, { ok: true, matched: false, reason: "tidak ada nominal" });
    }

    const graceFrom = new Date(Date.now() - GRACE_MIN * 60e3).toISOString();
    const list = amounts.join(",");
    let cand = await sb(`rs_orders?select=id,amount,status,expires_at&amount=in.(${list})&status=eq.pending&order=created_at.asc&limit=1`);
    if (!cand.length)
      cand = await sb(`rs_orders?select=id,amount,status,expires_at&amount=in.(${list})&status=eq.expired&expires_at=gte.${enc(graceFrom)}&order=expires_at.desc&limit=1`);
    if (!cand.length) {
      await log("tidak ada order dengan nominal " + amounts.join("/"));
      return send(res, 200, { ok: true, matched: false, reason: "tidak cocok" });
    }

    const o = cand[0];
    const wid = await log("diproses", o.id);
    const f = await fulfill(o, "webhook", wid);
    await sb(`rs_webhook_log?id=eq.${wid}`, {
      method: "PATCH", prefer: "return=minimal",
      body: { result: f.ok ? "lunas · akun dibuat" : "gagal: " + f.reason },
    });
    return send(res, 200, { ok: true, matched: true, created: f.ok, order: o.id });
  } catch (e) {
    console.error(e);
    try { await log("error: " + String(e.message || e).slice(0, 200)); } catch {}
    return send(res, 500, { error: "Gagal memproses." });
  }
}
