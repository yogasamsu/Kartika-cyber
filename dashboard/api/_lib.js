// Pustaka bersama fungsi /api (berkas berawalan _ tidak jadi rute di Vercel).
// Sesi disimpan di cookie HttpOnly bertanda tangan HMAC, tanpa database.
// Catatan aktivitas dikirim ke Google Apps Script (SHEET_WEBHOOK) yang menulis
// ke Google Sheet; bila belum diatur, catatan hanya masuk ke log Vercel.
const crypto = require("crypto");

const COOKIE = "tameng_s";
const MAX_AGE = 7 * 24 * 3600;

const b64u = buf => Buffer.from(buf).toString("base64url");
const secret = () => process.env.SESSION_SECRET || "";

function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verify(token) {
  if (!token || !secret()) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const want = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return p.exp > Date.now() / 1000 ? p : null;
  } catch { return null; }
}

function cookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(c => {
    const i = c.indexOf("=");
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

const session = req => verify(cookies(req)[COOKIE]);

function setSession(res, payload) {
  res.setHeader("Set-Cookie", `${COOKIE}=${sign(payload)}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`);
}
function clearSession(res) {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

function body(req) {
  const b = req.body;
  if (b && typeof b === "object" && !Buffer.isBuffer(b)) return b;
  try { return JSON.parse(Buffer.isBuffer(b) ? b.toString("utf8") : b || "{}"); } catch { return {}; }
}

function device(ua = "") {
  const kind = /Mobi|Android|iPhone/i.test(ua) ? "Ponsel" : /iPad|Tablet/i.test(ua) ? "Tablet" : "Desktop";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Lainnya";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) && !/iPhone|iPad/.test(ua) ? "macOS"
    : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return [kind, br, os].filter(Boolean).join(" · ");
}

// Konteks permintaan yang ikut dicatat: lokasi kasar dari header Vercel dan jenis perangkat.
function ctx(req) {
  const h = req.headers;
  let city = h["x-vercel-ip-city"] || "";
  try { city = decodeURIComponent(city); } catch {}
  return { negara: h["x-vercel-ip-country"] || "", kota: city, perangkat: device(h["user-agent"]) };
}

async function record(rows) {
  if (!rows.length) return;
  const url = process.env.SHEET_WEBHOOK;
  if (!url) { console.log("[tameng-track]", JSON.stringify(rows)); return; }
  try {
    const r = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: process.env.SHEET_SECRET || "", rows }), redirect: "follow",
    });
    const txt = await r.text();
    let ok = r.ok;
    try { ok = ok && JSON.parse(txt).ok !== false; } catch { ok = false; }
    if (!ok) console.error("[tameng-track] webhook menolak", r.status, txt.slice(0, 160), JSON.stringify(rows));
  } catch (e) { console.error("[tameng-track] webhook gagal", e.message); }
}

// Satu baris catatan untuk Sheet.
function row(user, c, jenis, detail, halaman, t) {
  return {
    t: t || new Date().toISOString(), email: user.email, nama: user.name, sesi: user.sid,
    jenis: String(jenis).slice(0, 40), detail: detail ? JSON.stringify(detail).slice(0, 500) : "",
    halaman: String(halaman || "").slice(0, 80), ...c,
  };
}

function json(res, code, obj) {
  res.statusCode = code;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}

module.exports = { session, setSession, clearSession, body, ctx, record, row, json, MAX_AGE };
