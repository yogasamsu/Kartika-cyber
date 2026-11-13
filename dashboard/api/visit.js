// Mencatat kunjungan halaman, termasuk pengunjung yang belum login (pengganti
// Vercel Web Analytics). Pengunjung dikenali lewat ID acak di localStorage, bukan
// cookie pelacak; bila sudah login, emailnya ikut dicatat.
const { session, body, ctx, record, json } = require("./_lib");

const VID = /^[a-z0-9]{8,32}$/;
const clip = (s, n) => String(s || "").slice(0, n);

module.exports = async (req, res) => {
  if (req.method !== "POST") return json(res, 405, { error: "POST saja" });
  // Tolak kiriman dari situs lain supaya Sheet tidak mudah dibanjiri.
  const origin = req.headers.origin || "";
  if (origin && new URL(origin).host !== req.headers.host) return json(res, 403, { error: "asal tidak dikenal" });
  const b = body(req);
  if (!VID.test(b.vid || "")) return json(res, 400, { error: "vid tidak sah" });
  const u = session(req);
  let ref = clip(b.referrer, 200);
  try { const r = new URL(ref); ref = r.host === req.headers.host ? "(internal) " + r.pathname + r.hash : r.host + r.pathname; } catch { ref = ref ? ref : "(langsung)"; }
  await record([{
    t: new Date().toISOString(), jenis: "kunjungan", pengunjung: b.vid,
    email: u ? u.email : "", nama: u ? u.name : "", sesi: u ? u.sid : "",
    halaman: clip(b.path, 80), rujukan: clip(ref, 160), layar: clip(b.layar, 20),
    baru: !!b.baru, ...ctx(req),
  }]);
  json(res, 200, { ok: true });
};
