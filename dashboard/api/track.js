// Menerima kumpulan event aktivitas dari halaman (fetch atau sendBeacon) dan
// meneruskannya ke Sheet. Hanya pengguna yang sudah login yang dicatat.
const { session, body, ctx, record, row, json } = require("./_lib");

const JENIS = /^[a-z_]{2,40}$/;

module.exports = async (req, res) => {
  if (req.method !== "POST") return json(res, 405, { error: "POST saja" });
  const u = session(req);
  if (!u) return json(res, 401, { error: "Belum login" });
  const { events } = body(req);
  if (!Array.isArray(events)) return json(res, 400, { error: "events harus array" });
  const c = ctx(req), now = Date.now();
  const rows = events.slice(0, 50).filter(e => e && JENIS.test(e.type)).map(e => {
    const t = Date.parse(e.t);
    const ok = t && Math.abs(now - t) < 24 * 3600 * 1000;
    return row(u, c, e.type, e.data, e.path, ok ? new Date(t).toISOString() : undefined);
  });
  await record(rows);
  json(res, 200, { ok: true, n: rows.length });
};
