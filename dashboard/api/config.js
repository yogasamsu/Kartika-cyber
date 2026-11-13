// Memberi tahu halaman apakah login Google aktif. Tanpa GOOGLE_CLIENT_ID dan
// SESSION_SECRET, gerbang login dimatikan (mode offline/air-gapped).
const { json } = require("./_lib");

module.exports = (req, res) => {
  const on = !!(process.env.GOOGLE_CLIENT_ID && process.env.SESSION_SECRET);
  json(res, 200, { clientId: on ? process.env.GOOGLE_CLIENT_ID : null });
};
