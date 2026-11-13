// Menerima ID token dari tombol "Sign in with Google", memverifikasinya ke
// Google, lalu membuat sesi cookie dan mencatat login ke Sheet.
const crypto = require("crypto");
const { setSession, body, ctx, record, row, json, MAX_AGE } = require("./_lib");

const ISS = new Set(["accounts.google.com", "https://accounts.google.com"]);

async function verifyGoogle(idToken) {
  const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken));
  if (!r.ok) return null;
  const t = await r.json();
  if (t.aud !== process.env.GOOGLE_CLIENT_ID || !ISS.has(t.iss)) return null;
  if (String(t.email_verified) !== "true" || +t.exp < Date.now() / 1000) return null;
  return t;
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return json(res, 405, { error: "POST saja" });
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.SESSION_SECRET) return json(res, 503, { error: "Login belum dikonfigurasi" });
  const { credential, halaman, vid } = body(req);
  if (!credential) return json(res, 400, { error: "credential kosong" });
  const t = await verifyGoogle(credential).catch(() => null);
  if (!t) return json(res, 401, { error: "Token Google tidak sah" });
  const now = Math.floor(Date.now() / 1000);
  const user = { sub: t.sub, email: t.email, name: t.name || t.email, picture: t.picture || "",
    sid: crypto.randomBytes(6).toString("hex"), iat: now, exp: now + MAX_AGE };
  setSession(res, user);
  const pengunjung = /^[a-z0-9]{8,32}$/.test(vid || "") ? vid : "";
  await record([{ ...row(user, ctx(req), "login", null, halaman), pengunjung }]);
  json(res, 200, { user: { email: user.email, name: user.name, picture: user.picture } });
};
