const { session, clearSession, ctx, record, row, json } = require("./_lib");

module.exports = async (req, res) => {
  if (req.method !== "POST") return json(res, 405, { error: "POST saja" });
  const u = session(req);
  clearSession(res);
  if (u) await record([row(u, ctx(req), "logout")]);
  json(res, 200, { ok: true });
};
