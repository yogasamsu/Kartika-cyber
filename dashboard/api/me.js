const { session, json } = require("./_lib");

module.exports = (req, res) => {
  const u = session(req);
  if (!u) return json(res, 200, { user: null });   // 200 supaya konsol pengunjung bersih
  json(res, 200, { user: { email: u.email, name: u.name, picture: u.picture } });
};
