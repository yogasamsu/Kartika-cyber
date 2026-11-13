/* Tameng · gerbang login Google + pencatat aktivitas + pencatat kunjungan.
 *
 * Halaman dengan <html data-gate> wajib login bila server mengaktifkan login
 * (/api/config memberi clientId). Bila /api tidak ada (file://, laptop
 * air-gapped, server statis biasa), halaman langsung terbuka tanpa login dan
 * tanpa pencatatan: Tameng tetap jalan offline.
 *
 * API untuk halaman:
 *   tamengTrack(jenis, detail)  catat event (hanya terkirim bila sudah login)
 *   event "tameng:ready"        detail = {user|null, online:boolean}
 */
(function () {
  "use strict";
  const html = document.documentElement;
  const gated = html.hasAttribute("data-gate");
  const path = () => location.pathname + location.hash;

  /* ---------- ID pengunjung anonim (localStorage, bukan cookie) ---------- */
  let vid = "", baru = false;
  try {
    vid = localStorage.getItem("tameng_vid") || "";
    if (!/^[a-z0-9]{8,32}$/.test(vid)) {
      vid = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()) + Date.now()).replace(/[^a-z0-9]/gi, "").toLowerCase().slice(0, 24);
      localStorage.setItem("tameng_vid", vid); baru = true;
    }
  } catch { vid = Math.random().toString(36).slice(2, 14).padEnd(8, "0"); baru = true; }
  function visit() {
    fetch("/api/visit", { method: "POST", credentials: "same-origin", keepalive: true,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vid, baru, path: path(), referrer: document.referrer, layar: `${screen.width}x${screen.height}` }) }).catch(() => {});
  }

  /* ---------- antrean event ---------- */
  // Event yang terjadi sebelum status login diketahui ditahan dulu; dibuang bila
  // ternyata offline atau tidak login.
  let user = null, queue = [], online = false, settled = false;
  const t0 = Date.now();
  window.tamengTrack = function (type, data) {
    if (settled && (!online || !user)) return;
    queue.push({ type, data: data || null, path: path(), t: new Date().toISOString() });
    if (queue.length >= 20) flush();
  };
  function flush(beacon) {
    if (!user || !queue.length) return;
    const payload = JSON.stringify({ events: queue.splice(0) });
    if (beacon && navigator.sendBeacon) {
      navigator.sendBeacon("/api/track", new Blob([payload], { type: "text/plain" }));
    } else {
      fetch("/api/track", { method: "POST", credentials: "same-origin", keepalive: true,
        headers: { "Content-Type": "application/json" }, body: payload }).catch(() => {});
    }
  }
  setInterval(flush, 5000);
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      hiddenAt = Date.now();
      tamengTrack("halaman_ditinggal", { detik_aktif: Math.round((Date.now() - t0) / 1000) });
      flush(true);
    } else if (hiddenAt) {
      tamengTrack("halaman_kembali", { detik_pergi: Math.round((Date.now() - hiddenAt) / 1000) });
    }
  });

  function ready() {
    settled = true;
    if (!user) queue = [];
    html.classList.remove("auth-wait");
    document.dispatchEvent(new CustomEvent("tameng:ready", { detail: { user, online } }));
    if (user) {
      tamengTrack("buka_halaman", { referrer: document.referrer.slice(0, 120), layar: `${screen.width}x${screen.height}` });
      userBox();
    }
  }

  /* ---------- kotak pengguna (nama + keluar) ---------- */
  function userBox() {
    const box = document.getElementById("userBox");
    if (!box || !user) return;
    const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    box.innerHTML = `${user.picture ? `<img src="${esc(user.picture)}" alt="" referrerpolicy="no-referrer">` : ""}
      <span class="un" title="${esc(user.email)}">${esc(user.name)}</span><button type="button" id="logoutBtn">Keluar</button>`;
    box.hidden = false;
    document.getElementById("logoutBtn").addEventListener("click", async () => {
      flush();
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
      location.reload();
    });
  }

  /* ---------- gerbang login ---------- */
  function gate(clientId) {
    const g = document.createElement("div");
    g.className = "gate";
    g.innerHTML = `<div class="gate-card bracket">
      <svg class="gate-logo" viewBox="0 0 26 30"><path d="M13 1 L25 5 V15 C25 22 20 27 13 29 C6 27 1 22 1 15 V5 Z" fill="none" stroke="#ece8d4" stroke-width="1.5"/><path d="M7 12 L13 15 L19 12 M7 17 L13 20 L19 17" fill="none" stroke="#d4f74b" stroke-width="2"/></svg>
      <div class="lbl"><b>Akses terbatas</b> · Kartika Cyber Hackathon 2026</div>
      <h1 class="disp">Masuk ke pusat komando</h1>
      <p>Masuk dengan akun Google untuk mencoba dashboard, temuan, dan simulasi serangan Tameng.</p>
      <div id="gBtn" class="gate-btn"></div>
      <div class="gate-err" id="gErr" hidden></div>
      <p class="gate-note">Yang kami catat: nama, email, waktu masuk, perkiraan lokasi (negara/kota), jenis perangkat, serta menu dan simulasi yang Anda buka. Data ini hanya dipakai untuk melihat siapa yang sudah mencoba Tameng selama penilaian hackathon dan tidak dibagikan ke pihak lain.</p>
      <a class="gate-back" href="privasi.html">Kebijakan privasi</a> &nbsp;·&nbsp; <a class="gate-back" href="index.html">← Kembali ke beranda</a>
    </div>`;
    document.body.appendChild(g);
    html.classList.remove("auth-wait");
    html.classList.add("locked");
    const err = m => { const e = document.getElementById("gErr"); e.textContent = m; e.hidden = false; };
    const s = document.createElement("script");
    s.src = "https://accounts.google.com/gsi/client"; s.async = true;
    s.onerror = () => err("Tombol Google gagal dimuat. Periksa koneksi internet lalu muat ulang halaman.");
    s.onload = () => {
      google.accounts.id.initialize({
        client_id: clientId, ux_mode: "popup", auto_select: false, cancel_on_tap_outside: true,
        callback: async r => {
          const res = await fetch("/api/login", { method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ credential: r.credential, halaman: path(), vid }) }).catch(() => null);
          if (!res || !res.ok) return err("Login gagal diverifikasi. Coba lagi.");
          user = (await res.json()).user;
          g.remove(); html.classList.remove("locked");
          ready();
        },
      });
      google.accounts.id.renderButton(document.getElementById("gBtn"),
        { theme: "filled_black", size: "large", text: "signin_with", shape: "rectangular", locale: "id", width: 280 });
    };
    document.head.appendChild(s);
  }

  /* ---------- mulai ---------- */
  async function getJson(url) {
    const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), 6000);
    try {
      const r = await fetch(url, { credentials: "same-origin", signal: ctl.signal, cache: "no-store" });
      const ct = r.headers.get("content-type") || "";
      return { status: r.status, data: ct.includes("json") ? await r.json() : null };
    } finally { clearTimeout(to); }
  }
  (async () => {
    let cfg = null;
    try { cfg = (await getJson("/api/config")).data; } catch {}
    if (!cfg || !cfg.clientId) return ready();            // offline: tanpa login, tanpa pencatatan
    online = true;
    visit();                                               // satu kunjungan per muat halaman
    let me = null;
    try { me = await getJson("/api/me"); } catch {}
    if (me && me.status === 200 && me.data && me.data.user) { user = me.data.user; return ready(); }
    if (gated) return gate(cfg.clientId);
    ready();                                               // halaman publik: tidak dikunci
  })();
})();
