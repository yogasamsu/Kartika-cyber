/**
 * Tameng · pencatat penguji ke Google Sheet.
 *
 * Pasang: buka Google Sheet baru → Ekstensi → Apps Script → tempel berkas ini
 * → ganti RAHASIA → Terapkan → Penerapan baru → jenis "Aplikasi web",
 * Jalankan sebagai: Saya, Akses: Siapa saja → salin URL /exec ke env Vercel
 * SHEET_WEBHOOK, dan RAHASIA ke SHEET_SECRET.
 *
 * Memperbarui skrip ini: tempel ulang → Terapkan → Kelola penerapan → ikon
 * pensil → Versi: "Versi baru" → Terapkan. (Jangan "Penerapan baru", karena URL
 * /exec akan berganti.)
 *
 * Tab yang dibuat otomatis:
 *   Ringkasan  angka total: kunjungan, pengunjung unik, penguji login, simulasi
 *   Kunjungan  satu baris per muat halaman, termasuk pengunjung belum login
 *   Penguji    satu baris per email: kapan pertama/terakhir aktif, jumlah login,
 *              simulasi dijalankan/selesai, laporan diunduh, menu dibuka
 *   Aktivitas  satu baris per event (login, buka_menu, simulasi_mulai, ...)
 */
const RAHASIA = "GANTI_DENGAN_SHEET_SECRET";
const ZONA = "Asia/Jakarta";

const KOLOM_AKT = ["Waktu (WIB)", "Email", "Nama", "Kejadian", "Detail", "Halaman", "Negara", "Kota", "Perangkat", "Sesi"];
const KOLOM_USR = ["Email", "Nama", "Pertama masuk (WIB)", "Terakhir aktif (WIB)", "Jumlah login",
  "Simulasi dimulai", "Simulasi selesai", "Laporan diunduh", "Menu dibuka", "Negara", "Kota", "Perangkat", "ID pengunjung"];
const KOLOM_KJG = ["Waktu (WIB)", "Pengunjung", "Pengunjung baru", "Email", "Nama", "Halaman", "Rujukan",
  "Negara", "Kota", "Perangkat", "Layar"];

function doPost(e) {
  let body;
  try { body = JSON.parse(e.postData.contents); } catch (err) { return out({ ok: false, error: "json" }); }
  if (body.secret !== RAHASIA) return out({ ok: false, error: "rahasia" });
  const semua = (body.rows || []).slice(0, 50);
  if (!semua.length) return out({ ok: true, n: 0 });
  const kunjungan = semua.filter(r => r.jenis === "kunjungan");
  const rows = semua.filter(r => r.jenis !== "kunjungan");

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ringkasan(ss);
    const waktu = r => Utilities.formatDate(new Date(r.t || Date.now()), ZONA, "yyyy-MM-dd HH:mm:ss");
    if (kunjungan.length) {
      const kj = tab(ss, "Kunjungan", KOLOM_KJG);
      kj.getRange(kj.getLastRow() + 1, 1, kunjungan.length, KOLOM_KJG.length).setValues(kunjungan.map(r => [
        waktu(r), r.pengunjung || "", r.baru ? "ya" : "", r.email || "", r.nama || "", r.halaman || "", r.rujukan || "",
        r.negara || "", r.kota || "", r.perangkat || "", r.layar || ""]));
    }
    if (!rows.length) return out({ ok: true, n: semua.length });
    const akt = tab(ss, "Aktivitas", KOLOM_AKT);
    const usr = tab(ss, "Penguji", KOLOM_USR);

    akt.getRange(akt.getLastRow() + 1, 1, rows.length, KOLOM_AKT.length).setValues(rows.map(r => [
      waktu(r), r.email || "", r.nama || "", r.jenis || "", r.detail || "", r.halaman || "",
      r.negara || "", r.kota || "", r.perangkat || "", r.sesi || ""]));

    // Ringkasan per penguji.
    const data = usr.getLastRow() > 1 ? usr.getRange(2, 1, usr.getLastRow() - 1, KOLOM_USR.length).getValues() : [];
    const idx = {};
    data.forEach((d, i) => idx[String(d[0]).toLowerCase()] = i);
    rows.forEach(r => {
      if (!r.email) return;
      const key = r.email.toLowerCase();
      let i = idx[key];
      if (i === undefined) {
        data.push([r.email, r.nama || "", waktu(r), waktu(r), 0, 0, 0, 0, 0, "", "", "", ""]);
        i = idx[key] = data.length - 1;
      }
      const d = data[i];
      d[1] = r.nama || d[1];
      d[3] = waktu(r);
      if (r.jenis === "login") d[4]++;
      if (r.jenis === "simulasi_mulai") d[5]++;
      if (r.jenis === "simulasi_selesai") d[6]++;
      if (r.jenis === "unduh_laporan") d[7]++;
      if (r.jenis === "buka_menu") d[8]++;
      if (r.negara) d[9] = r.negara;
      if (r.kota) d[10] = r.kota;
      if (r.perangkat) d[11] = r.perangkat;
      while (d.length < KOLOM_USR.length) d.push("");
      if (r.pengunjung && String(d[12]).indexOf(r.pengunjung) < 0) d[12] = d[12] ? d[12] + ", " + r.pengunjung : r.pengunjung;
    });
    if (data.length) usr.getRange(2, 1, data.length, KOLOM_USR.length).setValues(data);
    return out({ ok: true, n: semua.length });
  } finally {
    lock.releaseLock();
  }
}

// Buka URL /exec di browser untuk cek bahwa skrip hidup.
function doGet() { return out({ ok: true, layanan: "pencatat Tameng" }); }

function tab(ss, nama, kolom) {
  let sh = ss.getSheetByName(nama);
  if (!sh) sh = ss.insertSheet(nama);
  // Buat atau lengkapi baris judul (mis. kolom baru setelah skrip diperbarui).
  const ada = sh.getLastColumn() ? sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0].join("|") : "";
  if (ada !== kolom.join("|")) {
    sh.getRange(1, 1, 1, kolom.length).setValues([kolom]).setFontWeight("bold");
    sh.setFrozenRows(1);
  }
  return sh;
}

// Tab Ringkasan berisi rumus, dibuat sekali saja.
function ringkasan(ss) {
  if (ss.getSheetByName("Ringkasan")) return;
  tab(ss, "Kunjungan", KOLOM_KJG); tab(ss, "Penguji", KOLOM_USR); tab(ss, "Aktivitas", KOLOM_AKT);
  const sh = ss.insertSheet("Ringkasan", 0);
  sh.getRange(1, 1, 9, 2).setValues([
    ["Angka", "Nilai"],
    ["Total kunjungan halaman", "=COUNTA(Kunjungan!A2:A)"],
    ["Pengunjung unik", "=COUNTUNIQUE(Kunjungan!B2:B)"],
    ["Kunjungan hari ini", "=SUMPRODUCT(--(LEFT(TEXT(Kunjungan!A2:A, \"yyyy-mm-dd\"), 10) = TEXT(TODAY(), \"yyyy-mm-dd\")))"],
    ["Penguji yang login", "=COUNTA(Penguji!A2:A)"],
    ["Simulasi dimulai", "=SUM(Penguji!F2:F)"],
    ["Simulasi selesai", "=SUM(Penguji!G2:G)"],
    ["Laporan diunduh", "=SUM(Penguji!H2:H)"],
    ["Kunjungan per halaman", "=QUERY(Kunjungan!F2:F, \"select F, count(F) where F <> '' group by F order by count(F) desc label count(F) ''\", 0)"],
  ]);
  sh.getRange(1, 1, 1, 2).setFontWeight("bold");
  sh.setColumnWidth(1, 220);
}

function out(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
