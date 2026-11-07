// Deck Tameng, versi alur "masalah pengguna dulu" (12 slide + 2 lampiran).
// Jalankan: PPTX_SKILL=<dir skill pptx> NODE_PATH=<node_modules> node build-deck.js out.pptx
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");
const { applyTheme } = require(process.env.PPTX_SKILL + "/scripts/apply_theme.js");

const OUT = process.argv[2];

const THEME = {
  name: "Tameng Ops",
  headFontFace: "Calibri",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0F1B26", lt1: "FFFFFF", dk2: "33475B", lt2: "EDF2F6",
    accent1: "0B7F9C",   // IT
    accent2: "D97A00",   // OT
    accent3: "C8312F",   // kritis / masalah
    accent4: "2E8B57",   // aman / sudah
    accent5: "6B7C8C",   // redup
    accent6: "3CC8E6",   // sian terang untuk latar gelap
    hlink: "0B7F9C", folHlink: "6B7C8C",
  },
};
const H = THEME.colors;

async function icon(Comp, hex, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + hex, size }));
  const buf = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";            // 13.333" x 7.5"
  pres.title = "Tameng (Tangkal Ancaman Mandiri lewat Edukasi, Notifikasi, dan Gerak cepat): pendamping analis insiden IT/OT";
  pres.author = "Tim Tameng";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const C = pres.SchemeColor;
  const W = 13.333, M = 0.6;

  // ---------- Layout ----------
  pres.defineSlideMaster({
    title: "JUDUL_GELAP",
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 1.7, w: 8.2, h: 1.4,
          fontSize: 66, bold: true, color: C.background1, valign: "bottom", align: "left", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: M, y: 3.25, w: 8.2, h: 1.9,
          fontSize: 24, color: C.accent6, valign: "top", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "KONTEN",
    background: { color: C.background1 },
    margin: [0.5, M, 0.6, M],
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 0.4, w: W - 2 * M, h: 1.1,
          fontSize: 30, bold: true, color: C.text1, valign: "top", align: "left", margin: 0 }, text: "" } },
      { text: { text: "Tameng · Kartika Cyber Hackathon 2026",
          options: { x: M, y: 7.0, w: 6, h: 0.3, fontSize: 10, color: C.accent5, margin: 0 } } },
    ],
    slideNumber: { x: W - M - 0.6, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });
  pres.defineSlideMaster({
    title: "GELAP",
    background: { color: C.text1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 0.5, w: W - 2 * M, h: 1.1,
          fontSize: 32, bold: true, color: C.background1, valign: "top", align: "left", margin: 0 }, text: "" } },
    ],
    slideNumber: { x: W - M - 0.6, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: C.accent5, align: "right" },
  });

  // ---------- Helper ----------
  const ic = {};
  for (const [k, comp, hex] of [
    ["skull", fa.FaUserSecret, H.lt1], ["pc", fa.FaDesktop, H.lt1], ["server", fa.FaServer, H.lt1],
    ["plc", fa.FaBolt, H.lt1], ["lock", fa.FaLock, H.lt1], ["user", fa.FaUserClock, H.lt1],
    ["eye", fa.FaEye, H.lt1], ["filter", fa.FaFilter, H.lt1], ["link", fa.FaProjectDiagram, H.lt1],
    ["warn", fa.FaExclamationTriangle, H.lt1], ["hand", fa.FaHandPaper, H.lt1], ["file", fa.FaFileAlt, H.lt1],
    ["db", fa.FaDatabase, H.lt1], ["sitemap", fa.FaSitemap, H.lt1], ["robot", fa.FaRobot, H.lt1],
    ["check", fa.FaCheckCircle, H.lt1], ["book", fa.FaBookOpen, H.lt1], ["dash", fa.FaDesktop, H.lt1],
    ["users", fa.FaUsers, H.lt1], ["list", fa.FaClipboardList, H.lt1], ["simple", fa.FaLayerGroup, H.lt1],
    ["easy", fa.FaLanguage, H.lt1], ["cheap", fa.FaLaptop, H.lt1], ["safe", fa.FaShieldAlt, H.lt1],
    ["wifi", fa.FaPlane, H.lt1], ["open", fa.FaCodeBranch, H.lt1], ["test", fa.FaCheckDouble, H.lt1],
    ["py", fa.FaPython, H.lt1], ["arrow", fa.FaArrowRight, H.accent5],
  ]) ic[k] = await icon(comp, hex);

  function badge(slide, key, x, y, d, fill, name) {
    slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { color: fill }, objectName: name + " lingkaran" });
    const p = d * 0.24;
    slide.addImage({ data: ic[key], x: x + p, y: y + p, w: d - 2 * p, h: d - 2 * p, objectName: name + " ikon" });
  }
  function card(slide, x, y, w, h, name, fill) {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.12,
      fill: { color: fill || C.background2 }, line: { color: fill || C.background2 }, objectName: name });
  }
  function text(slide, t, o) {
    slide.addText(t, Object.assign({ isTextBox: true, margin: 0, fontSize: 15, color: C.text1, valign: "top" }, o));
  }
  function pill(slide, x, y, w, h, t, fill, col, name, fs) {
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: h / 2, fill: { color: fill }, line: { color: fill }, objectName: name });
    text(slide, t, { x, y, w, h, fontSize: fs || 13, bold: true, color: col, align: "center", valign: "middle", objectName: name + " teks" });
  }
  const hdr = { bold: true, color: C.background1, fill: { color: C.text1 }, fontSize: 14 };
  const border = { type: "solid", pt: 0.75, color: "D5DDE4" };

  // Enam tahap journey dipakai di slide 3 dan 6
  const STAGES = [
    ["eye", "Memantau"], ["filter", "Memilah"], ["link", "Merangkai"],
    ["warn", "Menilai dampak"], ["hand", "Bertindak"], ["file", "Melapor"],
  ];
  const sw = 1.85, sg = (W - 2 * M - 6 * sw) / 5;   // lebar kolom tahap dan jarak

  // ---------- 1. Judul ----------
  pres.addSection({ title: "Pembuka" });
  let s = pres.addSlide({ masterName: "JUDUL_GELAP", sectionTitle: "Pembuka" });
  s.addText("Tameng", { placeholder: "title" });
  s.addText("Pendamping analis insiden IT/OT yang bekerja di dalam satuan, tanpa internet", { placeholder: "body" });
  text(s, "TANGKAL ANCAMAN MANDIRI LEWAT EDUKASI, NOTIFIKASI, DAN GERAK CEPAT", {
    x: M, y: 5.3, w: 8.6, h: 0.4, fontSize: 13, bold: true, color: C.accent6, charSpacing: 1, objectName: "Kepanjangan" });
  text(s, "Kartika Cyber Hackathon 2026 · Kategori Defensive Shield", {
    x: M, y: 6.55, w: 8, h: 0.4, fontSize: 14, color: C.accent5, objectName: "Acara" });
  const chain = [["skull", "Penyerang", C.accent3], ["pc", "PC staf", C.accent1], ["server", "Server file", C.accent1], ["plc", "PLC genset", C.accent2]];
  chain.forEach(([k, lbl, col], i) => {
    const y = 0.9 + i * 1.45;
    if (i > 0) s.addShape(pres.shapes.LINE, { x: 10.55, y: y - 0.55, w: 0, h: 0.5, line: { color: H.accent5, width: 2, dashType: "dash" }, objectName: "Penghubung " + i });
    badge(s, k, 10.0, y, 1.1, col, lbl);
    text(s, lbl, { x: 11.3, y: y + 0.35, w: 1.8, h: 0.4, fontSize: 14, color: C.background1, objectName: "Label " + lbl });
  });
  s.addNotes("Selamat pagi. Kami membawa Tameng, singkatan dari Tangkal Ancaman Mandiri lewat Edukasi, Notifikasi, dan Gerak cepat. Tameng adalah pendamping untuk analis yang menjaga keamanan siber satuan. Kami mulai bukan dari teknologinya, tetapi dari orang yang harus menghadapi serangan: analis jaga di satuan.");

  // ---------- 2. Masalah: orangnya ----------
  pres.addSection({ title: "Masalah" });
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Masalah" });
  s.addText("Satu analis jaga menerima 654 alert dalam 4 menit, dan hanya 13 yang benar-benar serangan", { placeholder: "title" });
  card(s, M, 1.85, 5.6, 4.15, "Kartu persona");
  badge(s, "user", M + 0.35, 2.15, 0.95, C.accent3, "Persona");
  text(s, "Analis jaga satuan", { x: M + 1.5, y: 2.2, w: 3.9, h: 0.45, fontSize: 20, bold: true, objectName: "Persona judul" });
  text(s, "sering masih junior", { x: M + 1.5, y: 2.65, w: 3.9, h: 0.4, fontSize: 15, color: C.text2, objectName: "Persona sub" });
  const persona = [
    "Berjaga sendirian, kadang tengah malam",
    "Senior tidak selalu ada untuk ditanya",
    "Harus melapor ke komandan yang bukan orang teknis",
    "Tidak boleh memakai AI cloud untuk data militer",
  ];
  text(s, persona.map((t, i) => ({ text: t, options: { bullet: true, breakLine: i < persona.length - 1 } })),
    { x: M + 0.4, y: 3.45, w: 4.9, h: 2.4, fontSize: 16, color: C.text2, paraSpaceAfter: 8, objectName: "Persona isi" });
  const stats = [
    ["654", "alert dalam simulasi serangan 4 menit di lab kami", C.accent1],
    ["13", "di antaranya bagian dari serangan; sisanya pemeriksaan rutin", C.accent3],
    ["1", "orang yang harus menemukan, merangkai, dan melaporkannya", C.accent2],
  ];
  stats.forEach(([n, lbl, col], i) => {
    const y = 1.85 + i * 1.42;
    text(s, n, { x: 6.7, y, w: 1.7, h: 1.0, fontSize: 54, bold: true, color: col, valign: "middle", objectName: "Angka " + (i + 1) });
    text(s, lbl, { x: 8.5, y, w: W - M - 8.5, h: 1.0, fontSize: 17, color: C.text2, valign: "middle", objectName: "Keterangan " + (i + 1) });
  });
  text(s, "Konteks nasional: BSSN mencatat 5,2 miliar anomali trafik ke Indonesia (Jan–Nov 2025); malware terbanyak menyasar CCTV dan router. Sumber: BSSN via Investortrust dan Bisnis.com.",
    { x: M, y: 6.2, w: W - 2 * M, h: 0.5, fontSize: 12, color: C.accent5, objectName: "Sumber" });
  s.addNotes("Bayangkan analis jaga di satuan. Sering masih junior, berjaga sendirian, kadang tengah malam. Dalam simulasi empat menit di lab kami, sistem deteksi mengeluarkan 654 alert. Hanya tiga belas yang bagian dari serangan. Ia harus menemukannya, merangkainya, lalu melapor ke komandan. Dan ia tidak boleh minta bantuan AI cloud, karena ini data militer.");

  // ---------- 3. Journey: titik sakit ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Masalah" });
  s.addText("Dari alert pertama sampai laporan, analis junior tersendat di tahap yang butuh jam terbang", { placeholder: "title" });
  const pains = [
    "Ratusan baris per menit; IT dan OT di layar berbeda",
    "654 alert, 13 serangan: mana yang penting?",
    "Menyambung login SSH, pencurian hash, gerak lateral, dan Modbus dari dua sistem",
    "Apakah \"Modbus write\" berarti genset mati?",
    "SOP terlalu umum, tidak menyebut host dan akun yang kena",
    "Menulis laporan lama; istilah teknis membingungkan komandan",
  ];
  STAGES.forEach(([k, t], i) => {
    const x = M + i * (sw + sg);
    badge(s, k, x + (sw - 0.85) / 2, 1.85, 0.85, i === 0 ? C.accent5 : C.accent3, t);
    text(s, (i + 1) + ". " + t, { x, y: 2.85, w: sw, h: 0.4, fontSize: 16, bold: true, align: "center", objectName: "Tahap " + t });
    card(s, x, 3.4, sw, 2.0, "Kartu sakit " + t, i === 0 ? C.background2 : "FBE3E2");
    text(s, pains[i], { x: x + 0.15, y: 3.55, w: sw - 0.3, h: 1.75, fontSize: 14, color: C.text1, objectName: "Sakit " + t });
    if (i < 5) s.addImage({ data: ic.arrow, x: x + sw + (sg - 0.22) / 2, y: 2.17, w: 0.22, h: 0.22, objectName: "Panah tahap " + (i + 1) });
  });
  const bx = M + (sw + sg);
  pill(s, bx, 5.65, W - M - bx, 0.5, "Tahap 2–6 biasanya harus menunggu analis senior", C.accent3, C.background1, "Label senior", 15);
  text(s, "Alur kerja disusun dari riset dan skenario lab tim; belum divalidasi lewat wawancara analis satuan.",
    { x: M, y: 6.4, w: W - 2 * M, h: 0.35, fontSize: 12, color: C.accent5, objectName: "Catatan asumsi" });
  s.addNotes("Kami petakan perjalanan analis dari alert pertama sampai laporan. Memantau masih bisa dikerjakan siapa saja. Tetapi memilah, merangkai cerita serangan, menilai dampak, menentukan tindakan, dan menulis laporan, semuanya butuh jam terbang. Di situlah analis junior tersendat dan biasanya harus menunggu senior.");

  // ---------- 4. Solusi saat ini ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Masalah" });
  s.addText("Alat yang ada kuat di deteksi, tetapi tahap yang butuh pengalaman masih dikerjakan manual", { placeholder: "title" });
  const r4 = (a, b, c, d) => [{ text: a, options: { bold: true } }, { text: b }, { text: c, options: { color: C.accent4 } }, { text: d, options: { color: C.accent3 } }];
  s.addTable([
    [{ text: "Tahap", options: hdr }, { text: "Solusi hari ini", options: hdr }, { text: "Bagusnya", options: hdr }, { text: "Kurangnya", options: hdr }],
    r4("Memantau", "Dashboard Wazuh/Kibana, layar vendor OT", "Gratis, real-time", "Banjir alert; IT dan OT terpisah"),
    r4("Memilah", "Baca log manual; copilot AI cloud", "Akurat di tangan ahli; copilot cepat", "Butuh jam terbang; AI cloud dilarang untuk data militer"),
    r4("Merangkai", "Timeline manual di Excel", "Fleksibel dan detail", "Berjam-jam; jejak IT→OT mudah terputus"),
    r4("Menilai dampak", "Telepon teknisi, tanya atasan", "Dapat konteks dari yang paham", "Malam hari orangnya tidak ada"),
    r4("Bertindak", "SOP cetak, edaran", "Sesuai aturan satuan", "Terlalu umum, tanpa urutan langkah"),
    r4("Melapor", "Word, WhatsApp", "Bebas format", "Lama; mutu beda-beda; WhatsApp lewat server asing"),
  ], { x: M, y: 1.8, w: W - 2 * M, colW: [1.9, 3.5, 3.0, W - 2 * M - 8.4], fontSize: 14, color: C.text1,
       border, rowH: 0.62, valign: "middle", margin: [0.06, 0.12, 0.06, 0.12], objectName: "Tabel solusi saat ini" });
  s.addNotes("Kami tidak bilang alat yang ada buruk. Wazuh dan Suricata gratis dan andal untuk deteksi. Copilot AI cepat. SOP sesuai aturan. Masalahnya, tahap yang butuh pengalaman tetap dikerjakan manual, dan satu-satunya alat yang bisa membantu, AI cloud, tidak boleh dipakai.");

  // ---------- 5. Proposisi ----------
  pres.addSection({ title: "Solusi" });
  s = pres.addSlide({ masterName: "GELAP", sectionTitle: "Solusi" });
  s.addText("Dengan Tameng, analis junior bisa menangani insiden yang biasanya harus menunggu analis senior", { placeholder: "title" });
  const pillars = [
    ["simple", "Lebih sederhana", "Satu laporan insiden dari Wazuh dan Suricata, bukan 3–4 layar terpisah"],
    ["easy", "Lebih mudah", "Bahasa Indonesia, dampak yang jelas, dan langkah yang menyebut host serta akun"],
    ["cheap", "Lebih murah", "Satu laptop 16 GB dan perangkat lunak open-source, tanpa lisensi"],
    ["safe", "Lebih aman", "Berjalan offline; tidak ada data yang keluar dari jaringan satuan"],
  ];
  pillars.forEach(([k, t, d], i) => {
    const x = M + i * 3.08, y = 2.3, w = 2.83;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 3.3, rectRadius: 0.12, fill: { color: "1B2B3A" }, line: { color: "1B2B3A" }, objectName: "Pilar " + t });
    badge(s, k, x + 0.3, y + 0.3, 0.85, C.accent6, t);
    text(s, t, { x: x + 0.3, y: y + 1.35, w: w - 0.6, h: 0.45, fontSize: 19, bold: true, color: C.background1, objectName: "Pilar judul " + t });
    text(s, d, { x: x + 0.3, y: y + 1.85, w: w - 0.6, h: 1.35, fontSize: 15, color: "C9D4DD", objectName: "Pilar isi " + t });
  });
  text(s, "Tameng tidak menggantikan Wazuh, Suricata, atau analisnya. Tameng membantu orang yang menjaganya.",
    { x: M, y: 6.0, w: W - 2 * M, h: 0.5, fontSize: 17, bold: true, color: C.accent6, objectName: "Penegas" });
  s.addNotes("Proposisi kami satu kalimat: dengan Tameng, analis junior bisa menangani insiden yang biasanya harus menunggu analis senior. Caranya lebih sederhana, satu laporan dari semua sumber. Lebih mudah, bahasa Indonesia dengan langkah yang spesifik. Lebih murah, satu laptop. Dan lebih aman, tidak ada data yang keluar.");

  // ---------- 6. Journey dengan Tameng ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Solusi" });
  s.addText("Tameng mengerjakan bagian yang butuh jam terbang; analis tetap yang memutuskan", { placeholder: "title" });
  const helps = [
    ["Daftar insiden, bukan alert; IT dan OT dalam satu peta", 1],
    ["654 alert dipilah kode menjadi 1 insiden", 1],
    ["Kronologi IT→OT; tiap baris menunjuk ID bukti", 1],
    ["\"Genset DIMATIKAN\" atau \"DIBLOKIR, genset menyala\"", 1],
    ["Host, akun, dan IP yang perlu ditindak; checklist SOP menyusul", 0],
    ["Laporan bahasa Indonesia ±1,5 menit; ringkasan komandan menyusul", 0],
  ];
  STAGES.forEach(([k, t], i) => {
    const x = M + i * (sw + sg);
    badge(s, k, x + (sw - 0.85) / 2, 1.85, 0.85, C.accent1, t);
    text(s, (i + 1) + ". " + t, { x, y: 2.85, w: sw, h: 0.4, fontSize: 16, bold: true, align: "center", objectName: "Tahap T " + t });
    card(s, x, 3.4, sw, 2.0, "Kartu bantu " + t, "E3F1F5");
    text(s, helps[i][0], { x: x + 0.15, y: 3.55, w: sw - 0.3, h: 1.75, fontSize: 14, color: C.text1, objectName: "Bantu " + t });
    const done = helps[i][1];
    pill(s, x + 0.2, 5.6, sw - 0.4, 0.4, done ? "Sudah jalan" : "Sebagian", done ? C.accent4 : C.accent2, C.background1, "Status " + t, 13);
    if (i < 5) s.addImage({ data: ic.arrow, x: x + sw + (sg - 0.22) / 2, y: 2.17, w: 0.22, h: 0.22, objectName: "Panah T " + (i + 1) });
  });
  text(s, "Keputusan isolasi, reset akun, dan eskalasi tetap di tangan analis dan atasannya.",
    { x: M, y: 6.3, w: W - 2 * M, h: 0.4, fontSize: 14, color: C.accent5, objectName: "Catatan keputusan" });
  s.addNotes("Perjalanan yang sama, dengan Tameng. Analis tidak lagi melihat alert, tetapi insiden. Kode memilah dan merangkai kronologi dari IT sampai OT. Dampaknya ditulis jelas: genset mati, atau perintahnya diblokir. Empat tahap pertama sudah berjalan di purwarupa. Untuk tindakan dan laporan, rekomendasi dan laporan sudah ada; checklist SOP dan ringkasan khusus komandan sedang kami kerjakan. Keputusan tetap di tangan analis.");

  // ---------- 7. Cara kerja + penjaga ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Solusi" });
  s.addText("Di balik layar: kode menetapkan fakta, AI lokal hanya menulis, dan narasi yang mengarang ditolak", { placeholder: "title" });
  const steps = [
    ["db", "Bukti mentah", "Alert Wazuh (IT) dan Suricata (OT)", C.accent1],
    ["link", "Korelasi", "Rantai per pelaku dan host; derau dibuang", C.accent1],
    ["sitemap", "ATT&CK", "Teknik Enterprise + ICS dan tingkat bahaya", C.accent1],
    ["robot", "Narasi AI", "Qwen 2.5 7B lokal menulis ringkasan dan rekomendasi", C.accent2],
    ["check", "Validasi", "Fakta di luar bukti: narasi ditolak", C.accent4],
  ];
  const bw = 2.06, gap = 0.45;
  steps.forEach(([k, t, d, col], i) => {
    const x = M + i * (bw + gap), y = 1.85;
    card(s, x, y, bw, 2.45, "Langkah " + (i + 1));
    badge(s, k, x + (bw - 0.8) / 2, y + 0.25, 0.8, col, t);
    text(s, t, { x: x + 0.15, y: y + 1.15, w: bw - 0.3, h: 0.4, fontSize: 17, bold: true, align: "center", objectName: "Judul langkah " + (i + 1) });
    text(s, d, { x: x + 0.2, y: y + 1.6, w: bw - 0.4, h: 0.8, fontSize: 14, color: C.text2, align: "center", objectName: "Isi langkah " + (i + 1) });
    if (i < steps.length - 1) s.addImage({ data: ic.arrow, x: x + bw + 0.09, y: y + 0.52, w: 0.27, h: 0.27, objectName: "Panah langkah " + (i + 1) });
  });
  pill(s, M, 4.5, 3 * bw + 2 * gap, 0.45, "Kode deterministik: fakta pasti", C.accent1, C.background1, "Label kode", 14);
  pill(s, M + 3 * (bw + gap), 4.5, bw, 0.45, "AI lokal: narasi", C.accent2, C.background1, "Label AI", 14);
  pill(s, M + 4 * (bw + gap), 4.5, bw, 0.45, "Kode: penjaga", C.accent4, C.background1, "Label penjaga", 14);
  text(s, [{ text: "Kenapa analis junior bisa percaya laporannya: ", options: { bold: true } },
           { text: "narasi ditolak bila menyebut hal di luar bukti." }],
    { x: M, y: 5.3, w: W - 2 * M, h: 0.4, fontSize: 16, objectName: "Judul validasi" });
  ["IP", "penanda bukti", "waktu", "teknik ATT&CK", "nama host"].forEach((t, i) => {
    pill(s, M + i * 2.1, 5.85, 1.9, 0.48, t, "FBE3E2", C.accent3, "Chip " + t, 14);
  });
  text(s, "Bila ditolak, laporan memakai ringkasan cadangan dari kode.", { x: M + 10.6, y: 5.85, w: W - M - (M + 10.6), h: 0.5, fontSize: 12, color: C.accent5, valign: "middle", objectName: "Catatan cadangan" });
  s.addNotes("Di balik layar ada lima tahap. Tiga tahap pertama murni kode: membaca bukti, merangkai rantai, memetakan ke MITRE ATT&CK. AI lokal hanya menulis narasi. Lalu kode memeriksanya: kalau AI menyebut IP, waktu, atau host yang tidak ada di bukti, narasinya ditolak dan diganti ringkasan dari kode. Ini penting untuk analis junior: ia tidak punya pengalaman untuk menangkap kesalahan AI, jadi sistemnya yang harus menjaga.");

  // ---------- 8. Skenario ----------
  pres.addSection({ title: "Bukti" });
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Bukti" });
  s.addText("Uji di lab: penyerang menembus PC staf, lalu menyerang genset markas lewat Modbus", { placeholder: "title" });
  const nodes = [
    ["skull", "kali-ops", "10.10.5.90 · luar jaringan", C.accent3],
    ["pc", "pc-staf-07", "10.10.5.66 · workstation", C.accent1],
    ["server", "srv-file-01", "10.10.5.7 · server file", C.accent1],
    ["plc", "plc-genset-01", "10.10.5.20 · PLC genset", C.accent2],
  ];
  const edges = ["Brute force SSH, lalu login 'sertu'", "SSH lateral dari sesi penyerang", "Perintah Modbus: matikan genset"];
  nodes.forEach(([k, n, d, col], i) => {
    const cx = M + 0.6 + i * 3.25;
    badge(s, k, cx, 2.0, 1.3, col, n);
    text(s, n, { x: cx - 0.6, y: 3.45, w: 2.5, h: 0.45, fontSize: 18, bold: true, align: "center", objectName: "Nama " + n });
    text(s, d, { x: cx - 0.6, y: 3.9, w: 2.5, h: 0.4, fontSize: 13, color: C.text2, align: "center", objectName: "Detail " + n });
    if (i < 3) {
      s.addShape(pres.shapes.LINE, { x: cx + 1.45, y: 2.65, w: 1.65, h: 0, line: { color: H.accent5, width: 2, endArrowType: "triangle" }, objectName: "Alur " + (i + 1) });
      text(s, edges[i], { x: cx + 1.35, y: 1.75, w: 1.85, h: 0.75, fontSize: 12, color: C.text2, align: "center", valign: "bottom", objectName: "Label alur " + (i + 1) });
    }
  });
  card(s, M, 4.75, 5.95, 1.2, "Babak 1");
  text(s, [{ text: "Babak 1 · tanpa blokir: ", options: { bold: true, color: C.accent3 } },
           { text: "perintah Modbus sampai ke PLC, genset mati" }],
       { x: M + 0.3, y: 4.75, w: 5.4, h: 1.2, fontSize: 16, valign: "middle", objectName: "Teks babak 1" });
  card(s, M + 6.15, 4.75, W - 2 * M - 6.15, 1.2, "Babak 2");
  text(s, [{ text: "Babak 2 · mode blokir: ", options: { bold: true, color: C.accent4 } },
           { text: "perintah dari host tak sah dijatuhkan, genset tetap menyala" }],
       { x: M + 6.45, y: 4.75, w: W - 2 * M - 6.75, h: 1.2, fontSize: 16, valign: "middle", objectName: "Teks babak 2" });
  text(s, "Trafik nyata di lab Docker: SSH terekam Wazuh (IT), perintah Modbus tertangkap Suricata (OT).",
       { x: M, y: 6.2, w: W - 2 * M, h: 0.4, fontSize: 13, color: C.accent5, objectName: "Catatan lab" });
  s.addNotes("Untuk membuktikannya kami membangun lab di satu laptop. Penyerang menebak kata sandi SSH, masuk sebagai sertu, menyalin hash kata sandi, pindah ke server file, lalu mengirim perintah Modbus ke PLC genset. Kami jalankan dua babak: tanpa blokir, genset mati; dengan mode blokir, perintahnya dijatuhkan. Di kedua babak, yang kami ukur adalah apa yang diterima analis.");

  // ---------- 9. Hasil babak 1 ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Bukti" });
  s.addText("Babak 1: analis menerima 1 insiden dengan 13 bukti, bukan 654 alert", { placeholder: "title" });
  const big = [["654 → 1", "alert mentah menjadi satu insiden kritis", C.accent1],
               ["15 detik", "dari tebakan sandi pertama sampai genset mati, terangkai utuh", C.accent3],
               ["7", "teknik ATT&CK terpetakan: 5 Enterprise, 2 ICS", C.accent2]];
  big.forEach(([n, l, col], i) => {
    const y = 1.8 + i * 1.5;
    text(s, n, { x: M, y, w: 3.9, h: 0.75, fontSize: 40, bold: true, color: col, objectName: "Hasil angka " + (i + 1) });
    text(s, l, { x: M, y: y + 0.75, w: 3.9, h: 0.6, fontSize: 14, color: C.text2, objectName: "Hasil label " + (i + 1) });
  });
  const th = { bold: true, color: C.background1, fill: { color: C.text1 }, fontSize: 13 };
  const tr = (a, b, c, ot) => [{ text: a, options: { fontFace: "Courier New" } }, { text: b, options: ot ? { bold: true, color: C.accent3 } : {} }, { text: c, options: { fontFace: "Courier New" } }];
  s.addTable([
    [{ text: "Waktu", options: th }, { text: "Yang dibaca analis (ditetapkan kode)", options: th }, { text: "Bukti", options: th }],
    tr("10:19:26", "4 login SSH gagal dari 10.10.5.90", "W13 dst."),
    tr("10:19:37", "Login berhasil sebagai 'sertu'", "W18"),
    tr("10:19:37", "Eksekusi /tmp/exfil.sh", "W24"),
    tr("10:19:37", "Pembacaan /etc/shadow", "W22 dst."),
    tr("10:19:38", "SSH lateral ke srv-file-01", "W27"),
    tr("10:19:41", "Modbus mematikan genset", "S1", true),
  ], { x: 5.0, y: 1.85, w: W - M - 5.0, colW: [1.3, 4.45, W - M - 5.0 - 5.75], fontSize: 13, color: C.text1,
       border, rowH: 0.56, valign: "middle", margin: [0.05, 0.12, 0.05, 0.12], objectName: "Tabel kronologi" });
  text(s, "Uji lab 6 November 2026. Mayoritas dari 654 alert adalah pemeriksaan konfigurasi CIS; 27 pembacaan /etc/shadow yang berupa derau dibuang. Narasi qwen2.5:7b lolos validasi.",
       { x: 5.0, y: 5.95, w: W - M - 5.0, h: 0.6, fontSize: 12, color: C.accent5, objectName: "Catatan hasil" });
  s.addNotes("Hasil babak pertama, 6 November. Dari 654 alert, analis menerima satu insiden kritis dengan tiga belas bukti. Lima belas detik dari tebakan kata sandi pertama sampai genset mati, terangkai utuh dari IT ke OT. Setiap baris kronologi menunjuk ke penanda bukti, jadi analis bisa mengecek sumbernya sendiri.");

  // ---------- 10. Babak 2 ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Bukti" });
  s.addText("Babak 2, mode blokir: genset tetap menyala, dan analis tetap menerima cerita serangannya utuh", { placeholder: "title" });
  const round = (y, head, sub, fill, col, name) => {
    card(s, M, y, 4.1, 1.85, name, fill);
    text(s, head, { x: M + 0.3, y: y + 0.25, w: 3.5, h: 0.6, fontSize: 22, bold: true, color: col, objectName: name + " judul" });
    text(s, sub, { x: M + 0.3, y: y + 0.9, w: 3.5, h: 0.85, fontSize: 14, color: C.text2, objectName: name + " isi" });
  };
  round(1.85, "Babak 1: GENSET MATI", "Tanpa blokir. Insiden KRITIS, perintah Modbus sampai ke PLC.", "FBE3E2", C.accent3, "Kartu babak 1");
  round(3.95, "Babak 2: GENSET NYALA", "Mode blokir. Insiden TINGGI: serangan ke OT dicoba, lalu DIBLOKIR.", "E2F2E8", C.accent4, "Kartu babak 2");
  s.addTable([
    [{ text: "Waktu", options: th }, { text: "Kronologi di laporan babak 2", options: th }, { text: "Bukti", options: th }],
    tr("05:12:45", "4 login SSH gagal ke pc-staf-07", "W1 dst."),
    tr("05:12:52", "Login berhasil sebagai 'sertu'", "W7"),
    tr("05:12:52", "Pembacaan /etc/shadow", "W9 dst."),
    tr("05:12:52", "SSH lateral ke srv-file-01", "W16"),
    [{ text: "05:12:54", options: { fontFace: "Courier New" } }, { text: "Perintah Modbus ke PLC DIBLOKIR", options: { bold: true, color: C.accent4 } }, { text: "S2", options: { fontFace: "Courier New" } }],
  ], { x: 5.0, y: 1.85, w: W - M - 5.0, colW: [1.3, 4.45, W - M - 5.0 - 5.75], fontSize: 13, color: C.text1,
       border, rowH: 0.62, valign: "middle", margin: [0.05, 0.12, 0.05, 0.12], objectName: "Tabel babak 2" });
  text(s, "Uji lab 7 November 2026. Suricata mode IPS: hanya HMI resmi (10.10.5.30) yang boleh mengirim perintah tulis ke PLC.",
       { x: 5.0, y: 5.75, w: W - M - 5.0, h: 0.6, fontSize: 12, color: C.accent5, objectName: "Catatan babak 2" });
  s.addNotes("Babak kedua, 7 November, dengan mode blokir. Perintah Modbus dari host yang tidak sah dijatuhkan sebelum sampai ke PLC, dan genset tetap menyala. Yang penting untuk analis: serangannya tidak hilang dari pandangan. Tameng tetap merangkai seluruh rantai dan melaporkannya sebagai serangan ke OT yang digagalkan, sehingga analis tahu akun mana yang harus di-reset dan host mana yang harus diisolasi.");

  // ---------- 11. Mengapa Tameng ----------
  pres.addSection({ title: "Mengapa Tameng" });
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Mengapa Tameng" });
  s.addText("Bagian-bagiannya sudah ada; Tameng menyatukannya untuk analis satuan, dengan biaya satu laptop", { placeholder: "title" });
  const hc = (t, hi) => ({ text: t, options: Object.assign({}, hdr, { fontSize: 13, align: "center" }, hi ? { fill: { color: C.accent1 } } : {}) });
  const cell = (t, good) => ({ text: t, options: { align: "center", color: good === 1 ? C.accent4 : good === 0 ? C.accent3 : C.text2, bold: good === 1 } });
  const tm = (t) => ({ text: t, options: { align: "center", bold: true, color: C.text1, fill: { color: "D8EEF3" } } });
  s.addTable([
    [{ text: "", options: hdr }, hc("SIEM/IDS"), hc("Copilot AI cloud"), hc("Platform OT"), hc("AI SOC open-source"), hc("Tameng", true)],
    [{ text: "Dirancang untuk", options: { bold: true } }, cell("analis ahli", 2), cell("analis ahli", 2), cell("operator OT", 2), cell("analis ahli", 2), tm("analis junior satuan")],
    [{ text: "Merangkai insiden", options: { bold: true } }, cell("tidak", 0), cell("ya", 1), cell("sebagian", 2), cell("ya", 1), tm("ya")],
    [{ text: "IT dan OT dalam satu insiden", options: { bold: true } }, cell("tidak", 0), cell("sebagian", 2), cell("OT saja", 2), cell("IT saja", 2), tm("ya")],
    [{ text: "Data tetap di satuan", options: { bold: true } }, cell("ya", 1), cell("tidak", 0), cell("ya", 1), cell("ya", 1), tm("ya")],
    [{ text: "Biaya untuk satuan", options: { bold: true } }, cell("rendah", 1), cell("tinggi", 0), cell("sangat tinggi", 0), cell("rendah", 1), tm("rendah")],
  ], { x: M, y: 1.8, w: W - 2 * M, colW: [3.0, 1.75, 1.85, 1.75, 1.95, W - 2 * M - 10.3], fontSize: 14, color: C.text1,
       border, rowH: 0.56, valign: "middle", margin: [0.05, 0.1, 0.05, 0.1], objectName: "Tabel pembanding" });
  const feas = [["cheap", "1 laptop 16 GB"], ["db", "Lab ±685 MB RAM"], ["wifi", "Offline penuh"], ["test", "14 tes otomatis"]];
  feas.forEach(([k, t], i) => {
    const x = M + i * 3.08;
    badge(s, k, x, 5.55, 0.65, C.accent1, t);
    text(s, t, { x: x + 0.8, y: 5.55, w: 2.2, h: 0.65, fontSize: 15, bold: true, valign: "middle", objectName: "Fakta " + t });
  });
  text(s, "AI SOC open-source: contoh AiSOC dan AI_SOC (IT saja). Proyek OT dengan blokir Modbus dan laporan LLM juga ada (skripsi SETU Carlow), tanpa sisi IT.",
    { x: M, y: 6.4, w: W - 2 * M, h: 0.4, fontSize: 11, color: C.accent5, objectName: "Catatan pembanding" });
  s.addNotes("Kami tahu bagian-bagiannya sudah ada. Ada proyek AI SOC open-source dengan LLM lokal, tetapi hanya untuk IT dan dibuat untuk analis yang sudah ahli. Ada proyek OT yang memblokir Modbus, tetapi tanpa sisi IT. Tameng menyatukannya: satu insiden dari IT sampai OT, data tetap di satuan, dalam bahasa yang bisa langsung dipakai analis junior. Semua berjalan di satu laptop 16 GB, dan mesinnya dijaga 14 tes otomatis.");

  // ---------- 12. Penutup ----------
  pres.addSection({ title: "Penutup" });
  s = pres.addSlide({ masterName: "GELAP", sectionTitle: "Penutup" });
  s.addText("Langkah berikutnya: membuktikannya bersama analis satuan", { placeholder: "title" });
  const next = [
    ["users", "Uji dengan analis sungguhan", "Bandingkan log mentah dan laporan Tameng: waktu dan ketepatan menjawab siapa, apa yang kena, dan langkah pertama"],
    ["list", "Checklist dan ringkasan komandan", "Langkah bernomor sesuai SOP satuan; satu paragraf untuk atasan"],
    ["dash", "Dashboard langsung", "Insiden tampil saat terjadi; analis menyetujui atau menolak tiap rekomendasi"],
    ["book", "Rekomendasi berbasis playbook", "Langkah respons per teknik ATT&CK disusun kode; AI hanya merangkai kalimat"],
  ];
  next.forEach(([k, t, d], i) => {
    const x = M + (i % 2) * 6.15, y = 1.75 + Math.floor(i / 2) * 2.0;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 5.85, h: 1.75, rectRadius: 0.12, fill: { color: "1B2B3A" }, line: { color: "1B2B3A" }, objectName: "Kartu " + t });
    badge(s, k, x + 0.3, y + 0.45, 0.8, C.accent6, t);
    text(s, t, { x: x + 1.35, y: y + 0.22, w: 4.25, h: 0.45, fontSize: 18, bold: true, color: C.background1, objectName: "Judul " + t });
    text(s, d, { x: x + 1.35, y: y + 0.7, w: 4.25, h: 0.95, fontSize: 14, color: "C9D4DD", objectName: "Isi " + t });
  });
  text(s, "Usulan pilot: satu markas, satu tim analis, data tetap di dalam satuan.", {
    x: M, y: 5.9, w: W - 2 * M, h: 0.45, fontSize: 18, bold: true, color: C.accent6, objectName: "Usulan pilot" });
  text(s, "Tameng: alat deteksinya sudah ada, sekarang analisnya juga punya pendamping.", {
    x: M, y: 6.4, w: W - 2 * M, h: 0.4, fontSize: 15, color: C.background1, objectName: "Penutup kalimat" });
  s.addNotes("Langkah berikutnya yang paling penting: menguji Tameng bersama analis sungguhan, mengukur berapa cepat dan berapa tepat mereka memahami insiden dengan dan tanpa Tameng. Lalu checklist tindakan sesuai SOP satuan dan ringkasan untuk komandan, dashboard langsung dengan tombol setuju atau tolak, dan rekomendasi berbasis playbook. Kami mengusulkan pilot di satu markas. Terima kasih.");

  // ---------- Lampiran A: kriteria ----------
  pres.addSection({ title: "Lampiran" });
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Lampiran" });
  s.addText("Lampiran: pemetaan Tameng ke lima kriteria penjurian", { placeholder: "title" });
  const crit = [
    ["25%", "Relevansi IT/OT", "Rantai dari PC staf sampai genset; ATT&CK Enterprise dan ICS dalam satu laporan", C.accent1],
    ["25%", "Inovasi teknis", "Korelasi IT→OT berbasis entitas; AI lokal yang dijaga validasi anti-halusinasi; mode blokir Modbus", C.accent1],
    ["25%", "Purwarupa berfungsi", "Lab nyata 6 container; dua babak serangan bisa diulang di depan juri", C.accent1],
    ["15%", "Kelayakan implementasi", "Satu laptop, open-source, offline; laporan berbahasa Indonesia untuk analis junior", C.accent2],
    ["10%", "Dokumentasi", "Panduan lab dan mesin, 14 tes otomatis, contoh laporan dan JSON insiden", C.accent5],
  ];
  crit.forEach(([p, t, d, col], i) => {
    const y = 1.75 + i * 0.98;
    s.addShape(pres.shapes.OVAL, { x: M, y, w: 0.8, h: 0.8, fill: { color: col }, line: { color: col }, objectName: "Bobot " + t });
    text(s, p, { x: M, y, w: 0.8, h: 0.8, fontSize: 15, bold: true, color: C.background1, align: "center", valign: "middle", objectName: "Bobot teks " + t });
    text(s, t, { x: M + 1.05, y, w: 3.3, h: 0.8, fontSize: 18, bold: true, valign: "middle", objectName: "Kriteria " + t });
    text(s, d, { x: M + 4.45, y, w: W - 2 * M - 4.45, h: 0.8, fontSize: 15, color: C.text2, valign: "middle", objectName: "Jawaban " + t });
  });
  s.addNotes("Lampiran untuk sesi tanya jawab: pemetaan ke kriteria penjurian.");

  // ---------- Lampiran B: RAM ----------
  s = pres.addSlide({ masterName: "KONTEN", sectionTitle: "Lampiran" });
  s.addText("Lampiran: seluruh lab dan analisis berjalan di satu laptop 16 GB tanpa internet", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [{ name: "RAM (MB)",
    labels: ["wazuh-manager", "suricata", "pc-staf-07", "srv-file-01", "plc-genset-01", "attacker"],
    values: [546, 50, 34, 34, 19, 2] }], {
    x: M, y: 1.75, w: 6.2, h: 4.6, barDir: "bar", catAxisOrientation: "maxMin",
    showTitle: true, title: "RAM lab per container (total ±685 MB)", titleFontSize: 14, titleColor: H.dk1, titleFontFace: "+mn-lt",
    chartColors: [H.accent1], showValue: true, dataLabelPosition: "outEnd", dataLabelFontSize: 12, dataLabelColor: H.dk2, dataLabelFontFace: "+mn-lt",
    catAxisLabelColor: H.dk2, catAxisLabelFontSize: 12, catAxisLabelFontFace: "+mn-lt",
    valAxisHidden: true, valGridLine: { style: "none" }, catGridLine: { style: "none" }, showLegend: false,
    objectName: "Grafik RAM",
  });
  const fz = [
    ["wifi", "Offline penuh", "Wi-Fi dimatikan saat demo; model AI disimpan di SSD terenkripsi", C.accent1],
    ["py", "Tanpa dependensi", "Mesin Tameng hanya memakai pustaka standar Python", C.accent1],
    ["open", "Open-source", "Wazuh, Suricata, Ollama, dan Qwen; tanpa lisensi berbayar", C.accent1],
    ["test", "Teruji", "14 tes regresi otomatis, termasuk rekonstruksi insiden lab", C.accent4],
  ];
  fz.forEach(([k, t, d, col], i) => {
    const y = 1.85 + i * 1.15;
    badge(s, k, 7.25, y, 0.75, col, t);
    text(s, t, { x: 8.2, y: y - 0.02, w: 4.5, h: 0.4, fontSize: 17, bold: true, objectName: "Kelayakan " + t });
    text(s, d, { x: 8.2, y: y + 0.38, w: 4.5, h: 0.6, fontSize: 14, color: C.text2, objectName: "Kelayakan isi " + t });
  });
  s.addNotes("Lampiran untuk sesi tanya jawab: kebutuhan perangkat keras.");

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("tulis", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
