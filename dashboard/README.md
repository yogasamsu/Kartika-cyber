# Dashboard Tameng (pusat komando, gaya militer)

Satu halaman HTML tanpa pustaka luar, tanpa CDN, dan tanpa font daring, supaya
tetap jalan di laptop air-gapped.

- **Beranda (`index.html`)**: HUD yang mengunci perisai Tameng, lalu tujuh
  bagian singkat: masalah, solusi saat ini, apa itu Tameng, cara kerja,
  keunggulan, limitasi, dan integrasi ke sistem TNI.
- **Pusat komando (`komando.html`)**, empat menu:
  1. **Dashboard** (`#dashboard`): angka utama, insiden paling penting,
     langkah pertama, daftar insiden, notifikasi terbaru.
  2. **Temuan** (`#temuan/<i>`): analisa Tameng per insiden, peta alur
     serangan, rantai serangan, edukasi, temuan kerentanan.
  3. **Rekomendasi** (`#rekomendasi`): enam tindakan prioritas, checklist per
     insiden, daftar tambal kerentanan.
  4. **Data log** (`#log/<i>`): tabel alert asli, kronologi dengan penanda
     bukti, catatan narasi, semua notifikasi, status sistem.
- `tameng.css` dipakai kedua halaman.

Deploy: proyek Vercel `tameng` dari folder ini (`vercel deploy --prod`).
`.vercelignore` mencegah `build.py`, README, dan `.env*` ikut terunggah.

## Pakai

```bash
python3 lab/scripts/replay-deface.py --out lab/out
python3 lab/scripts/replay-deface.py --blokir --out lab/out
python3 dashboard/build.py                 # empat skenario + kerentanan + notifikasi -> data.js
python3 -m http.server 8765 --directory dashboard
# buka http://localhost:8765
```

Membuka `index.html` langsung lewat `file://` juga bisa di browser biasa.
`build.py` juga menerima JSON keluaran `python3 -m tameng --json` mana pun.
Animasi dimatikan otomatis bila sistem meminta *reduced motion*.

## Simulasi, login Google, dan pencatatan penguji

- **Simulasi** (`komando.html#simulasi`, menu 05): memutar ulang alert asli dari
  `data.js` satu per satu, lengkap dengan notifikasi, peta, rantai serangan, dan
  laporan yang bisa diunduh (.md). Tautan `#simulasi/mulai` langsung berjalan.
- **Login Google wajib** untuk `komando.html` di versi online. Beranda dan slide
  tetap publik. Bila `/api` tidak ada (file://, `python3 -m http.server`, laptop
  air-gapped), halaman terbuka tanpa login dan tanpa pencatatan.
- **Pencatatan**: `auth.js` mengirim event (login, buka_menu, simulasi_mulai,
  simulasi_selesai, unduh_laporan, centang_rekomendasi, logout, dll.) ke
  `/api/track`, lalu diteruskan ke Google Sheet lewat Apps Script
  (`setup/pencatat-sheet.gs`). Tab **Penguji** berisi ringkasan per email, tab
  **Aktivitas** berisi semua event.
- **Vercel Web Analytics** dimuat di semua halaman (kunjungan anonim). Aktifkan
  di dashboard Vercel → proyek `tameng` → Analytics → Enable.

Env Vercel yang dibutuhkan:

| Nama | Isi |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth Client ID (Web) dari Google Cloud Console; origin: `https://tameng.yogency.work`, `https://tameng-lake.vercel.app` |
| `SESSION_SECRET` | string acak panjang (`openssl rand -hex 32`) |
| `SHEET_WEBHOOK` | URL `/exec` dari penerapan Apps Script |
| `SHEET_SECRET` | sama dengan `RAHASIA` di `pencatat-sheet.gs` |

Tanpa `GOOGLE_CLIENT_ID` atau `SESSION_SECRET`, gerbang login mati. Tanpa
`SHEET_WEBHOOK`, event hanya masuk ke log fungsi Vercel.
