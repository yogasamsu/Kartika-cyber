# Dashboard Tameng (pusat komando, gaya militer)

Satu halaman HTML tanpa pustaka luar, tanpa CDN, dan tanpa font daring, supaya
tetap jalan di laptop air-gapped.

- **Beranda (`index.html`)**: HUD yang mengunci perisai Tameng, lalu tujuh
  bagian singkat: masalah, solusi saat ini, apa itu Tameng, cara kerja,
  keunggulan, limitasi, dan integrasi ke sistem TNI.
- **Pusat komando (`komando.html`)**: cara kerja singkat, status sistem,
  tindakan prioritas, notifikasi, insiden (peta alur serangan, kronologi,
  ringkasan, checklist, edukasi), ringkasan kerentanan, dan daftar fitur.
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
