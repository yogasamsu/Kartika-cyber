# Dashboard Tameng (pusat komando, gaya militer)

Satu halaman HTML tanpa pustaka luar, tanpa CDN, dan tanpa font daring, supaya
tetap jalan di laptop air-gapped.

- **Pembuka**: HUD bidik yang mengunci perisai Tameng (cincin skala berputar,
  radar sapu, segitiga kunci sasaran, log boot), lalu nama dan kepanjangan.
- **Pusat komando**: daftar insiden, peta alur serangan (zona luar, IT, OT;
  jalur serangan, jalur yang diblokir, reticle pada sasaran terakhir),
  kronologi dengan chip ATT&CK dan bukti, ringkasan, checklist *gerak cepat*,
  dan panel *edukasi*.

## Pakai

```bash
python3 dashboard/build.py                 # tiga skenario demo -> dashboard/data.js
python3 -m http.server 8765 --directory dashboard
# buka http://localhost:8765
```

Membuka `index.html` langsung lewat `file://` juga bisa di browser biasa.
`build.py` juga menerima JSON keluaran `python3 -m tameng --json` mana pun.
Animasi dimatikan otomatis bila sistem meminta *reduced motion*.
