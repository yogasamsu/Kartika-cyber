# Video Tameng gaya AgMon (GSAP, ±5:50, tanpa VO)

Satu halaman `index.html` berisi satu timeline GSAP yang dijeda. Footage asli
(dashboard, log Wazuh, laporan) digerakkan kamera; cerita dibawa teks layar.
Render dilakukan bingkai demi bingkai (30 fps) sehingga gerak selalu mulus.

```bash
cd video && npm install          # sekali: gsap, playwright-core
cd gsap
open index.html                  # pratinjau: Spasi putar/jeda, ← → 5 dtk, ?t=212 lompat
node render.mjs still 50 214     # gambar diam di detik tertentu -> out/still-*.jpg
node render.mjs --from 210 --to 235   # render sebagian
node render.mjs                  # render penuh -> out/tameng-video-tanpa-suara.mp4
```

Musik latar (opsional): taruh di `audio/audio.mp3` (atau `.m4a`/`.wav`), lalu
render ulang. Hasilnya `out/tameng-video.mp4`, dengan fade-out 3 detik di akhir.

| Berkas | Isi |
|---|---|
| `NASKAH.md` | Storyboard tujuh bagian (dimulai dari masalah analis) dan naskah lisan (dipakai juga untuk presentasi final) |
| `index.html` | Adegan, teks layar (`COPY`), gerak kamera, nama tim (`TIM`) |
| `render.mjs` | Render per bingkai dengan Chrome headless + ffmpeg |
| `capture.mjs` | Ambil ulang footage dashboard (`artifacts/tameng-replay.html?step=N`) dan halaman sumber |
| `build_sources.py` | Susun `sources/log.html` (log Wazuh asli dari SSD) dan `sources/laporan.html` |
| `assets/` | Footage hasil tangkapan (PNG 3200 px) |

Ambil ulang footage setelah uji lab baru:

```bash
python3 build_sources.py /Volumes/Prika-Tameng/lab-data/wazuh/alerts/alerts.json
node capture.mjs sources/log.html sources/laporan.html
```
