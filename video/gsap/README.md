# Video Tameng v4 (GSAP, ±2:34, VO ElevenLabs)

Satu halaman `index.html` berisi satu timeline GSAP yang dijeda, dengan gaya HUD
yang sama seperti banner tameng.yogency.work. Waktu tiap adegan mengikuti VO:
setiap kalimat VO memicu satu gerak.

```bash
cd video && npm install          # sekali: gsap, playwright-core
cd gsap
open index.html                  # pratinjau: Spasi putar/jeda, ← → 5 dtk, ?t=60 lompat
node render.mjs still 50 100     # gambar diam -> out/still-*.jpg
node render.mjs                  # render penuh -> out/tameng-video.mp4 (dengan VO)
```

## Alur VO

1. Teks VO ada di `VO-elevenlabs.txt` (ejaan fonetik untuk mesin) dan
   `NASKAH.md` (naskah dengan arahan layar).
2. Hasil ElevenLabs disimpan sebagai `audio/vo-1.mp3` sampai `audio/vo-7.mp3`.
3. Waktu tiap kalimat diukur dari jeda di audio (`vo-timing.json`), lalu
   disusun menjadi jadwal `vo-plan.js` dan trek gabungan `audio/audio.m4a`
   (jeda awal 1,2 dtk, antarbabak 0,9 dtk).
4. Subtitle di `index.html` (`CAP`) memakai ejaan asli, bukan ejaan fonetik.

## Berkas

| Berkas | Isi |
|---|---|
| `index.html` | Adegan, gerak HUD, subtitle, nama tim (`TIM`) |
| `vo-plan.js`, `vo-timing.json` | Jadwal babak dan kalimat dari VO |
| `capture-situs.mjs` | Ambil footage pusat komando (`dashboard/komando.html`) |
| `render.mjs` | Render per bingkai (Chrome headless + ffmpeg), audio digabung otomatis |
| `assets/` | Footage: log Wazuh asli, Dashboard, Temuan, Rekomendasi |
