// Render index.html bingkai demi bingkai (30 fps) dengan Chrome headless + ffmpeg.
//   node render.mjs                 -> out/tameng-video.mp4 (dengan audio bila ada audio/audio.*)
//   node render.mjs --from 210 --to 235   -> render sebagian (untuk cek adegan)
//   node render.mjs still 10 50 212       -> out/still-10.jpg, ... (gambar diam)
// Audio (musik latar atau VO, opsional): taruh di audio/audio.m4a (atau .wav/.mp3).
// Geser dengan AUDIO_DELAY=0.4 (detik, negatif = lebih awal).
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, "out");
mkdirSync(OUT, { recursive: true });
const FPS = 30;
const CHROME = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const args = process.argv.slice(2);
const opt = (k, d) => (args.includes(k) ? parseFloat(args[args.indexOf(k) + 1]) : d);

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
await page.goto("file://" + path.join(here, "index.html") + "?render", { waitUntil: "commit" });
// Jangan pakai page.waitForFunction (macet di halaman ini). Beri jeda, lalu cek manual.
await new Promise((r) => setTimeout(r, 1500));
for (let k = 0; !(await page.evaluate(() => window.__ready === true)); k++) {
  if (k > 300) throw new Error("index.html tidak siap dalam 60 dtk");
  await new Promise((r) => setTimeout(r, 200));
}
const DUR = await page.evaluate(() => window.__duration);
const shot = async (t) => {
  await page.evaluate((t) => window.__seek(t), t);
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => r())));   // tunggu satu frame tergambar
  return page.screenshot({ type: "jpeg", quality: 92 });
};

if (args[0] === "still") {
  for (const t of args.slice(1)) {
    const buf = await shot(parseFloat(t));
    const f = path.join(OUT, `still-${t}.jpg`);
    (await import("node:fs")).writeFileSync(f, buf);
    console.log(path.relative(here, f));
  }
  await browser.close();
  process.exit(0);
}

const from = opt("--from", 0), to = Math.min(opt("--to", DUR), DUR);
const partial = from > 0 || to < DUR;
const video = path.join(OUT, partial ? `bagian-${from}-${to}.mp4` : "tameng-video-tanpa-suara.mp4");
const ff = spawn("ffmpeg", ["-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", String(FPS), "-i", "-",
  "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-pix_fmt", "yuv420p", "-movflags", "+faststart", video],
  { stdio: ["pipe", "inherit", "inherit"] });
const frames = Math.round((to - from) * FPS);
const t0 = Date.now();
for (let i = 0; i < frames; i++) {
  const buf = await shot(from + i / FPS);
  if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once("drain", r));
  if (i % (FPS * 10) === 0) {
    const el = (Date.now() - t0) / 1000;
    process.stdout.write(`\r${(from + i / FPS).toFixed(0)}/${to.toFixed(0)} dtk · ${el.toFixed(0)} dtk berjalan   `);
  }
}
ff.stdin.end();
await new Promise((r) => ff.on("close", r));
await browser.close();
console.log(`\nVideo: ${path.relative(here, video)}`);

// Gabungkan audio bila ada (hanya untuk render penuh).
const vo = ["audio/audio.m4a", "audio/audio.wav", "audio/audio.mp3"].map((f) => path.join(here, f)).find(existsSync);
if (!partial && vo) {
  const final = path.join(OUT, "tameng-video.mp4");
  const delay = parseFloat(process.env.AUDIO_DELAY || "0");
  const ms = Math.max(0, Math.round(delay * 1000));
  const trim = delay < 0 ? ["-ss", String(-delay)] : [];
  await new Promise((r) => spawn("ffmpeg", ["-y", "-loglevel", "error", "-i", video, ...trim, "-i", vo,
    "-filter_complex", `[1:a]adelay=${ms}|${ms},apad,afade=t=out:st=${(DUR - 3).toFixed(1)}:d=3[a]`, "-map", "0:v", "-map", "[a]",
    "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-shortest", "-movflags", "+faststart", final],
    { stdio: "inherit" }).on("close", r));
  console.log(`Dengan audio: ${path.relative(here, final)} (${path.basename(vo)})`);
} else if (!partial) {
  console.log("Tidak ada audio/audio.*; video tanpa suara.");
}
