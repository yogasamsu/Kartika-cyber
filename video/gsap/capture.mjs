// Ambil footage asli untuk video: dashboard replay Tameng per langkah dan laporan.
// Gambar 2x (3840 lebar) supaya tetap tajam saat kamera memperbesar.
import { chromium } from "playwright-core";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const CHROME = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 2 });

const dash = "file://" + path.join(root, "artifacts/tameng-replay.html");
for (const step of ["0", "2", "4", "6", "7", "all"]) {
  await page.goto(`${dash}?step=${step}`);
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(here, `assets/dash-${step}.png`), fullPage: true });
  console.log(`assets/dash-${step}.png`);
}
for (const f of process.argv.slice(2)) {           // halaman tambahan: laporan, log
  await page.goto("file://" + path.resolve(f));
  await page.waitForTimeout(300);
  const out = path.join(here, "assets", path.basename(f).replace(/\.html$/, ".png"));
  await page.screenshot({ path: out, fullPage: true });
  console.log(path.relative(here, out));
}
await browser.close();
