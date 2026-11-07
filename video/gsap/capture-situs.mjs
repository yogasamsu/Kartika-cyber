// Ambil footage pusat komando Tameng (dashboard/komando.html) untuk video v4.
// Gambar 2x (3200 px lebar) supaya tetap tajam saat kamera memperbesar.
//   node capture-situs.mjs
import { chromium } from "playwright-core";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const CHROME = process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2 });
const base = "file://" + path.join(root, "dashboard/komando.html");

const SHOTS = [
  ["k-dashboard", "#dashboard", false],
  ["k-temuan", "#temuan/0", true],       // babak 1: genset dimatikan
  ["k-temuan-ips", "#temuan/1", true],   // babak 2: perintah ke PLC diblokir
  ["k-rekomendasi", "#rekomendasi", true],
];
for (const [name, hash, full] of SHOTS) {
  await page.goto(base + hash);
  await page.evaluate((h) => { location.hash = h; }, hash);
  await page.waitForTimeout(700);
  await page.screenshot({ path: path.join(here, "assets", name + ".png"), fullPage: full });
  const dim = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.scrollHeight]);
  console.log(`assets/${name}.png`, dim.join("x"));
}
await browser.close();
