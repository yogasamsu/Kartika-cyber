// Render slides.html -> PNG per slide, PDF, dan PPTX (gambar + catatan pembicara).
//   node presentasi/web/render.mjs   (dari root repo; butuh playwright-core dan pptxgenjs)
import { chromium } from "playwright-core";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const out = path.join(root, "siap kirim");
const png = path.join(here, "png");
fs.mkdirSync(png, { recursive: true });
const b = await chromium.launch({ executablePath: process.env.CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", headless: true });
const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
await p.goto("file://" + path.join(here, "slides.html"));
await p.waitForTimeout(800);
const n = await p.locator(".slide").count();
const notes = [];
for (let i = 0; i < n; i++) {
  const s = p.locator(".slide").nth(i);
  await s.screenshot({ path: path.join(png, String(i + 1).padStart(2, "0") + ".png") });
  notes.push(await s.getAttribute("data-notes"));
}
await p.addStyleTag({ content: "@page{size:1920px 1080px;margin:0} body{background:#07090a} .slide{margin:0}" });
await p.pdf({ path: path.join(out, "tameng-slide.pdf"), width: "1920px", height: "1080px", printBackground: true });
await b.close();
const require = createRequire(import.meta.url);
const PptxGenJS = require(process.env.PPTXGENJS || "pptxgenjs");
const pres = new PptxGenJS();
pres.layout = "LAYOUT_WIDE"; pres.title = "Tameng"; pres.author = "Yoga Samsugiharja";
for (let i = 0; i < n; i++) {
  const s = pres.addSlide();
  s.addImage({ path: path.join(png, String(i + 1).padStart(2, "0") + ".png"), x: 0, y: 0, w: 13.333, h: 7.5 });
  if (notes[i]) s.addNotes(notes[i]);
}
await pres.writeFile({ fileName: path.join(out, "tameng-slide.pptx") });
console.log(n, "slide ->", out);
