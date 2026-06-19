import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const PORT = 8766;
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

const banners = [
  { file: 'twitter-1500x500.html', out: 'twitter-1500x500.png', w: 1500, h: 500 },
  { file: 'linkedin-1584x396.html', out: 'linkedin-1584x396.png', w: 1584, h: 396 },
  { file: 'hero-1920x600.html', out: 'hero-1920x600.png', w: 1920, h: 600 },
  { file: 'github-1280x640.html', out: 'github-1280x640.png', w: 1280, h: 640 },
];

const server = createServer((req, res) => {
  const filename = req.url === '/' ? 'index.html' : req.url.slice(1);
  const filePath = join(__dir, filename);
  try {
    const file = readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(file);
  } catch {
    res.writeHead(404); res.end('not found');
  }
});

async function shot(banner) {
  return new Promise((resolve) => {
    const outPath = join(__dir, banner.out);
    const args = [
      '--headless=new', '--disable-gpu',
      `--screenshot=${outPath}`,
      `--window-size=${banner.w},${banner.h}`,
      '--hide-scrollbars', '--no-sandbox',
      '--force-device-scale-factor=1',
      `http://localhost:${PORT}/${banner.file}`,
    ];
    const p = spawn(CHROME, args, { stdio: 'inherit' });
    p.on('close', () => {
      console.log(`  done → ${banner.out}`);
      resolve();
    });
  });
}

server.listen(PORT, async () => {
  console.log(`Server on :${PORT}`);
  for (const b of banners) {
    await shot(b);
  }
  server.close();
  console.log('All done.');
  process.exit(0);
});
