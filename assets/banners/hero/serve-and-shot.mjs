import { createServer } from 'http';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync, spawn } from 'child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const PORT = 8765;

const server = createServer((req, res) => {
  try {
    const file = readFileSync(join(__dir, 'hero-1920x600.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(file);
  } catch {
    res.writeHead(404); res.end('not found');
  }
});

server.listen(PORT, () => {
  console.log(`Server on http://localhost:${PORT}`);

  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const outPath = join(__dir, 'hero-1920x600.png');

  const args = [
    '--headless=new',
    '--disable-gpu',
    `--screenshot=${outPath}`,
    '--window-size=1920,600',
    '--hide-scrollbars',
    '--no-sandbox',
    '--force-device-scale-factor=1',
    `http://localhost:${PORT}/`,
  ];

  const chrome = spawn(chromePath, args, { stdio: 'inherit' });
  chrome.on('close', (code) => {
    server.close();
    console.log(`Chrome exited ${code}. Done → ${outPath}`);
    process.exit(0);
  });
});
