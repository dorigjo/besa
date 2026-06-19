#!/usr/bin/env node
// @ts-check

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Skip in CI, non-TTY, or piped output — never block automated installs
if (!process.stdout.isTTY || process.env.CI || process.env.NO_COLOR) {
  process.exit(0);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, "..", "package.json"), "utf8"),
);

// Brand colors: S5 Sovereign Diamond
const RESET = "\x1b[0m";
const PARCHMENT = "\x1b[38;2;253;240;213m"; // #FDF0D5
const RED = "\x1b[38;2;193;18;31m";         // #C1121F
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const p = PARCHMENT;
const r = RED;
const b = BOLD;
const d = DIM;
const x = RESET;

// S5 Sovereign Diamond mark: parchment outline, red horizontal line at widest point
process.stdout.write([
  "",
  `  ${p}    /\\${x}`,
  `  ${p}   /  \\${x}`,
  `  ${p}  /    \\${x}      ${b}${p}BESA${x}`,
  `  ${p} /${r}------${p}\\${x}     ${p}${d}Signed trust for AI-agent tools.${x}`,
  `  ${p}  \\    /${x}      ${p}${d}v${pkg.version}${x}`,
  `  ${p}   \\  /${x}`,
  `  ${p}    \\/${x}`,
  "",
  "",
].join("\n"));
