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

const RESET = "\x1b[0m";
const RED   = "\x1b[31m";
const BOLD  = "\x1b[1m";
const DIM   = "\x1b[2m";

process.stdout.write([
  "",
  `  ${BOLD}${RED}BESA${RESET}`,
  `  ${DIM}Signed trust for AI-agent tools.${RESET}`,
  `  ${DIM}v${pkg.version}${RESET}`,
  "",
  "",
].join("\n"));
