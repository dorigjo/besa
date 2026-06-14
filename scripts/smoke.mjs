import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

const node = process.execPath;
const tsc = process.platform === "win32"
? "node_modules/typescript/bin/tsc"
: "node_modules/typescript/bin/tsc";

function run(label, args, expectedCode) {
console.log(`\n== ${label} (expect exit ${expectedCode}) ==`);

const result = spawnSync(node, args, {
stdio: "inherit",
});

const code = result.status ?? 1;

if (code !== expectedCode) {
console.error(
`SMOKE FAIL: ${label} exited ${code}, expected ${expectedCode}`,
);
return false;
}

return true;
}

console.log("Besa smoke test");

if (!existsSync(tsc)) {
console.error("SMOKE FAIL: local TypeScript compiler not found. Run npm install first.");
process.exit(1);
}

if (!run("build (tsc)", [tsc], 0)) {
process.exit(1);
}

const manifest = "examples/manifest.yaml";
const signedManifest = "examples/manifest.signed.json";

const steps = [
["load manifest", ["dist/index.js", "load", manifest], 0],
["sign manifest", ["dist/index.js", "sign", manifest], 0],
["verify signed manifest", ["dist/index.js", "verify", signedManifest], 0],
["admit crm.lookup", ["dist/index.js", "admit", signedManifest, "crm.lookup"], 0],
["admit crm.delete deny", ["dist/index.js", "admit", signedManifest, "crm.delete"], 1],
["receipt crm.lookup", ["dist/index.js", "receipt", "crm.lookup"], 0],
["grant admit allow agent-alpha/crm.lookup", ["dist/index.js", "admit", signedManifest, "crm.lookup", "--agent", "agent-alpha", "--grants", "examples/grants.yaml"], 0],
["grant admit deny agent-alpha/crm.delete", ["dist/index.js", "admit", signedManifest, "crm.delete", "--agent", "agent-alpha", "--grants", "examples/grants.yaml"], 1],
["grant receipt agent-alpha/crm.lookup", ["dist/index.js", "receipt", "crm.lookup", signedManifest, "--agent", "agent-alpha", "--grants", "examples/grants.yaml"], 0],
];

let ok = true;

for (const [label, args, expectedCode] of steps) {
if (!run(label, args, expectedCode)) {
ok = false;
}
}

if (!ok) {
console.error("\nSMOKE FAILED");
process.exit(1);
}

console.log("\nSMOKE OK: all steps behaved as expected");