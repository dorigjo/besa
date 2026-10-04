// n8n community-node packages may not declare a "dependencies" field (n8n's
// installer does not resolve a package's own transitive npm deps). Besa's
// node genuinely needs the real @dorigjo/besa SDK -- not a reimplementation
// -- so instead of vendoring/duplicating its logic, this bundles the real,
// installed @dorigjo/besa package straight into the compiled node/credential
// files at build time. n8n-workflow stays external: it is provided by the
// n8n runtime itself and must never be bundled.
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

await build({
	entryPoints: [
		join(root, 'nodes/Besa/Besa.node.ts'),
		join(root, 'credentials/BesaSigningKeyApi.credentials.ts'),
	],
	outbase: root,
	outdir: join(root, 'dist'),
	bundle: true,
	platform: 'node',
	target: 'node20',
	format: 'cjs',
	external: ['n8n-workflow'],
	sourcemap: false,
	logLevel: 'info',
});
