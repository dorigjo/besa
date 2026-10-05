import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashRequest, verifyReceiptDetailed } from '@dorigjo/besa';
import { Besa } from '../../dist/nodes/Besa/Besa.node.js';
import { createMockExecuteFunctions } from '../support/helpers.mjs';

const workflowUrl = new URL('../../examples/workflows/besa-demo.workflow.json', import.meta.url);
const manifestUrl = new URL('../../../examples/manifest.yaml', import.meta.url);

test('onboarding: shipped demo and example manifest complete the real CLI/node crypto chain', async (t) => {
	const workflow = JSON.parse(await readFile(workflowUrl, 'utf8'));
	const setNode = workflow.nodes.find((node) => node.name === 'Set Signed Manifest');
	const operations = workflow.nodes.filter((node) => node.type === 'n8n-nodes-besa.besa');
	assert.equal(workflow.nodes.length, 6, 'the public demo stays minimal, without IF/HTTP');
	assert.deepEqual(operations.map((node) => node.parameters.operation), [
		'verifySignedManifest', 'checkAdmission', 'createReceipt', 'verifyReceipt',
	]);
	const admissionNode = operations[1];
	assert.equal(admissionNode.parameters.toolName, 'crm.lookup');
	const requestValue = setNode.parameters.assignments.assignments.find(
		(assignment) => assignment.name === 'demoRequest',
	).value;
	assert.match(requestValue, /^=\{\{[\s\S]*\}\}$/);
	const request = JSON.parse(requestValue.slice(3, -2).trim());
	assert.equal(request.tool, admissionNode.parameters.toolName);
	assert.deepEqual(request.args, { query: 'alice@example.com' });
	const trigger = workflow.nodes.find((node) => node.type === 'n8n-nodes-base.manualTrigger');
	const chain = [trigger, setNode, ...operations];
	for (let index = 0; index < chain.length - 1; index++) {
		assert.deepEqual(workflow.connections[chain[index].name].main, [
			[{ node: chain[index + 1].name, type: 'main', index: 0 }],
		]);
	}
	assert.equal(
		operations[2].credentials.besaSigningKeyApi.id,
		'REPLACE_WITH_YOUR_CREDENTIAL_ID',
	);

	const tempRoot = await realpath(tmpdir());
	const directory = await mkdtemp(join(tempRoot, 'besa-n8n-onboarding-'));
	t.after(async () => {
		const pathWithinTemp = relative(tempRoot, directory);
		assert.ok(pathWithinTemp && !pathWithinTemp.startsWith('..') && !isAbsolute(pathWithinTemp));
		await rm(directory, { recursive: true, force: true });
	});
	await mkdir(join(directory, 'examples'));
	await copyFile(manifestUrl, join(directory, 'examples', 'manifest.yaml'));
	const sdkUrl = import.meta.resolve('@dorigjo/besa');
	const packageJson = JSON.parse(await readFile(new URL('../package.json', sdkUrl), 'utf8'));
	assert.equal(packageJson.version, '1.3.0');
	const publicManifest = await readFile(new URL('../examples/manifest.yaml', sdkUrl), 'utf8');
	const repositoryManifest = await readFile(manifestUrl, 'utf8');
	assert.equal(publicManifest.replace(/\r\n/g, '\n'), repositoryManifest.replace(/\r\n/g, '\n'));
	const cli = fileURLToPath(new URL('./index.js', sdkUrl));
	const passphrase = 'onboarding regression fixture, never a production secret';
	const cliOptions = {
		cwd: directory,
		env: { ...process.env, BESA_KEY_PASSPHRASE: passphrase },
		stdio: 'pipe',
	};
	execFileSync(process.execPath, [cli, 'keys'], cliOptions);
	execFileSync(process.execPath, [cli, 'sign', 'examples/manifest.yaml'], cliOptions);
	const storedKeyPair = await readFile(join(directory, '.besa', 'key.json'), 'utf8');
	assert.equal('privateKeyDer' in JSON.parse(storedKeyPair), false);
	const signedManifest = JSON.parse(await readFile(
		join(directory, 'examples', 'manifest.signed.json'), 'utf8',
	));
	const tool = signedManifest.manifest.tools.find((entry) => entry.name === request.tool);
	assert.ok(tool, 'the demo tool must exist in the actual shipped manifest');
	assert.deepEqual(tool.inputSchema.required, Object.keys(request.args));
	assert.equal(tool.inputSchema.properties.query.type, typeof request.args.query);

	let current = { signedManifest, demoRequest: request };
	for (const definition of operations) {
		// Resolve only this fixture's explicit data references, not a replacement n8n engine.
		const references = new Map([
			['={{ $json }}', current],
			['={{ $json.signedManifest }}', current.signedManifest],
			['={{ $json.toolName }}', current.toolName],
			['={{ $json.decision }}', current.decision],
			['={{ $json.reasonCode }}', current.reasonCode],
			["={{ $('Set Signed Manifest').item.json.signedManifest }}", signedManifest],
			["={{ $('Set Signed Manifest').item.json.demoRequest }}", request],
		]);
		const parameters = Object.fromEntries(Object.entries(definition.parameters).map(([name, value]) => {
			if (typeof value !== 'string' || !value.startsWith('={{')) return [name, value];
			assert.ok(references.has(value), `unexpected demo binding: ${name}`);
			return [name, references.get(value)];
		}));
		const ctx = createMockExecuteFunctions({
			items: [{ json: current }], parameters, node: definition,
			credentials: { storedKeyPair, passphrase },
		});
		const [items] = await new Besa().execute.call(ctx);
		current = items[0].json;
		if (parameters.operation === 'verifySignedManifest') assert.equal(current.valid, true);
		if (parameters.operation === 'checkAdmission') {
			assert.equal(current.decision, 'allow');
			assert.equal(current.reasonCode, 'ALLOWED');
		}
		if (parameters.operation === 'createReceipt') {
			assert.equal(current.requestHash, hashRequest(request));
			assert.equal(verifyReceiptDetailed(current, signedManifest.publicKey).valid, true);
		}
	}
	assert.equal(current.valid, true);
	assert.equal(current.reasonCode, 'OK');
});

test('onboarding: user-facing docs and credential do not advertise the removed keygen command', async () => {
	for (const name of ['README.md', 'TESTER.md', 'credentials/BesaSigningKeyApi.credentials.ts']) {
		const text = await readFile(new URL(`../../${name}`, import.meta.url), 'utf8');
		assert.equal(/\bbesa keygen\b/.test(text), false, `${name}: removed CLI command`);
		assert.equal(/\bbesa keys\b/.test(text), true, `${name}: current CLI command is documented`);
	}
});
