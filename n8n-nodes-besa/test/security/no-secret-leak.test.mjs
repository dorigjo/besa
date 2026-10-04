// Verifies the security properties the founder explicitly required:
//   - verification operations never touch the signing-key credential at all
//   - no operation's output or thrown error ever contains the passphrase or
//     raw private key material
//   - the credential test function never echoes the passphrase back
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Besa } from '../../dist/nodes/Besa/Besa.node.js';
import { addTrustAnchor, emptyTrustStore } from '@dorigjo/besa';
import { createMockExecuteFunctions } from '../support/helpers.mjs';
import { buildSignedFixture } from '../support/fixtures.mjs';

function credentialsThatMustNotBeCalled() {
	return {
		async getCredentials() {
			throw new Error('SECURITY TEST FAILURE: a verification-only operation requested credentials');
		},
	};
}

async function run(parameters, extraCtx = {}) {
	const node = new Besa();
	const ctx = createMockExecuteFunctions({ parameters, ...extraCtx });
	const [items] = await node.execute.call(ctx);
	return items[0].json;
}

test('verifySignedManifest never requests credentials', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run(
		{ operation: 'verifySignedManifest', signedManifest, trustStore: '' },
		credentialsThatMustNotBeCalled(),
	);
	assert.equal(result.valid, true);
});

test('checkAdmission never requests credentials', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run(
		{
			operation: 'checkAdmission',
			manifest: signedManifest,
			toolName: 'demo.echo',
			callCount: 0,
			denyDestructiveHighRisk: true,
		},
		credentialsThatMustNotBeCalled(),
	);
	assert.equal(result.decision, 'allow');
});

test('verifyReceipt never requests credentials, even with a trust store', async () => {
	const { signedManifest } = buildSignedFixture();
	const trustStore = addTrustAnchor(emptyTrustStore(), signedManifest.publicKey);
	const result = await run(
		{
			operation: 'verifyReceipt',
			signedManifest,
			receipt: {
				artifactVersion: 1,
				receiptId: 'rcpt_00000000-0000-4000-8000-000000000000',
				manifestHash: signedManifest.manifestHash,
				toolName: 'demo.echo',
				decision: 'allow',
				reasonCode: 'ALLOWED',
				timestamp: '2026-01-01T00:00:01.000Z',
				requestHash: '0'.repeat(64),
				publicKeyId: signedManifest.publicKeyId,
				algorithm: 'ed25519',
				signature: 'A'.repeat(87) + '=',
			},
			trustStore,
			requestToRebind: '',
		},
		credentialsThatMustNotBeCalled(),
	);
	// Signature will not verify (it is fabricated above), but the important
	// assertion is that reaching a result at all never touched credentials.
	assert.equal(result.valid, false);
});

test('a wrong passphrase never appears in the thrown error message', async () => {
	const { signedManifest, storedKeyPair } = buildSignedFixture('the-real-passphrase-1234567890');
	const wrongPassphrase = 'a-completely-different-guess-passphrase';

	await assert.rejects(
		() =>
			run(
				{
					operation: 'createReceipt',
					signedManifestForReceipt: signedManifest,
					toolNameForReceipt: 'demo.echo',
					decision: 'allow',
					reasonCode: 'ALLOWED',
					request: {},
					agentId: '',
					grantReasonCode: '',
				},
				{
					credentials: { storedKeyPair: JSON.stringify(storedKeyPair), passphrase: wrongPassphrase },
				},
			),
		(error) => {
			assert.doesNotMatch(error.message, /the-real-passphrase/);
			assert.doesNotMatch(error.message, /a-completely-different-guess-passphrase/);
			assert.doesNotMatch(error.message, /privateKeyDer/);
			return true;
		},
	);
});

test('createReceipt output never contains the passphrase, ciphertext, or privateKeyDer', async () => {
	const { signedManifest, storedKeyPair, passphrase } = buildSignedFixture('super-secret-passphrase-value-99');
	const receipt = await run(
		{
			operation: 'createReceipt',
			signedManifestForReceipt: signedManifest,
			toolNameForReceipt: 'demo.echo',
			decision: 'allow',
			reasonCode: 'ALLOWED',
			request: { input: 'hello' },
			agentId: '',
			grantReasonCode: '',
		},
		{
			credentials: { storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
		},
	);

	const serialized = JSON.stringify(receipt);
	assert.doesNotMatch(serialized, /super-secret-passphrase-value-99/);
	assert.doesNotMatch(serialized, /privateKeyDer/);
	assert.doesNotMatch(serialized, new RegExp(storedKeyPair.protection.ciphertext));
});

test('credential test function never echoes the passphrase back, on success or failure', async () => {
	const { storedKeyPair, passphrase } = buildSignedFixture('yet-another-secret-passphrase-77');
	const node = new Besa();
	const testFn = node.methods.credentialTest.besaSigningKeyTest;

	const ok = await testFn.call(
		{},
		{
			id: '1',
			name: 'x',
			type: 'besaSigningKeyApi',
			data: {
				storedKeyPair: JSON.stringify(storedKeyPair),
				passphrase,
			},
		},
	);
	assert.equal(ok.status, 'OK');
	assert.doesNotMatch(ok.message, /yet-another-secret-passphrase-77/);

	const bad = await testFn.call(
		{},
		{
			id: '1',
			name: 'x',
			type: 'besaSigningKeyApi',
			data: {
				storedKeyPair: JSON.stringify(storedKeyPair),
				passphrase: 'wrong-guess-entirely',
			},
		},
	);
	assert.equal(bad.status, 'Error');
	assert.doesNotMatch(bad.message, /yet-another-secret-passphrase-77/);
	assert.doesNotMatch(bad.message, /wrong-guess-entirely/);
});

test('malformed credential JSON produces a safe error, not a raw parser dump of the credential', async () => {
	const { signedManifest } = buildSignedFixture();
	await assert.rejects(
		() =>
			run(
				{
					operation: 'createReceipt',
					signedManifestForReceipt: signedManifest,
					toolNameForReceipt: 'demo.echo',
					decision: 'allow',
					reasonCode: 'ALLOWED',
					request: {},
					agentId: '',
					grantReasonCode: '',
				},
				{
					credentials: { storedKeyPair: 'not even json {{{', passphrase: 'irrelevant-here-1234567890' },
				},
			),
		(error) => {
			assert.match(error.message, /does not contain valid JSON/);
			assert.doesNotMatch(error.message, /irrelevant-here-1234567890/);
			return true;
		},
	);
});
