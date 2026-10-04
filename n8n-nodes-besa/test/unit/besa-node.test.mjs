import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Besa } from '../../dist/nodes/Besa/Besa.node.js';
import { addTrustAnchor, emptyTrustStore, verifyReceiptDetailed } from '@dorigjo/besa';
import { createMockExecuteFunctions } from '../support/helpers.mjs';
import { buildSignedFixture } from '../support/fixtures.mjs';

async function run(parameters, credentials) {
	const node = new Besa();
	const ctx = createMockExecuteFunctions({ parameters, credentials });
	const [items] = await node.execute.call(ctx);
	assert.equal(items.length, 1);
	return items[0].json;
}

// --- Verify Signed Manifest ---

test('verifySignedManifest: valid signature, no trust store -> valid, not trust-anchored', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'verifySignedManifest',
		signedManifest,
		trustStore: '',
	});
	assert.equal(result.valid, true);
	assert.equal(result.reasonCode, 'OK');
	assert.equal(result.trustAnchored, false);
});

test('verifySignedManifest: key present as active trust anchor -> valid, trust-anchored', async () => {
	const { signedManifest } = buildSignedFixture();
	const trustStore = addTrustAnchor(emptyTrustStore(), signedManifest.publicKey);
	const result = await run({
		operation: 'verifySignedManifest',
		signedManifest,
		trustStore,
	});
	assert.equal(result.valid, true);
	assert.equal(result.trustAnchored, true);
});

test('verifySignedManifest: empty trust store -> untrusted, fails closed', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'verifySignedManifest',
		signedManifest,
		trustStore: emptyTrustStore(),
	});
	assert.equal(result.valid, false);
	assert.equal(result.reasonCode, 'E_KEY_UNTRUSTED');
	assert.equal(result.trustAnchored, true);
});

test('verifySignedManifest: tampered manifest content -> hash mismatch', async () => {
	const { signedManifest } = buildSignedFixture();
	const tampered = {
		...signedManifest,
		manifest: { ...signedManifest.manifest, serverName: 'attacker-controlled' },
	};
	const result = await run({
		operation: 'verifySignedManifest',
		signedManifest: tampered,
		trustStore: '',
	});
	assert.equal(result.valid, false);
	assert.equal(result.reasonCode, 'E_MANIFEST_HASH_MISMATCH');
});

// --- Check Admission ---

test('checkAdmission: within budget -> ALLOWED', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'demo.echo',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.deepEqual(result, {
		decision: 'allow',
		reasonCode: 'ALLOWED',
		toolName: 'demo.echo',
		detail: 'tool call admitted',
	});
});

test('checkAdmission: budget exhausted -> BUDGET_EXCEEDED deny (never throws)', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'demo.echo',
		callCount: 3, // budgetLimit is 3
		denyDestructiveHighRisk: true,
	});
	assert.equal(result.decision, 'deny');
	assert.equal(result.reasonCode, 'BUDGET_EXCEEDED');
});

test('checkAdmission: unknown tool -> TOOL_NOT_FOUND deny', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'does.not.exist',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.equal(result.decision, 'deny');
	assert.equal(result.reasonCode, 'TOOL_NOT_FOUND');
});

test('checkAdmission: destructive+high-risk tool blocked by default policy', async () => {
	const { signedManifest } = buildSignedFixture();
	const result = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'demo.wipe',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.equal(result.decision, 'deny');
	assert.equal(result.reasonCode, 'RISK_BLOCKED');
});

test('checkAdmission: accepts a bare manifest (not just a signed envelope)', async () => {
	const { manifest } = buildSignedFixture();
	const result = await run({
		operation: 'checkAdmission',
		manifest,
		toolName: 'demo.echo',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.equal(result.decision, 'allow');
});

// --- Create Receipt ---

test('createReceipt: produces a receipt that verifies against the real public key', async () => {
	const { signedManifest, keypair, storedKeyPair, passphrase } = buildSignedFixture();
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
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);

	assert.equal(receipt.manifestHash, signedManifest.manifestHash);
	assert.equal(receipt.toolName, 'demo.echo');
	assert.equal(receipt.decision, 'allow');
	assert.match(receipt.receiptId, /^rcpt_/);
	assert.equal(verifyReceiptDetailed(receipt, keypair.publicKeyDer).valid, true);
});

test('createReceipt: deny decision is still signed as real evidence', async () => {
	const { signedManifest, keypair, storedKeyPair, passphrase } = buildSignedFixture();
	const receipt = await run(
		{
			operation: 'createReceipt',
			signedManifestForReceipt: signedManifest,
			toolNameForReceipt: 'demo.wipe',
			decision: 'deny',
			reasonCode: 'RISK_BLOCKED',
			request: { input: 'rm -rf /' },
			agentId: '',
			grantReasonCode: '',
		},
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);
	assert.equal(receipt.decision, 'deny');
	assert.equal(verifyReceiptDetailed(receipt, keypair.publicKeyDer).valid, true);
});

test('createReceipt: wrong passphrase throws a non-leaking NodeOperationError', async () => {
	const { signedManifest, storedKeyPair } = buildSignedFixture('correct horse battery staple 42');
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
				{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase: 'totally the wrong passphrase!!' },
			),
		(error) => {
			assert.match(error.message, /key file authentication failed/i);
			assert.doesNotMatch(error.message, /correct horse battery staple/);
			return true;
		},
	);
});

// --- Verify Receipt ---

test('verifyReceipt: full valid chain with trust store', async () => {
	const { signedManifest, storedKeyPair, passphrase } = buildSignedFixture();
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
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);
	const trustStore = addTrustAnchor(emptyTrustStore(), signedManifest.publicKey);

	const result = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt,
		trustStore,
		requestToRebind: '',
	});
	assert.equal(result.valid, true);
	assert.equal(result.trustAnchored, true);
});

test('verifyReceipt: request rebinding catches a swapped request payload', async () => {
	const { signedManifest, storedKeyPair, passphrase } = buildSignedFixture();
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
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);

	const result = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt,
		trustStore: '',
		requestToRebind: { input: 'a different request entirely' },
	});
	assert.equal(result.valid, false);
	assert.equal(result.reasonCode, 'E_RECEIPT_REQUEST_MISMATCH');
});

test('verifyReceipt: tampered receipt signature is rejected', async () => {
	const { signedManifest, storedKeyPair, passphrase } = buildSignedFixture();
	const receipt = await run(
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
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);
	const tampered = { ...receipt, toolName: 'demo.wipe' };

	const result = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt: tampered,
		trustStore: '',
		requestToRebind: '',
	});
	assert.equal(result.valid, false);
	assert.equal(result.reasonCode, 'E_SIGNATURE_INVALID');
});
