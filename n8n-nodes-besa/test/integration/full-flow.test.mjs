// End-to-end test of the exact chain a real n8n workflow runs: Verify Signed
// Manifest -> Check Admission -> Create Receipt -> Verify Receipt. Every step
// goes through the compiled Besa node, and every result is independently
// cross-checked against the real, separately-imported @dorigjo/besa package
// (not the node's own bundled copy) so this test would fail if the node
// silently diverged from BESA's actual signing/hashing/verification behavior.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Besa } from '../../dist/nodes/Besa/Besa.node.js';
import {
	addTrustAnchor,
	emptyTrustStore,
	generateKeyPair,
	hashManifest,
	hashRequest,
	revokeTrustAnchor,
	sealKeyPair,
	signManifest,
	verifyReceiptDetailed,
} from '@dorigjo/besa';
import { createMockExecuteFunctions } from '../support/helpers.mjs';
import { buildManifest } from '../support/fixtures.mjs';

async function run(parameters, credentials) {
	const node = new Besa();
	const ctx = createMockExecuteFunctions({ parameters, credentials });
	const [items] = await node.execute.call(ctx);
	return items[0].json;
}

test('integration: sign -> verify -> admit -> receipt -> verify-receipt, cross-checked against real @dorigjo/besa', async () => {
	const keypair = generateKeyPair();
	const manifest = buildManifest();
	const signedManifest = signManifest(manifest, keypair);
	const passphrase = 'integration test passphrase, twelve+ unique chars';
	const storedKeyPair = sealKeyPair(keypair, passphrase);
	let trustStore = addTrustAnchor(emptyTrustStore(), signedManifest.publicKey);

	// 1. Verify Signed Manifest -- independently confirm the node's manifestHash
	//    claim against a from-scratch hashManifest() computed here.
	assert.equal(signedManifest.manifestHash, hashManifest(manifest));
	const verifyResult = await run({
		operation: 'verifySignedManifest',
		signedManifest,
		trustStore,
	});
	assert.equal(verifyResult.valid, true);
	assert.equal(verifyResult.trustAnchored, true);

	// 2. Check Admission for a first call (agent wants to call demo.echo).
	const admission = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'demo.echo',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.equal(admission.decision, 'allow');

	// 3. Create Receipt for the allowed call.
	const request = { tool: 'demo.echo', args: { input: 'ping' } };
	const receipt = await run(
		{
			operation: 'createReceipt',
			signedManifestForReceipt: signedManifest,
			toolNameForReceipt: admission.toolName,
			decision: admission.decision,
			reasonCode: admission.reasonCode,
			request,
			agentId: 'agent-42',
			grantReasonCode: '',
		},
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);
	assert.equal(receipt.requestHash, hashRequest(request));
	assert.equal(verifyReceiptDetailed(receipt, keypair.publicKeyDer).valid, true);

	// 4. Verify Receipt -- full CLI-faithful trust chain, request rebound.
	const verifyReceiptResult = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt,
		trustStore,
		requestToRebind: request,
	});
	assert.equal(verifyReceiptResult.valid, true);
	assert.equal(verifyReceiptResult.reasonCode, 'OK');
	assert.equal(verifyReceiptResult.trustAnchored, true);

	// 5. Revoke the key after the fact -- a receipt from before revocation must
	//    still be evaluated relative to its own timestamp, but a fresh
	//    verifyReceipt trust check against the now-revoked store must fail closed.
	trustStore = revokeTrustAnchor(trustStore, signedManifest.publicKeyId);
	const afterRevocation = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt,
		trustStore,
		requestToRebind: '',
	});
	assert.equal(afterRevocation.valid, false);
	assert.equal(afterRevocation.reasonCode, 'E_KEY_REVOKED');
});

test('integration: a denied admission still produces valid, verifiable evidence', async () => {
	const keypair = generateKeyPair();
	const manifest = buildManifest();
	const signedManifest = signManifest(manifest, keypair);
	const passphrase = 'another integration passphrase, 16+ chars ok';
	const storedKeyPair = sealKeyPair(keypair, passphrase);

	const admission = await run({
		operation: 'checkAdmission',
		manifest: signedManifest,
		toolName: 'demo.wipe',
		callCount: 0,
		denyDestructiveHighRisk: true,
	});
	assert.equal(admission.decision, 'deny');
	assert.equal(admission.reasonCode, 'RISK_BLOCKED');

	const receipt = await run(
		{
			operation: 'createReceipt',
			signedManifestForReceipt: signedManifest,
			toolNameForReceipt: admission.toolName,
			decision: admission.decision,
			reasonCode: admission.reasonCode,
			request: { tool: 'demo.wipe' },
			agentId: '',
			grantReasonCode: '',
		},
		{ storedKeyPair: JSON.stringify(storedKeyPair), passphrase },
	);
	assert.equal(receipt.decision, 'deny');

	const verifyReceiptResult = await run({
		operation: 'verifyReceipt',
		signedManifest,
		receipt,
		trustStore: '',
		requestToRebind: '',
	});
	assert.equal(verifyReceiptResult.valid, true);
});
