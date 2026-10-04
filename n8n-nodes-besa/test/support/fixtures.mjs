import { generateKeyPair, sealKeyPair, signManifest } from '@dorigjo/besa';

export function buildManifest(overrides = {}) {
	return {
		serverName: 'test-mcp-server',
		serverVersion: '1.0.0',
		serverUrl: 'https://example.invalid/mcp',
		createdAt: '2026-01-01T00:00:00.000Z',
		tools: [
			{
				name: 'demo.echo',
				description: 'Echoes the request back; used only for testing/demo workflows.',
				capability: 'read',
				risk: 'low',
				scopes: ['demo'],
				budgetLimit: 3,
				inputSchema: { type: 'object' },
			},
			{
				name: 'demo.wipe',
				description: 'A destructive+high-risk tool, present only to exercise policy denial.',
				capability: 'destructive',
				risk: 'high',
				scopes: ['demo'],
				budgetLimit: 100,
				inputSchema: { type: 'object' },
			},
		],
		...overrides,
	};
}

export function buildSignedFixture(passphrase = 'correct horse battery staple 42') {
	const keypair = generateKeyPair();
	const manifest = buildManifest();
	const signedManifest = signManifest(manifest, keypair);
	const storedKeyPair = sealKeyPair(keypair, passphrase);
	return { keypair, manifest, signedManifest, storedKeyPair, passphrase };
}
