import type { Icon, ICredentialType, INodeProperties } from 'n8n-workflow';

export class BesaSigningKeyApi implements ICredentialType {
	name = 'besaSigningKeyApi';

	displayName = 'Besa Signing Key API';

	icon: Icon = { light: 'file:../nodes/Besa/besa.svg', dark: 'file:../nodes/Besa/besa.dark.svg' };

	documentationUrl = 'https://github.com/dorigjo/besa/blob/main/n8n-nodes-besa/README.md';

	properties: INodeProperties[] = [
		{
			displayName: 'Stored Key Pair (.besa/key.json contents)',
			name: 'storedKeyPair',
			type: 'string',
			typeOptions: {
				rows: 8,
			},
			default: '',
			required: true,
			description:
				'The full JSON contents of the encrypted key file created or loaded by "besa keys" (normally .besa/key.json). This is the AES-256-GCM/scrypt-sealed key, never a raw private key.',
		},
		{
			displayName: 'Passphrase',
			name: 'passphrase',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description:
				'The passphrase used to seal the key pair. Only used in-memory to decrypt the key during a single Create Receipt execution; never stored or logged by this node.',
		},
	];
}
