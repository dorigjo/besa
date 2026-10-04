import type {
	ICredentialsDecrypted,
	ICredentialTestFunctions,
	IDataObject,
	IExecuteFunctions,
	INodeCredentialTestResult,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import {
	admit,
	createReceipt,
	DEFAULT_POLICY,
	hashRequest,
	openKeyPair,
	publicKeyId,
	validateReceipt,
	verifyReceiptDetailed,
	verifySignedManifest,
	verifyTrustedSignedManifest,
	checkTrustedKey,
	emptyTrustStore,
	type AdmissionPolicy,
	type Manifest,
	type ReceiptInput,
	type SignedManifest,
	type TrustStore,
} from '@dorigjo/besa';

const OPERATION_VERIFY_MANIFEST = 'verifySignedManifest';
const OPERATION_CHECK_ADMISSION = 'checkAdmission';
const OPERATION_CREATE_RECEIPT = 'createReceipt';
const OPERATION_VERIFY_RECEIPT = 'verifyReceipt';

function parseJsonParameter(
	ctx: IExecuteFunctions,
	itemIndex: number,
	raw: unknown,
	label: string,
): unknown {
	if (raw === undefined || raw === null || raw === '') {
		return undefined;
	}
	if (typeof raw === 'object') {
		return raw;
	}
	if (typeof raw !== 'string') {
		throw new NodeOperationError(ctx.getNode(), `${label} must be a JSON object or a JSON string`, {
			itemIndex,
		});
	}
	try {
		return JSON.parse(raw);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		throw new NodeOperationError(ctx.getNode(), `${label} is not valid JSON: ${message}`, { itemIndex });
	}
}

function requireJsonObject(
	ctx: IExecuteFunctions,
	itemIndex: number,
	raw: unknown,
	label: string,
): Record<string, unknown> {
	const parsed = parseJsonParameter(ctx, itemIndex, raw, label);
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
		throw new NodeOperationError(ctx.getNode(), `${label} must be a JSON object`, { itemIndex });
	}
	return parsed as Record<string, unknown>;
}

// Accepts either a full SignedManifest ({ manifest: {...}, manifestHash, ... })
// or a bare Manifest ({ serverName, tools, ... }) so the node stays useful both
// right after "Verify Signed Manifest" (which hands back the signed envelope)
// and when a caller already extracted the inner manifest.
function extractManifest(value: Record<string, unknown>): Manifest {
	if (value.manifest && typeof value.manifest === 'object' && !Array.isArray(value.manifest)) {
		return value.manifest as Manifest;
	}
	return value as unknown as Manifest;
}

export class Besa implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Besa',
		name: 'besa',
		icon: { light: 'file:besa.svg', dark: 'file:besa.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description:
			'Verify Besa signed manifests, gate tool calls through Besa admission policy, and issue signed Besa execution receipts',
		defaults: {
			name: 'Besa',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'besaSigningKeyApi',
				required: true,
				testedBy: 'besaSigningKeyTest',
				displayOptions: {
					show: {
						operation: [OPERATION_CREATE_RECEIPT],
					},
				},
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				default: OPERATION_VERIFY_MANIFEST,
				options: [
					{
						name: 'Verify Signed Manifest',
						value: OPERATION_VERIFY_MANIFEST,
						description:
							"Check a signed manifest's internal signature (and, optionally, that its key is in a trust store)",
						action: 'Verify a signed manifest',
					},
					{
						name: 'Check Admission',
						value: OPERATION_CHECK_ADMISSION,
						description: 'Run the Besa admission policy for one tool call (allow/deny, no state written)',
						action: 'Check admission for a tool call',
					},
					{
						name: 'Create Receipt',
						value: OPERATION_CREATE_RECEIPT,
						description: 'Sign a tamper-evident execution receipt for an admission decision',
						action: 'Create a signed receipt',
					},
					{
						name: 'Verify Receipt',
						value: OPERATION_VERIFY_RECEIPT,
						description: 'Verify a receipt against its signed manifest (and, optionally, a trust store)',
						action: 'Verify a receipt',
					},
				],
			},
			// --- Verify Signed Manifest ---
			{
				displayName: 'Signed Manifest',
				name: 'signedManifest',
				type: 'json',
				default: '',
				required: true,
				displayOptions: {
					show: { operation: [OPERATION_VERIFY_MANIFEST, OPERATION_VERIFY_RECEIPT] },
				},
				description: 'The signed manifest JSON produced by "besa sign"',
			},
			{
				displayName: 'Trust Store',
				name: 'trustStore',
				type: 'json',
				default: '',
				displayOptions: {
					show: { operation: [OPERATION_VERIFY_MANIFEST, OPERATION_VERIFY_RECEIPT] },
				},
				description:
					"Optional Besa trust store JSON. When provided, the manifest's signing key must be an active trust anchor, not just internally self-consistent. When omitted, only the signature/self-consistency is checked (no trust decision is made).",
			},
			// --- Check Admission ---
			{
				displayName: 'Manifest',
				name: 'manifest',
				type: 'json',
				default: '',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CHECK_ADMISSION] } },
				description: 'A signed manifest or a bare manifest JSON containing the tool to check',
			},
			{
				displayName: 'Tool Name',
				name: 'toolName',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CHECK_ADMISSION] } },
			},
			{
				displayName: 'Call Count',
				name: 'callCount',
				type: 'number',
				default: 0,
				required: true,
				displayOptions: { show: { operation: [OPERATION_CHECK_ADMISSION] } },
				description:
					'Number of times this tool has already been called (the caller tracks this; Besa never writes state)',
			},
			{
				displayName: 'Deny Destructive+High-Risk Tools',
				name: 'denyDestructiveHighRisk',
				type: 'boolean',
				default: true,
				displayOptions: { show: { operation: [OPERATION_CHECK_ADMISSION] } },
				description: 'Whether to deny any tool declared as capability=destructive and risk=high, regardless of budget',
			},
			// --- Create Receipt ---
			{
				displayName: 'Signed Manifest',
				name: 'signedManifestForReceipt',
				type: 'json',
				default: '',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
				description: 'The signed manifest the receipt is evidence for (its manifestHash is sealed into the receipt)',
			},
			{
				displayName: 'Tool Name',
				name: 'toolNameForReceipt',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
			},
			{
				displayName: 'Decision',
				name: 'decision',
				type: 'options',
				default: 'allow',
				options: [
					{ name: 'Allow', value: 'allow' },
					{ name: 'Deny', value: 'deny' },
				],
				required: true,
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
				description: 'The admission decision this receipt records (a deny receipt is still real, signed evidence)',
			},
			{
				displayName: 'Reason Code',
				name: 'reasonCode',
				type: 'string',
				default: 'ALLOWED',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
				description: 'Uppercase machine-readable reason, e.g. ALLOWED, RISK_BLOCKED, BUDGET_EXCEEDED, TOOL_NOT_FOUND',
			},
			{
				displayName: 'Request',
				name: 'request',
				type: 'json',
				default: '{}',
				required: true,
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
				description: 'The tool-call request payload; its hash is sealed into the receipt as requestHash',
			},
			{
				displayName: 'Agent ID',
				name: 'agentId',
				type: 'string',
				default: '',
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
			},
			{
				displayName: 'Grant Reason Code',
				name: 'grantReasonCode',
				type: 'string',
				default: '',
				displayOptions: { show: { operation: [OPERATION_CREATE_RECEIPT] } },
				description: 'Only meaningful when Agent ID is set',
			},
			// --- Verify Receipt ---
			{
				displayName: 'Receipt',
				name: 'receipt',
				type: 'json',
				default: '',
				required: true,
				displayOptions: { show: { operation: [OPERATION_VERIFY_RECEIPT] } },
			},
			{
				displayName: 'Original Request',
				name: 'requestToRebind',
				type: 'json',
				default: '',
				displayOptions: { show: { operation: [OPERATION_VERIFY_RECEIPT] } },
				description: "Optional. When provided, its hash must match the receipt's requestHash exactly.",
			},
		],
	};

	methods = {
		credentialTest: {
			async besaSigningKeyTest(
				this: ICredentialTestFunctions,
				credential: ICredentialsDecrypted,
			): Promise<INodeCredentialTestResult> {
				const data = credential.data ?? {};
				const storedKeyPairRaw = data.storedKeyPair as string | undefined;
				const passphrase = data.passphrase as string | undefined;

				if (!storedKeyPairRaw || !passphrase) {
					return { status: 'Error', message: 'Both the stored key pair and passphrase are required.' };
				}

				let storedKeyPair: unknown;
				try {
					storedKeyPair = JSON.parse(storedKeyPairRaw);
				} catch {
					return { status: 'Error', message: 'Stored key pair is not valid JSON.' };
				}

				try {
					const keypair = openKeyPair(storedKeyPair, passphrase);
					return {
						status: 'OK',
						message: `Key pair decrypted successfully (public key id ${publicKeyId(keypair.publicKeyDer)}).`,
					};
				} catch (error) {
					// openKeyPair() throws a fixed, non-leaking message on failure --
					// never includes the passphrase or key bytes.
					const message = error instanceof Error ? error.message : 'Key file authentication failed.';
					return { status: 'Error', message };
				}
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const operation = this.getNodeParameter('operation', 0) as string;
		const returnData: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				let result: IDataObject;

				if (operation === OPERATION_VERIFY_MANIFEST) {
					result = runVerifySignedManifest(this, itemIndex);
				} else if (operation === OPERATION_CHECK_ADMISSION) {
					result = runCheckAdmission(this, itemIndex);
				} else if (operation === OPERATION_CREATE_RECEIPT) {
					result = await runCreateReceipt(this, itemIndex);
				} else if (operation === OPERATION_VERIFY_RECEIPT) {
					result = runVerifyReceipt(this, itemIndex);
				} else {
					throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, { itemIndex });
				}

				returnData.push({
					json: result,
					pairedItem: itemIndex,
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: error instanceof Error ? error.message : String(error) },
						pairedItem: itemIndex,
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex });
			}
		}

		return [returnData];
	}
}

function runVerifySignedManifest(ctx: IExecuteFunctions, itemIndex: number): IDataObject {
	const signedManifest = requireJsonObject(
		ctx,
		itemIndex,
		ctx.getNodeParameter('signedManifest', itemIndex),
		'Signed Manifest',
	);
	const trustStoreRaw = ctx.getNodeParameter('trustStore', itemIndex);
	const trustStoreParsed = parseJsonParameter(ctx, itemIndex, trustStoreRaw, 'Trust Store');

	if (trustStoreParsed !== undefined) {
		const trustStore = trustStoreParsed as TrustStore;
		const result = verifyTrustedSignedManifest(signedManifest, trustStore);
		return { ...result, trustAnchored: true };
	}

	const result = verifySignedManifest(signedManifest);
	return { ...result, trustAnchored: false };
}

function runCheckAdmission(ctx: IExecuteFunctions, itemIndex: number): IDataObject {
	const manifestInput = requireJsonObject(
		ctx,
		itemIndex,
		ctx.getNodeParameter('manifest', itemIndex),
		'Manifest',
	);
	const manifest = extractManifest(manifestInput);
	const toolName = ctx.getNodeParameter('toolName', itemIndex) as string;
	const callCount = ctx.getNodeParameter('callCount', itemIndex) as number;
	const denyDestructiveHighRisk = ctx.getNodeParameter('denyDestructiveHighRisk', itemIndex) as boolean;
	const policy: AdmissionPolicy = { ...DEFAULT_POLICY, denyDestructiveHighRisk };

	const decision = admit(manifest, toolName, callCount, policy);
	return { ...decision };
}

async function runCreateReceipt(ctx: IExecuteFunctions, itemIndex: number): Promise<IDataObject> {
	const signedManifest = requireJsonObject(
		ctx,
		itemIndex,
		ctx.getNodeParameter('signedManifestForReceipt', itemIndex),
		'Signed Manifest',
	) as unknown as SignedManifest;
	const toolName = ctx.getNodeParameter('toolNameForReceipt', itemIndex) as string;
	const decision = ctx.getNodeParameter('decision', itemIndex) as 'allow' | 'deny';
	const reasonCode = ctx.getNodeParameter('reasonCode', itemIndex) as string;
	const request = parseJsonParameter(ctx, itemIndex, ctx.getNodeParameter('request', itemIndex), 'Request');
	const agentId = (ctx.getNodeParameter('agentId', itemIndex) as string) || undefined;
	const grantReasonCode = (ctx.getNodeParameter('grantReasonCode', itemIndex) as string) || undefined;

	const credentials = await ctx.getCredentials('besaSigningKeyApi');
	const storedKeyPairRaw = credentials.storedKeyPair as string;
	const passphrase = credentials.passphrase as string;

	let storedKeyPair: unknown;
	try {
		storedKeyPair = JSON.parse(storedKeyPairRaw);
	} catch {
		// Never echo the raw credential value back into an error message.
		throw new NodeOperationError(ctx.getNode(), 'Besa Signing Key credential does not contain valid JSON', {
			itemIndex,
		});
	}

	// openKeyPair() throws a fixed, non-leaking message on any failure
	// ("key file authentication failed" / "encrypted key file is malformed or
	// unsupported") -- it never includes the passphrase or key bytes, so this
	// is safe to let propagate as-is.
	const keypair = openKeyPair(storedKeyPair, passphrase);

	const input: ReceiptInput = {
		manifestHash: signedManifest.manifestHash,
		toolName,
		decision,
		reasonCode,
		request,
		...(agentId ? { agentId } : {}),
		...(grantReasonCode ? { grantReasonCode } : {}),
	};

	const receipt = createReceipt(input, keypair);
	return { ...receipt };
}

function runVerifyReceipt(ctx: IExecuteFunctions, itemIndex: number): IDataObject {
	const signedManifest = requireJsonObject(
		ctx,
		itemIndex,
		ctx.getNodeParameter('signedManifest', itemIndex),
		'Signed Manifest',
	) as unknown as SignedManifest;
	const receiptRaw = ctx.getNodeParameter('receipt', itemIndex);
	const trustStoreRaw = ctx.getNodeParameter('trustStore', itemIndex);
	const trustStoreParsed = parseJsonParameter(ctx, itemIndex, trustStoreRaw, 'Trust Store');
	const requestToRebindRaw = ctx.getNodeParameter('requestToRebind', itemIndex);
	const requestToRebind = parseJsonParameter(ctx, itemIndex, requestToRebindRaw, 'Original Request');

	const trustAnchored = trustStoreParsed !== undefined;
	const trustStore = (trustStoreParsed as TrustStore | undefined) ?? emptyTrustStore();

	const manifestVerification = trustAnchored
		? verifyTrustedSignedManifest(signedManifest, trustStore)
		: verifySignedManifest(signedManifest);

	if (!manifestVerification.valid) {
		return { ...manifestVerification, trustAnchored };
	}

	const receiptRawParsed = parseJsonParameter(ctx, itemIndex, receiptRaw, 'Receipt');
	const receiptValidation = validateReceipt(receiptRawParsed);

	if (!receiptValidation.ok || !receiptValidation.receipt) {
		return {
			valid: false,
			reasonCode: 'E_RECEIPT_INVALID',
			detail: receiptValidation.errors.join('; '),
			trustAnchored,
		};
	}

	const receipt = receiptValidation.receipt;

	if (receipt.manifestHash !== signedManifest.manifestHash) {
		return {
			valid: false,
			reasonCode: 'E_RECEIPT_MANIFEST_MISMATCH',
			detail: 'receipt manifestHash does not match the signed manifest',
			trustAnchored,
		};
	}

	if (
		receipt.decision === 'allow' &&
		!signedManifest.manifest.tools.some((tool) => tool.name === receipt.toolName)
	) {
		return {
			valid: false,
			reasonCode: 'E_RECEIPT_TOOL_NOT_DECLARED',
			detail: 'allow receipt references a tool not declared in the signed manifest',
			trustAnchored,
		};
	}

	if (requestToRebind !== undefined && hashRequest(requestToRebind) !== receipt.requestHash) {
		return {
			valid: false,
			reasonCode: 'E_RECEIPT_REQUEST_MISMATCH',
			detail: 'supplied request does not hash to the receipt requestHash',
			trustAnchored,
		};
	}

	const signatureResult = verifyReceiptDetailed(receipt, signedManifest.publicKey);

	if (!signatureResult.valid) {
		return { ...signatureResult, trustAnchored };
	}

	if (trustAnchored) {
		const trustResult = checkTrustedKey(trustStore, signedManifest.publicKey, receipt.timestamp);
		return { ...trustResult, trustAnchored };
	}

	return { ...signatureResult, trustAnchored };
}
