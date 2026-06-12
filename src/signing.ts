import {
randomUUID,
sign as ed25519Sign,
verify as ed25519Verify
} from "node:crypto";
import type { Decision, Manifest, Receipt, SignedManifest } from "./types.js";
import {
canonicalize,
hashObject,
privateKeyFromDer,
publicKeyFromDer,
publicKeyId,
type KeyPair
} from "./crypto.js";

export interface VerifyResult {
valid: boolean;
reasonCode: string;
detail: string;
}

export interface ReceiptInput {
manifestHash: string;
toolName: string;
decision: Decision;
reasonCode: string;
request: unknown;
}

export function hashManifest(manifest: Manifest): string {
return hashObject(manifest);
}

export function signManifest(manifest: Manifest, keypair: KeyPair): SignedManifest {
const canonical = canonicalize(manifest);
const signature = ed25519Sign(
null,
Buffer.from(canonical, "utf8"),
privateKeyFromDer(keypair.privateKeyDer)
);

return {
manifest,
manifestHash: hashManifest(manifest),
algorithm: "ed25519",
publicKey: keypair.publicKeyDer,
publicKeyId: publicKeyId(keypair.publicKeyDer),
signature: signature.toString("base64"),
signedAt: new Date().toISOString()
};
}

export function verifySignedManifest(signed: SignedManifest): VerifyResult {
if (signed.algorithm !== "ed25519") {
return {
valid: false,
reasonCode: "E_ALGORITHM_UNSUPPORTED",
detail: "only ed25519 signed manifests are supported"
};
}

const canonical = canonicalize(signed.manifest);
const expectedHash = hashManifest(signed.manifest);

if (expectedHash !== signed.manifestHash) {
return {
valid: false,
reasonCode: "E_MANIFEST_HASH_MISMATCH",
detail: "manifest content does not match stored hash"
};
}

if (publicKeyId(signed.publicKey) !== signed.publicKeyId) {
return {
valid: false,
reasonCode: "E_PUBLIC_KEY_ID_MISMATCH",
detail: "publicKeyId does not match publicKey"
};
}

try {
const valid = ed25519Verify(
null,
Buffer.from(canonical, "utf8"),
publicKeyFromDer(signed.publicKey),
Buffer.from(signed.signature, "base64")
);

if (!valid) {
  return {
    valid: false,
    reasonCode: "E_SIGNATURE_INVALID",
    detail: "signature does not verify against the public key"
  };
}

return {
  valid: true,
  reasonCode: "OK",
  detail: "manifest signature is valid"
};

} catch {
return {
valid: false,
reasonCode: "E_SIGNATURE_CHECK_FAILED",
detail: "signature verification failed"
};
}
}

export function createReceipt(input: ReceiptInput, keypair: KeyPair): Receipt {
const body: Omit<Receipt, "signature"> = {
receiptId: "rcpt_" + randomUUID(),
manifestHash: input.manifestHash,
toolName: input.toolName,
decision: input.decision,
reasonCode: input.reasonCode,
timestamp: new Date().toISOString(),
requestHash: hashObject(input.request ?? {}),
publicKeyId: publicKeyId(keypair.publicKeyDer),
algorithm: "ed25519"
};

const signature = ed25519Sign(
null,
Buffer.from(canonicalize(body), "utf8"),
privateKeyFromDer(keypair.privateKeyDer)
);

return {
...body,
signature: signature.toString("base64")
};
}

export function verifyReceipt(receipt: Receipt, publicKeyDer: string): boolean {
if (receipt.algorithm !== "ed25519") {
return false;
}

if (publicKeyId(publicKeyDer) !== receipt.publicKeyId) {
return false;
}

const { signature, ...body } = receipt;

try {
return ed25519Verify(
null,
Buffer.from(canonicalize(body), "utf8"),
publicKeyFromDer(publicKeyDer),
Buffer.from(signature, "base64")
);
} catch {
return false;
}
}