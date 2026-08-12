/**
 * FROZEN v1.0 golden vectors — DO NOT REGENERATE.
 *
 * These artifacts were signed once with a throwaway Ed25519 keypair; the private
 * key was discarded and never stored. Only public material (public key,
 * signatures, hashes) is frozen here.
 *
 * The contract: any change to canonical serialization, domain separation, field
 * order, or hashing rules will cause these frozen artifacts to stop verifying —
 * which fails the golden tests. This is the mechanism that guarantees a receipt
 * signed today still verifies in five years. If a golden test breaks, the format
 * changed; that requires a new artifactVersion, never an edit to these vectors.
 */
import type { Receipt, SignedManifest } from "../../sdk.js";

export const GOLDEN_PUBLIC_KEY_DER =
  "MCowBQYDK2VwAyEAU8Rd381cF98qVQPwpA3v/aQJajeqGMh06YavYFmcLJM=";

export const GOLDEN_MANIFEST_HASH =
  "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504";

export const GOLDEN_REQUEST_HASH =
  "47791d544a584573594feaaefae1ef98c5a5b8859eca280281e8b7ed13ea576e";

/** Input and expected output that lock canonical JSON key ordering. */
export const GOLDEN_CANONICAL_ORDERING_INPUT = { b: 1, a: { d: 2, c: 3 } };
export const GOLDEN_CANONICAL_ORDERING = '{"a":{"c":3,"d":2},"b":1}';

/** The exact request object the golden receipt was signed over. */
export const GOLDEN_REQUEST = { customerId: "cust_0001" };

export const GOLDEN_SIGNED_MANIFEST: SignedManifest = {
  artifactVersion: 1,
  manifest: {
    serverName: "besa-golden",
    serverVersion: "1.0.0",
    serverUrl: "https://golden.besa.dev/mcp",
    createdAt: "2026-01-01T00:00:00.000Z",
    tools: [
      {
        name: "crm.lookup",
        description: "Look up a customer record.",
        capability: "read",
        risk: "low",
        scopes: ["crm:read"],
        budgetLimit: 100,
        inputSchema: {
          type: "object",
          properties: { customerId: { type: "string" } },
          required: ["customerId"],
        },
      },
    ],
  },
  manifestHash:
    "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
  algorithm: "ed25519",
  publicKey: "MCowBQYDK2VwAyEAU8Rd381cF98qVQPwpA3v/aQJajeqGMh06YavYFmcLJM=",
  publicKeyId:
    "0bccb1c411d1f3962902a629a4da9e9ed6a5aecd830af2f7f54c0d709c10c1ee",
  signedAt: "2026-07-11T21:39:12.664Z",
  signature:
    "SVmi+lwcAQUyRduQc+Y6Jf6dyOIe19z7qqYIxIzZzcR4bU7w4cKTxi5qiHRE6lsfChLkGdDUO7EG6Ogk+yzqCA==",
};

export const GOLDEN_RECEIPT: Receipt = {
  artifactVersion: 1,
  receiptId: "rcpt_b4e65921-85cc-4d8d-b152-d120f46a02fc",
  manifestHash:
    "8cc3e32f13dd1b0d4f5979b9510b368f18ff525cf5281be5fff469ac40984504",
  toolName: "crm.lookup",
  decision: "allow",
  reasonCode: "ALLOWED",
  timestamp: "2026-07-11T21:39:12.670Z",
  requestHash:
    "47791d544a584573594feaaefae1ef98c5a5b8859eca280281e8b7ed13ea576e",
  publicKeyId:
    "0bccb1c411d1f3962902a629a4da9e9ed6a5aecd830af2f7f54c0d709c10c1ee",
  algorithm: "ed25519",
  signature:
    "y8tnGrdDq16Z5Or0IVC13140c9QVkqFhIkH3J1vPcHIvQW9jXZpKk+GeNpK/vKwcgFc0d8h7LNXw+9AlIKssDg==",
};
