/**
 * Replacement v1.4 conformance vectors using the reserved neutral test domain.
 * Signed with a dedicated throwaway Ed25519 keypair; the private key was never
 * stored. Artifact version and signing semantics remain v1-compatible. The
 * previously published v1.3 vectors remain immutable in their release history.
 */
import type { Receipt, SignedManifest } from "../../sdk.js";

export const GOLDEN_PUBLIC_KEY_DER =
  "MCowBQYDK2VwAyEA3SYqrtd0l8qbQf3EpgUYU4Fbwm1YHgrWXirOaeXfQpE=";

export const GOLDEN_MANIFEST_HASH =
  "4c52ba59ecd6c6ee6f865c5c727ce3cb52a2392388068c9f3209f4c25d1eaf29";

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
    serverUrl: "https://golden.example.com/mcp",
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
    "4c52ba59ecd6c6ee6f865c5c727ce3cb52a2392388068c9f3209f4c25d1eaf29",
  algorithm: "ed25519",
  publicKey: "MCowBQYDK2VwAyEA3SYqrtd0l8qbQf3EpgUYU4Fbwm1YHgrWXirOaeXfQpE=",
  publicKeyId:
    "5c76b07f364ed26b90eb557cb3b223d1bf72bf2d9bc44f896108eaaf2e1b508b",
  signedAt: "2026-11-14T22:32:10.411Z",
  signature:
    "7WgjFEyL61SusqkNerwy8PJrG7N/g6dRMRRNEae8IjjPfyo4vYww49ygffYK60YGr5G/y1z9k3/KwLTd6qEiCQ==",
};

export const GOLDEN_RECEIPT: Receipt = {
  artifactVersion: 1,
  receiptId: "rcpt_791934b0-c0dc-4ec3-b1cf-55c20dedcf43",
  manifestHash:
    "4c52ba59ecd6c6ee6f865c5c727ce3cb52a2392388068c9f3209f4c25d1eaf29",
  toolName: "crm.lookup",
  decision: "allow",
  reasonCode: "ALLOWED",
  timestamp: "2026-11-14T22:32:10.415Z",
  requestHash:
    "47791d544a584573594feaaefae1ef98c5a5b8859eca280281e8b7ed13ea576e",
  publicKeyId:
    "5c76b07f364ed26b90eb557cb3b223d1bf72bf2d9bc44f896108eaaf2e1b508b",
  algorithm: "ed25519",
  signature:
    "OcOupWQFRlTmHS0M4TNlxm+b8neNcpJPoZnBELkDi1tvhkhC97jc2Uj89ayRPzlua2DWxiafTS7Nuc1+ECZLDA==",
};
