export type CapabilityType = "read" | "write" | "destructive";

export type RiskLevel = "low" | "medium" | "high";

export type Decision = "allow" | "deny";

export interface ToolDefinition {
  name: string;
  description: string;
  capability: CapabilityType;
  risk: RiskLevel;
  scopes: string[];
  budgetLimit: number;
  inputSchema: Record<string, unknown>;
}

export interface Manifest {
  serverName: string;
  serverVersion: string;
  serverUrl: string;
  createdAt: string;
  tools: ToolDefinition[];
}

export interface SignedManifest {
  artifactVersion: 1;
  manifest: Manifest;
  manifestHash: string;
  algorithm: "ed25519";
  publicKey: string;
  publicKeyId: string;
  signature: string;
  signedAt: string;
}

export interface AdmissionDecision {
  decision: Decision;
  reasonCode: string;
  toolName: string;
  detail: string;
  agentId?: string;
}

export interface Receipt {
  artifactVersion: 1;
  receiptId: string;
  manifestHash: string;
  toolName: string;
  decision: Decision;
  reasonCode: string;
  timestamp: string;
  requestHash: string;
  publicKeyId: string;
  algorithm: "ed25519";
  agentId?: string;
  grantReasonCode?: string;
  signature: string;
}

export interface Grant {
  agentId: string;
  tools: string[];
}

export interface GrantSet {
  grants: Grant[];
}

export interface GrantDecision {
  granted: boolean;
  reasonCode: string;
  agentId: string;
  toolName: string;
  detail: string;
}

export type TrustKeyStatus = "active" | "retired" | "revoked";

export interface TrustAnchor {
  publicKeyId: string;
  publicKey: string;
  status: TrustKeyStatus;
  addedAt: string;
  retiredAt?: string;
  revokedAt?: string;
}

export interface TrustStore {
  version: 1;
  keys: TrustAnchor[];
}

export interface KeyRotation {
  artifactVersion: 1;
  algorithm: "ed25519";
  previousPublicKey: string;
  previousPublicKeyId: string;
  newPublicKey: string;
  newPublicKeyId: string;
  rotatedAt: string;
  signature: string;
}
