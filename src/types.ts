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