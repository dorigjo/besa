import type { Decision, Receipt, SignedManifest, TrustStore } from "./types.js";
import { verifyReceiptDetailed } from "./signing.js";
import { verifyTrustedSignedManifest } from "./trust.js";

// A regulatory/audit-facing export format. It repackages data that is
// already independently verifiable (a signed manifest + a signed receipt)
// into one structured document. It intentionally carries no signature of
// its own: every fact it states can be re-derived and re-verified by the
// recipient directly from the enclosed manifestHash/receiptId against the
// original signed artifacts, the same way the hosted verifier's VerifyResult
// is returned unsigned. Precedent: docs/HOSTED_VERIFIER.md.
export interface EvidenceEnvelope {
  envelopeVersion: 1;
  generatedAt: string;
  subject: {
    manifestHash: string;
    toolName: string;
    decision: Decision;
    reasonCode: string;
    receiptId: string;
    receiptTimestamp: string;
    publicKeyId: string;
    algorithm: "ed25519";
    agentId?: string;
  };
  provenance: {
    serverName: string;
    serverVersion: string;
    serverUrl: string;
  };
  verification: {
    manifestTrusted: boolean;
    manifestReasonCode: string;
    receiptSignatureValid: boolean;
    receiptReasonCode: string;
    manifestHashMatch: boolean;
  };
  disclaimer: string;
}

const DISCLAIMER =
  "This envelope is a structured, machine-readable export of a Besa signed " +
  "manifest and execution receipt, intended as input to external audit, " +
  "evidence-retention, or register-of-information workflows (for example " +
  "under the EU AI Act, DORA, NIS2, or ISO/IEC 42001). It is a factual " +
  "export of cryptographically verified data, not a compliance " +
  "certification, legal attestation, or regulatory filing on its own. " +
  "Besa does not certify compliance with any regulation.";

// Pure function: the same manifest/receipt/trust-store input always
// produces the same envelope (aside from `generatedAt`, injectable via
// `now` for deterministic tests). No file I/O, no signing key involved.
export function createEvidenceEnvelope(
  signedManifest: SignedManifest,
  receipt: Receipt,
  trustStore: TrustStore,
  now: () => string = () => new Date().toISOString(),
): EvidenceEnvelope {
  const manifestVerification = verifyTrustedSignedManifest(
    signedManifest,
    trustStore,
  );
  const receiptSignature = verifyReceiptDetailed(
    receipt,
    signedManifest.publicKey,
  );

  return {
    envelopeVersion: 1,
    generatedAt: now(),
    subject: {
      manifestHash: receipt.manifestHash,
      toolName: receipt.toolName,
      decision: receipt.decision,
      reasonCode: receipt.reasonCode,
      receiptId: receipt.receiptId,
      receiptTimestamp: receipt.timestamp,
      publicKeyId: receipt.publicKeyId,
      algorithm: receipt.algorithm,
      agentId: receipt.agentId,
    },
    provenance: {
      serverName: signedManifest.manifest.serverName,
      serverVersion: signedManifest.manifest.serverVersion,
      serverUrl: signedManifest.manifest.serverUrl,
    },
    verification: {
      manifestTrusted: manifestVerification.valid,
      manifestReasonCode: manifestVerification.reasonCode,
      receiptSignatureValid: receiptSignature.valid,
      receiptReasonCode: receiptSignature.reasonCode,
      manifestHashMatch: receipt.manifestHash === signedManifest.manifestHash,
    },
    disclaimer: DISCLAIMER,
  };
}
