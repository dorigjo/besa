# Evidence Envelope

## What it is

`besa export-evidence <signed-manifest> <receipt>` reformats an already
signed manifest and an already signed receipt into one structured JSON
document: an **Evidence Envelope**. It is intended as input to whatever
external audit, evidence-retention, or register-of-information workflow an
organization already runs — not a new trust primitive.

It reuses the exact verification path `besa verify` / `besa verify-receipt`
already use (`verifyTrustedSignedManifest`, `verifyReceiptDetailed`). No new
cryptography, no new signing, no new trust decision is introduced.

## What it is not

- **Not a compliance certification.** Besa does not certify compliance with
  the EU AI Act, DORA, NIS2, ISO/IEC 42001, or any other regulation, and the
  envelope says so explicitly in its own `disclaimer` field.
- **Not itself signed.** Every fact the envelope states (`manifestHash`,
  `receiptId`, the verification outcome) can be independently re-derived by
  the recipient from the original signed manifest and receipt. This mirrors
  the hosted verifier's `VerifyResult`, which is likewise returned unsigned
  (see `docs/HOSTED_VERIFIER.md`) — the envelope's integrity depends on the
  recipient being able to re-verify the underlying artifacts, not on trusting
  the envelope file by itself.
- **Not a batch/multi-receipt export.** v1.0 exports exactly one manifest +
  one receipt pair per invocation. Aggregating many receipts into a single
  register-style export is a named, unimplemented Future Opportunity from
  an internal, non-public release-scoping note.

## Shape

```jsonc
{
  "envelopeVersion": 1,
  "generatedAt": "2026-01-01T00:00:00.000Z",
  "subject": {
    "manifestHash": "...",
    "toolName": "crm.lookup",
    "decision": "allow",
    "reasonCode": "ALLOWED",
    "receiptId": "rcpt_...",
    "receiptTimestamp": "...",
    "publicKeyId": "...",
    "algorithm": "ed25519"
  },
  "provenance": {
    "serverName": "acme-crm",
    "serverVersion": "1.0.0",
    "serverUrl": "https://tools.acme.example/mcp"
  },
  "verification": {
    "manifestTrusted": true,
    "manifestReasonCode": "OK",
    "receiptSignatureValid": true,
    "receiptReasonCode": "OK",
    "manifestHashMatch": true
  },
  "disclaimer": "..."
}
```

A `false` value anywhere in `verification` is not an error the command
throws on — it is itself the evidence: the envelope still generates,
recording exactly which check failed and why, and the CLI exits non-zero to
signal it. This mirrors the deliberate "deny receipts are evidence too"
behavior of `besa receipt` (see `src/index.ts`'s `cmdReceipt`).

## Why this shape, not one per regulation

Rather than inventing a separate export for each framework, the envelope
exposes the general facts (who signed, what was decided, whether the chain
still verifies) that recur across several external evidence needs:

| Field | Read as ... in a DORA register-of-information context | Read as ... in an EU AI Act Art. 12 logging context | Read as ... in an ISO/IEC 42001 evidence context |
|---|---|---|---|
| `subject.manifestHash` / `provenance` | identity of the ICT third-party tool/function invoked | identity of the system component that acted | identity of the AI-system function exercised |
| `subject.decision` / `subject.reasonCode` | outcome of the third-party-risk control | outcome of the automated logging record | outcome of the governance control |
| `verification.*` | whether the invoked-tool identity is independently verifiable | whether the log record is tamper-evident | whether the audit evidence is independently verifiable |

None of these mappings assert that satisfying Besa's fields alone satisfies
the cited article or standard — each still requires the organization's own
process, retention, and reporting on top of this envelope. See
`docs/REGULATORY_INEVITABILITY_MAP.md` for the fuller, non-code discussion of
these frameworks.

## Limitations

- No trust-store-aware batch export.
- No eIDAS-qualified timestamp — `generatedAt` is a local system clock read,
  not a qualified electronic timestamp from a QTSP.
- No built-in retention or storage — the caller decides where the resulting
  JSON file is kept.
