# Evidence Artifacts

Besa v1.1 adds `ActionEvidenceV1`, a signed post-action artifact that links one
exact proposed action and its signed allow capability to the result data
supplied by the executor or recorder. It is additive: the frozen v1 Receipt and
legacy `export-evidence` format remain unchanged.

## ActionEvidenceV1

An action evidence artifact contains signed hashes or references for:

- the canonical `ActionEnvelopeV1`;
- the exact `ActionCapabilityV1` used before execution;
- the capability's delegation-chain hash, when present;
- an optional legacy Receipt hash;
- the supplied execution result;
- success or failure outcome;
- executor and recorder identifiers;
- start, completion, and recording timestamps; and
- the recorder public key identity and Ed25519 signature.

The signature domain is `besa:action-evidence:v1`. Artifact identity and result
hashes use separate domains. Unknown fields, malformed key material, invalid
timestamps, non-canonical data, and altered signatures fail closed.

## Independent verification

`verifyActionEvidence()` requires the evidence plus the original action,
capability, result, and a verifier-controlled trust store. It verifies:

1. strict schemas and the recorder signature;
2. recorder trust at the signed recording time;
3. ordered evidence timestamps;
4. action, capability, delegation-hash, optional receipt-hash, and result links;
5. the capability issuer signature and trust; and
6. that the capability authorized the exact action at `startedAt`.

When a capability binds a delegation-chain hash, verify the supplied chain
separately with `verifyActionDelegation()` and require its returned `chainHash`
to equal the capability value. The hash prevents substitution; the separate
chain verification proves root trust and narrowing.

The self-hosted verifier exposes the same checks at
`POST /v1/verify/evidence`, while `POST /v1/verify/delegation` verifies a
delegation chain. See [HOSTED_VERIFIER.md](HOSTED_VERIFIER.md).

## Runtime records

`withBesa` and `withBesaMcp` append a `RuntimeEvidenceRecordV1` containing the
Action Envelope, Action Capability, and signed Action Evidence. The bundled
`AppendOnlyEvidenceLog` writes one canonical JSON object per line, serializes
in-process appends, rejects non-regular or symlink targets, and fsyncs each
record.

The local JSONL file is append-only by API behavior, not an immutable ledger.
An operator with filesystem authority can delete or replace it. Copy records to
customer-controlled retention when deletion detection or long-term custody is
required.

If a guarded handler throws, the runtime signs failure evidence containing only
the error type, not the error message or stack. If a successful result cannot
be hashed or signed, the runtime returns `EVIDENCE_CREATION_FAILED` and does
not falsely label the handler as failed. An append failure returns
`EVIDENCE_RECORD_FAILED`; the side effect may already have happened.

## What the signature proves

Valid Action Evidence proves that the trusted recorder signed the supplied
artifact links, result hash, outcome, and timestamps. It does not independently
observe or prove that a deployment, deletion, payment, or other real-world side
effect occurred. That claim is only as strong as the recorder's access to the
real execution result and the verifier's decision to trust that recorder.

Besa does not provide a trusted timestamp authority, immutable retention,
compliance certification, or legal conclusions. Its artifacts can be inputs to
customer-owned security, governance, audit, and evidence-retention processes.

## Legacy Evidence Envelope

`besa export-evidence <signed-manifest> <receipt>` still reformats one already
signed v1 SignedManifest and Receipt into an unsigned `EvidenceEnvelope`. It
reuses legacy trust and receipt verification and introduces no new signature or
trust decision. Recipients must re-verify the embedded source artifacts; the
envelope file itself is not tamper-evident.

The command exports one manifest/receipt pair, records failed verification in
its `verification` fields, and exits non-zero when checks fail. It is not a
batch export, retention system, or compliance report.
