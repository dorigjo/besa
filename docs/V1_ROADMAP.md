# Besa v1.0 Roadmap

Phase model for where Besa is and where it is deliberately not yet going.
Phases marked DONE are implemented and verified in this repository. Phases
below that are architecture notes only — nothing in them is implemented,
and none of it should be inferred as committed or scheduled.

## Phase 0 — Foundation (DONE)

- Manifest signing (`signManifest`, `src/signing.ts`)
- Signed receipts (`createReceipt`)
- Verification (`verifySignedManifest`, `verifyReceiptDetailed`)
- Admission logic (`admit`, `src/admit.ts`)
- Golden vectors (`src/tests/fixtures/golden-v1.ts`) — frozen artifact
  compatibility contract

## Phase 1 — Provider Architecture (DONE)

- `KeyProvider` interface (`src/keys/provider.ts`)
- `LocalKeyProvider` (`src/keys/local-provider.ts`)
- `signManifestWithProvider` / `createReceiptWithProvider`
  (`src/signing.ts`) — async, provider-native signing path
- Single signing primitive (`signWithKeyPair`, `src/crypto.ts`) shared by
  the legacy `KeyPair` path and every `KeyProvider` implementation
- CLI secret hygiene: `--key-file`, `--passphrase-file` (including stdin
  via `-`), `BESA_KEY_PASSPHRASE` environment fallback
- `TRUST_MODEL.md`, `MCP_TRUST_MODEL.md`, `KEY_PROVIDER_ARCHITECTURE.md`,
  `KMS_HSM_READINESS.md`, `PHASE3_SECURITY_AUDIT.md`

Known, documented, deliberately unaddressed gaps carried out of this phase
(see `PHASE3_SECURITY_AUDIT.md` and `KMS_HSM_READINESS.md`):

- `createKeyRotation()` has no provider-native counterpart — a KMS/HSM-backed
  key cannot have its rotation proof signed through a `KeyProvider` yet.
- Besa's artifact format is hard-pinned to Ed25519; AWS KMS and Azure Key
  Vault do not offer Ed25519 signing as of the Phase 3 assessment, so a
  provider for either would require a versioned artifact-format change,
  not just a new `KeyProvider` implementation.
- `KeyProvider`/`LocalKeyProvider` are not exported through the public SDK
  surface (`sdk.ts`) — deliberate, pending a second real implementation.

## Phase 2 — Hosted Trust Plane

**Partially implemented (2026-07-19).** Architecture:

```
Agent
 |
Besa SDK
 |
Authorization API      <- PARTIAL: docs/RUNTIME_ADMISSION.md,
 |                          `besa serve --trust` (non-consuming attestation
 |                          only — no policy language, no receipts)
Policy Engine          <- not implemented (beyond existing admit() rules)
 |
Trust Ledger           <- not implemented
 |
Verifier                <- DONE: docs/HOSTED_VERIFIER.md, `besa serve`
```

This was the first phase that would introduce a hosted/networked component
at all — everything in Phase 0/1 runs entirely locally, with no server Besa
operates. Per the project's founder constraints document ("no hosted
registry," "no multi-tenant SaaS," "no complex policy engine"), this phase
was explicitly gated behind "a deliberate, separate decision to expand MVP
scope" — that decision was made on 2026-07-19, scoped narrowly to the
**Verifier** node first (stateless cryptographic signature verification
over HTTP — see `docs/HOSTED_VERIFIER.md`), then extended on 2026-07-22
("Phase 7 — Runtime Admission Infrastructure" in an earlier internal
phase-numbering scheme) to
a narrow, opt-in slice of the **Authorization API** node: `POST /v1/admit`
reuses the existing `admit()`/trust-verification/signing logic to issue a
signed, non-consuming `AdmissionAttestation` — see
`docs/RUNTIME_ADMISSION.md` for the full scope cut, including why this is
explicitly not a receipt and not real-time distributed budget enforcement.
The Policy Engine (beyond today's fixed `admit()` rules) and Trust Ledger
nodes remain unimplemented and are not authorized by either decision.
Building either of the remaining two nodes needs its own separate scope
decision and plan, exactly as these two did.

## Phase 3 — Enterprise Trust Infrastructure ("Phase 6 — Enterprise Trust Plane" in an earlier internal execution numbering)

**Not implemented.** Architecture direction and candidate scope only — this
section absorbs an earlier internal feature-scoping pass, translated out of
its original pitch-style framing into technical candidates, each mapped to
the existing gap or document that already names it. Nothing below is
authorized for implementation by appearing here — each candidate needs its
own FACTS-first plan, exactly like the Hosted Verifier (Phase 5) did,
before any code is written.

**Numbering note:** an earlier internal phase chain (Phase 5 Hosted
Verifier → Phase 6 Enterprise Trust Plane → Phase 7 Runtime Admission
Infrastructure → Phase 8 Release Candidate) is a different numbering scheme
than this roadmap's Phase 0–4. "Phase 6" in that chain is this document's
Phase 3. Recorded here once, explicitly, so the two schemes don't become
two silently-conflicting truths.

### Carried over from the original Phase 3 scope

- KMS integration (concrete `KeyProvider` implementation — see
  `KMS_HSM_READINESS.md` for per-backend feasibility)
- HSM support (PKCS#11-backed `KeyProvider`)
- Organization identities (extending the identity model in
  `TRUST_MODEL.md` §1 beyond "a key identifies a publisher")
- Agent lifecycle (agent identity as a verified principal, not a
  caller-supplied label — see `TRUST_MODEL.md` §1's explicit open point)
- Key rotation (closing the `createKeyRotationWithProvider` gap identified
  in Phase 1)
- Revocation (extending local trust-store revocation toward the
  cross-organization gap identified in `TRUST_MODEL.md` §3)

### Candidates from the 2026-07-19 scoping pass

Each is stated as an engineering question, not a pitch. "Fit" notes where
it lands relative to the founder constraints document and the 2026-07-19
Infrastructure Development authorization (Hosted Verifier / Enterprise
Trust Plane / Runtime Admission Infrastructure permitted "when implemented
incrementally and backed by tests, documentation and security review" —
every other constraint, including "no fake enterprise functionality" and
"smallest credible implementation," still applies).

- **Extended receipt provenance** (earlier working name: "AI Liability Ledger"). Technical
  shape: additional fields on the existing `Receipt` artifact —
  policy version, model identifier/hash, and the permission state the
  decision was made under — chained via hashes the way `manifestHash`
  already chains a receipt to its manifest. This is an `artifactVersion`
  *shape* change (new required/optional fields), which needs
  `ALGORITHM_AGILITY_DESIGN.md`'s Design B discipline applied to shape
  versioning, not just algorithm versioning. Smallest-scope candidate of
  the five: extends an existing, already-tested artifact type rather than
  introducing new infrastructure.
- **Cross-consumer revocation propagation** (earlier working name: "Kill Switch Network").
  This is the exact gap `TRUST_MODEL.md` §3 and `TRUST_GUARANTEES.md`
  non-guarantee #6 already name: today, a compromised key can only be
  revoked one trust store at a time, with no mechanism to push that
  revocation to consumers Besa does not control. A real fix requires
  shared, persistent, multi-party state (a ledger or registry) — this is
  the highest-scope, highest-risk candidate of the five: it is the one
  that most resembles the "hosted registry" / "multi-tenant SaaS" shape
  the founder constraints document names explicitly, and needs the most scrutiny before any
  plan is written for it, specifically on the questions of who operates
  the shared state, how consumers authenticate to it, and what happens
  when it is unavailable (must still fail closed locally).
- **Standardized evidence export format** (earlier working name: "Evidence Envelope").
  Technical shape: a documented, versioned serialization bundling fields
  Besa already produces (`agentId`, `manifestHash`, `publicKeyId`,
  `timestamp`, `signature`, the receipt itself) into one exportable
  document for auditors/insurers/regulators. Mostly a formatting/export
  layer over existing data, not new trust logic — second-smallest-scope
  candidate.
- **Read-only trust status query** (earlier working name: "Trust Score API"). Technical
  shape: a `GET` endpoint answering questions the trust store and
  `checkTrustedKey` can already answer locally (is this key active/
  retired/revoked) plus fields that do not exist yet (`last_audit`,
  `risk_level` imply new tracked history, not just a read of current
  state). The identity-verification part is a thin, stateless wrapper
  candidate for the existing Hosted Verifier; the audit-history/risk-score
  part is new state and needs its own scope decision — do not conflate the
  two into one feature.
- **Per-agent cryptographic identity** (earlier working name: "Agent Passport"). This is
  precisely the "agent identity as a verified principal, not a
  caller-supplied label" gap `TRUST_MODEL.md` §1 already flags as "a
  natural next step... explicitly out of scope for this document." Largest
  conceptual lift of the five — it is a new identity model (agents sign
  their own requests; capabilities/restrictions become a property of the
  agent's identity, not just the tool manifest's), not an extension of an
  existing one. Needs its own architecture document before a plan, the way
  `KEY_PROVIDER_ARCHITECTURE.md` preceded provider implementation.

None of the above is scheduled. This section exists so that whichever one
is picked next is picked against a phase model that already accounts for
it, per this roadmap's own stated purpose.

## Phase 4 — Agent Authorization Network

**Not implemented.** Long-term direction only, furthest from current scope:

- Tool registry (discovery of signed manifests beyond direct file exchange)
- Trust exchange (a mechanism for propagating trust/revocation between
  organizations that do not directly exchange files — the gap
  `TRUST_MODEL.md` §3 calls out as "no mechanism today for A to push a
  revocation to consumers it does not control")
- Third-party verification (an independent party attesting to a manifest
  or receipt's validity without being either the signer or the verifier)

## What this roadmap deliberately does not commit to

No dates, no version numbers beyond "v1.0," no team sizing, no pricing. A
phase appearing here is not authorization to start building it — Phase 2–4
require their own explicit scope decision, exactly as the project's founder
constraints document requires for anything beyond the current MVP.
