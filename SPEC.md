# Besa Artifact Specification — v1

This document freezes the on-the-wire contract for Besa's signed artifacts. It
is the interoperability surface: independent implementations that follow this
spec must be able to verify each other's artifacts.

**Compatibility guarantee:** an artifact signed under this specification must
remain verifiable indefinitely. The golden vectors in `src/tests/fixtures/` and
the golden tests enforce this — if a change breaks them, the change is breaking.

---

## Versioning and compatibility policy

Besa follows Semantic Versioning for the package, and a stricter rule for the
signed format:

- **Every signed artifact carries `artifactVersion: 1`.** This document defines
  version `1`.
- **Additive, non-breaking changes** (a new optional field, a new reason code, a
  new SDK export, a new CLI command) are **minor** package releases. They must
  not change the canonical bytes of any existing artifact.
- **Breaking changes** (removing or renaming a field, changing a field type,
  changing field order, changing canonicalization, domain separation, or hashing)
  require a **new `artifactVersion`** and a **major** package release. The old
  version's verification path must be retained.
- **The golden vectors are never regenerated.** They are the proof that version 1
  bytes still verify. A failing golden test means the format drifted.

---

## Canonical serialization

All hashing and signing operate over **canonical JSON**, produced by
`canonicalize(value)`:

- Object keys are sorted lexicographically before JavaScript JSON serialization
  (recursively). ECMAScript integer-index keys are emitted first in ascending
  numeric order; remaining keys retain lexicographic order. For example
  `canonicalize({"10":"ten","2":"two"})` is
  `{"2":"two","10":"ten"}`. This frozen v1 format is not RFC 8785/JCS.
- Output is compact (no insignificant whitespace).
- Only finite JSON values are allowed. `NaN`, `Infinity`, `undefined`,
  functions, symbols, accessors, circular references, and non-plain objects are
  rejected.
- Bounded for safety: max depth 64, max 100,000 nodes, max 1,048,576 bytes.
- Numeric serialization follows ECMAScript JSON for finite binary64 numbers:
  negative zero becomes `0`. Sparse array slots become `null`. Cross-language
  verifiers must reproduce these frozen semantics and UTF-8 encoding. Transport
  parsers must reject duplicate JSON keys before producing the object to verify.

Frozen ordering vector:

```
canonicalize({ "b": 1, "a": { "d": 2, "c": 3 } })  ==  {"a":{"c":3,"d":2},"b":1}
```

### Raw JSON boundary

`parseArtifactJson(textOrUtf8Bytes)` is the shared transport decoder used by
JSON file loaders, CLI artifact reads and the Hosted Verifier. SDK/offline
integrations receiving untrusted JSON must use it before artifact verification:
ordinary `JSON.parse` has already discarded duplicate-key information.
Object-based verifier APIs cannot reconstruct the original transport bytes.

- Reject duplicate object keys at every depth, including identical values and
  escape-equivalent keys, before native JSON parsing constructs the object.
- Accept only JSON grammar and fatal UTF-8 decoding. Reject a leading BOM,
  truncated data and unpaired UTF-16 surrogates in decoded strings or keys.
- Do not normalize arbitrary JSON strings/keys. Unicode scalar sequences are
  exact: composed/decomposed text and visually similar keys remain different.
  Identity schemas retain their existing NFC, control and exact-match rules.
- Reject non-finite numbers and decimal tokens whose signed decimal coefficient
  and exponent differ from their ECMAScript JSON number serialization. This
  rejects overflow, nonzero underflow and silently rounded integers/decimals.
  Equivalent decimal spelling (`1.0`, `1e0`) and negative zero remain supported.
  Finite binary64 values serialized by the frozen canonicalizer round-trip.
- Bound raw input to 1048576 UTF-8 bytes, depth 64 and 100000 value nodes,
  additionally enforcing the existing canonical JSON bounds.

This decoder does not authenticate, validate an artifact schema, consume replay
state or authorize execution. HTTP parsing failures remain `400`; file/SDK
decoding throws before verification. All existing object APIs, canonical bytes,
hash/signature domains and frozen signed vectors remain unchanged. Historical
ambiguous or non-scalar transport representations are deliberately rejected;
do not restore permissive parsing as an execution fallback. A previously parsed
object is not evidence that the original raw input passed this boundary.

`conformance/json-boundary-v1.json` freezes positive/negative decoder vectors,
separately from signed-artifact versions. It does not replace the existing
signature, delegation, policy or replay conformance vectors.

**The canonical key order defined above, not the order of the field tables
below, determines the signed and hashed bytes.** The tables in
this document define which fields are *required*, *optional*, and *rejected*;
they are documentation order, not wire order. An implementation must never
serialize fields in table order and sign the result.

---

## Domain separation and hashing

Hashes are SHA-256 over a domain-separated message: `besa:<domain>:v1\0<canonical-json>`
(where `\0` is a single NUL byte).

| Purpose | Message | Result |
|---|---|---|
| `manifestHash` | `besa:manifest:v1\0<canonical(manifest)>` | 64-char lowercase hex |
| `requestHash` | `besa:request:v1\0<canonical(request)>` | 64-char lowercase hex |

When no request payload is present, `requestHash` is computed over the **empty
object**: `hashRequest(undefined)` is defined as `hashRequest({})`. It is never
computed over `null`, over the string `"undefined"`, nor omitted.

Ed25519 signatures are computed over domain-separated messages of the same
shape, one domain per artifact type:

| Artifact | Signature domain |
|---|---|
| Signed manifest | `besa:signed-manifest:v1` |
| Receipt | `besa:receipt:v1` |
| Key rotation | `besa:key-rotation:v1` |
| Admission attestation | `besa:admission-attestation:v1` |

The signature covers the **entire artifact envelope minus the `signature`
field**, canonicalized using the key order defined above.

### Signing and verification algorithm

Both operations construct the identical message. To **sign** an artifact of type
`T` with domain `D`:

1. Build the artifact object with every field except `signature`. Optional
   fields that are absent are **omitted entirely** — never emitted as `null`,
   `false`, or an empty string.
2. `message = "besa:" + D + ":v1" + NUL + canonicalize(object)`, encoded UTF-8,
   where `NUL` is a single `0x00` byte.
3. `signature = base64(ed25519_sign(privateKey, message))`.
4. Emit the artifact with `signature` attached.

To **verify**:

1. Validate every field against the rules below. Reject unknown top-level
   fields. On any failure return `valid: false` with the reason code — do not
   throw.
2. Recompute `publicKeyId` from `publicKey` (see derivation below) and compare.
3. Rebuild the object **without** the `signature` field, omitting absent
   optional fields exactly as in signing step 1.
4. Recompute `message` exactly as in signing step 2.
5. `ed25519_verify(publicKey, message, base64_decode(signature))`.
6. Where applicable, recompute `manifestHash` and compare against the value
   carried in the artifact.
7. Any failure at any step yields `valid: false`. Never partially accept.

### `publicKeyId` derivation

`publicKeyId` is derived from the `publicKey` field, not from a PEM or a raw
key object:

1. `der = base64_decode(publicKey)` — the Ed25519 SPKI DER bytes.
2. `digest = SHA-256(der)`.
3. `publicKeyId = lowercase_hex(digest)` — exactly 64 characters.

Hashing the base64 *string*, hashing a PEM encoding, or emitting uppercase hex
all produce a non-conforming identifier.

---

## Field validation rules

| Rule | Definition |
|---|---|
| SHA-256 hex | `^[a-f0-9]{64}$` |
| `publicKeyId` | full SHA-256 fingerprint of the public key DER bytes; `^[a-f0-9]{64}$` |
| `receiptId` | `rcpt_` followed by a canonical UUIDv4 |
| `toolName` | `^[a-zA-Z0-9._-]{1,256}$` (ASCII, no whitespace/control) |
| `reasonCode` | `^[A-Z][A-Z0-9_]{0,63}$` |
| Timestamps | canonical ISO-8601; `new Date(x).toISOString() === x`, length ≤ 35 |
| `signature` | 88-char canonical base64 decoding to exactly 64 bytes |
| `publicKey` | canonical base64, valid Ed25519 SPKI DER |
| `algorithm` | exactly `ed25519` |

Unknown top-level fields are rejected on every artifact.

---

## Signed manifest (`artifactVersion: 1`)

All fields below are required. Signed byte order is lexicographic, not table
order.

| Field | Required | Type |
|---|---|---|
| `artifactVersion` | yes | `1` |
| `manifest` | yes | Manifest (below) |
| `manifestHash` | yes | SHA-256 hex of the manifest |
| `algorithm` | yes | `ed25519` |
| `publicKey` | yes | base64 Ed25519 SPKI DER |
| `publicKeyId` | yes | 64-hex fingerprint of `publicKey` |
| `signedAt` | yes | canonical ISO-8601 |
| `signature` | yes | base64 Ed25519 signature |

### Manifest

| Field | Required | Type |
|---|---|---|
| `serverName` | yes | string |
| `serverVersion` | yes | string |
| `serverUrl` | yes | string |
| `createdAt` | yes | string |
| `tools` | yes | ToolDefinition[] |

### ToolDefinition

| Field | Required | Type |
|---|---|---|
| `name` | yes | tool name |
| `description` | yes | string |
| `capability` | yes | `read` \| `write` \| `destructive` |
| `risk` | yes | `low` \| `medium` \| `high` |
| `scopes` | yes | string[] |
| `budgetLimit` | yes | number |
| `inputSchema` | yes | object |

---

## Receipt (`artifactVersion: 1`)

`agentId` and `grantReasonCode` are optional. When absent they are **omitted
from the object entirely** before canonicalization — emitting them as `null`
produces a different signature and will fail verification. `grantReasonCode` may
only appear alongside `agentId`. Signed byte order is lexicographic, not table
order.

| Field | Required | Type |
|---|---|---|
| `artifactVersion` | yes | `1` |
| `receiptId` | yes | `rcpt_` + UUIDv4 |
| `manifestHash` | yes | SHA-256 hex |
| `toolName` | yes | tool name |
| `decision` | yes | `allow` \| `deny` |
| `reasonCode` | yes | reason code |
| `timestamp` | yes | canonical ISO-8601 |
| `requestHash` | yes | SHA-256 hex |
| `agentId` | no | non-empty string |
| `grantReasonCode` | no | reason code (requires `agentId`) |
| `publicKeyId` | yes | 64-hex fingerprint |
| `algorithm` | yes | `ed25519` |
| `signature` | yes | base64 Ed25519 signature |

Consistency rules: an `allow` receipt must carry `reasonCode` `ALLOWED`; a `deny`
receipt must not carry `ALLOWED`.

Illustrative receipt (synthetic; signature is a placeholder):

```json
{
  "artifactVersion": 1,
  "receiptId": "rcpt_2d7942c7-8f70-4984-9c3f-24876acfd860",
  "manifestHash": "ea7e9ca22d199f40281cdf9e5d6145440c6c7d6bfbe94157c4b1da5527054410",
  "toolName": "crm.lookup",
  "decision": "allow",
  "reasonCode": "ALLOWED",
  "timestamp": "2026-06-19T10:00:00.000Z",
  "requestHash": "b27b80d1227c167a6fca199778645daa77d20a8087782fc48802d11d6281c920",
  "publicKeyId": "f68668614543c4896cf8cee418492f1a4df1f1acdba8850f94728b8a94cf90fe",
  "algorithm": "ed25519",
  "signature": "<base64-ed25519-signature>"
}
```

---

## Trust store (`version: 1`)

| Field | Required | Type |
|---|---|---|
| `version` | yes | `1` |
| `keys` | yes | TrustAnchor[] (max 4096, unique `publicKeyId`) |

### TrustAnchor

| Field | Required | Type |
|---|---|---|
| `publicKeyId` | yes | 64-hex fingerprint |
| `publicKey` | yes | base64 Ed25519 SPKI DER |
| `status` | yes | `active` \| `retired` \| `revoked` |
| `addedAt` | yes | canonical ISO-8601 |
| `retiredAt` | when retired | canonical ISO-8601 |
| `revokedAt` | when revoked | canonical ISO-8601 |

---

## Key rotation (`artifactVersion: 1`)

A signed proof that a previous key hands off to a new key, signed by the
**previous** key.

| Field | Required | Type |
|---|---|---|
| `artifactVersion` | yes | `1` |
| `algorithm` | yes | `ed25519` |
| `previousPublicKey` | yes | base64 Ed25519 SPKI DER |
| `previousPublicKeyId` | yes | 64-hex fingerprint |
| `newPublicKey` | yes | base64 Ed25519 SPKI DER |
| `newPublicKeyId` | yes | 64-hex fingerprint |
| `rotatedAt` | yes | canonical ISO-8601 |
| `signature` | yes | base64 Ed25519 signature (by previous key) |

---

## Admission attestation (`artifactVersion: 1`)

A signed, **non-consuming** snapshot of an admission decision, issued by
`besa serve --trust`. It records what the admission logic decided at a point in
time and at a given meter count.

An attestation is **not a receipt**. It does not consume budget, does not
advance the meter, and is not evidence that a tool call was actually executed —
only that a decision *would have been* returned at that moment. Consumers must
not treat it as proof of execution.

| Field | Required | Type |
|---|---|---|
| `artifactVersion` | yes | `1` |
| `attestationId` | yes | `att_` + canonical UUIDv4 |
| `manifestHash` | yes | SHA-256 hex |
| `toolName` | yes | tool name |
| `decision` | yes | `allow` \| `deny` |
| `reasonCode` | yes | reason code |
| `detail` | yes | string |
| `meterCountAtCheck` | yes | number |
| `timestamp` | yes | canonical ISO-8601 |
| `publicKeyId` | yes | 64-hex fingerprint |
| `algorithm` | yes | `ed25519` |
| `signature` | yes | base64 Ed25519 signature |

Signature domain: `besa:admission-attestation:v1`.

---

## Evidence envelope (`envelopeVersion: 1`)

An **unsigned** export format that bundles an already-verified manifest and
receipt pair for handing to an auditor. It carries `envelopeVersion`, not
`artifactVersion`, precisely because it is **not a cryptographic artifact** and
has no signature of its own.

The envelope's trustworthiness derives entirely from the signed artifacts it
describes. A consumer must re-verify the underlying signed manifest and receipt
independently; the envelope itself proves nothing and must never be treated as
evidence on its own. Because it is unsigned, it is outside the frozen-artifact
compatibility guarantee — its shape is documented in `docs/EVIDENCE_ENVELOPE.md`
and may evolve additively without an `artifactVersion` bump.

---

## Verification contract

Verification functions return a structured result and **fail closed** — any
mismatch yields `valid: false` with a reason code, never an exception for a bad
artifact:

```
{ valid: boolean, reasonCode: string, detail: string }
```

### Reason codes

**Admission** (`decision: allow | deny`):
`ALLOWED`, `TOOL_NOT_FOUND`, `RISK_BLOCKED`, `BUDGET_EXCEEDED`,
`INVALID_MANIFEST`, `INVALID_TOOL_NAME`, `INVALID_CALL_COUNT`, `INVALID_POLICY`.

**Grant scoping:** `GRANT_OK`, `TOOL_NOT_GRANTED`, `AGENT_NOT_FOUND`.

**Verification (`E_*`):** `OK`, `E_ARTIFACT_VERSION_UNSUPPORTED`,
`E_ALGORITHM_UNSUPPORTED`, `E_SIGNED_MANIFEST_INVALID`, `E_RECEIPT_INVALID`,
`E_ROTATION_INVALID`, `E_MANIFEST_HASH_MISMATCH`, `E_PUBLIC_KEY_ID_MISMATCH`,
`E_PUBLIC_KEY_INVALID`, `E_SIGNATURE_INVALID`, `E_SIGNATURE_CHECK_FAILED`,
`E_TRUST_STORE_INVALID`, `E_ARTIFACT_TIMESTAMP_INVALID`,
`E_ARTIFACT_TIMESTAMP_FUTURE`, `E_KEY_UNTRUSTED`, `E_TRUST_ANCHOR_MISMATCH`,
`E_KEY_REVOKED`, `E_KEY_RETIRED`.

New reason codes may be **added** in a minor release. Existing codes and their
meaning are frozen.

---

## Frozen surfaces

The following are part of the v1 contract and change only under the versioning
policy above:

- All artifact schemas and field order (this document).
- Canonicalization, domain separation, and hashing rules.
- The verification contract and reason codes.
- The public SDK export surface (enforced by `src/tests/sdk-surface.test.ts`).
- The CLI commands and flags.

---

# Consequential action artifacts (v1.1, additive)

These artifacts add a new protocol surface. They do not modify, reinterpret,
or invalidate any frozen v1.0 artifact. Every v1.1 object rejects unknown
fields, uses canonical JSON, and has `artifactVersion: 1` where it is a signed
artifact. Timestamps are canonical UTC ISO-8601 strings.

## Canonical domains

All strings below append canonical JSON after a NUL byte. Signatures use the
existing `signatureMessage(domain, value)` construction:

| Purpose | Domain |
|---|---|
| Action identity | `besa:action-envelope:v1` |
| Action constraints identity | `besa:action-constraints:v1` |
| Delegation signature | `besa:delegation:v1` |
| Delegation artifact identity | `besa:delegation-artifact:v1` |
| Delegation-chain identity | `besa:delegation-chain:v1` |
| Capability signature | `besa:action-capability:v1` |
| Capability artifact identity | `besa:action-capability-artifact:v1` |
| Execution-result identity | `besa:execution-result:v1` |
| Evidence signature | `besa:action-evidence:v1` |
| Evidence artifact identity | `besa:action-evidence-artifact:v1` |
| Replay key | `besa:replay-key:v1` |

## Action Envelope (`ActionEnvelopeV1`)

The canonical proposed action answers: who is requesting which operation on
which resource, under which declared authority and constraints, until when.

| Field | Required | Type / constraint |
|---|---|---|
| `artifactVersion` | yes | `1` |
| `principalId`, `agentId`, `authority` | yes | bounded NFC text |
| `tool`, `operation` | yes | stable ASCII machine name |
| `resource` | yes | bounded NFC text |
| `requestHash` | yes | 64-character lowercase SHA-256 hex |
| `scopes` | yes | sorted, unique bounded NFC strings |
| `constraints` | yes | bounded canonical JSON object |
| `expiresAt` | yes | canonical UTC timestamp |
| `nonce` | yes | 16-128 base64url characters |
| `riskClass` | yes | `low`, `medium`, or `high` |
| `contextHash` | no | 64-character lowercase SHA-256 hex |

`hashActionEnvelope()` returns the action-identity domain hash.
`checkActionEnvelope()` additionally rejects action expiry at the supplied
verification time.

## Delegation (`DelegationV1`)

A delegation carries `delegationId`, issuer and subject IDs/public keys/key IDs,
sorted `allowedOperations`, `allowedResources`, and `scopes`, constraints with
`exact` and numeric `maximums`, `issuedAt`, `notBefore`, `expiresAt`, optional
`parentDelegationHash`, `algorithm: "ed25519"`, and `signature`.

The first chain member must be signed by a trusted root. Each child must name
the parent hash and parent subject as issuer, and must narrow—not broaden—the
parent's allowed operations, resources, scopes, constraints, and time interval.
`verifyActionDelegation()` additionally requires that the exact action matches
the root principal, leaf agent, leaf permissions, constraints, and expiry.

## Action Capability (`ActionCapabilityV1`)

A signed allow/deny contract contains `capabilityId`, `actionHash`, redundant
principal/agent/authority/tool/operation/resource values, `constraintsHash`,
`expiresAt`, `nonce`, `policyId`, `delegationChainHash`, `decision`,
`reasonCode`, issuer identity/public key/key ID, `issuedAt`, `algorithm`, and
`signature`.

An allow must use `ACTION_ALLOWED`; a signed deny remains cryptographically
valid but never authorizes a runtime handler. Verification checks the signature,
trusted issuer, timestamp interval, and exact supplied action. A capability for
one resource, nonce, constraint set, or request hash cannot authorize another.

## Action Evidence (`ActionEvidenceV1`)

Evidence contains `evidenceId`, `actionHash`, `capabilityHash`,
`delegationChainHash`, optional `receiptHash`, `resultHash`, `outcome`,
`executorId`, `startedAt`, `completedAt`, recorder identity/public key/key ID,
`recordedAt`, `algorithm`, and `signature`.

Verification checks recorder trust, timestamp ordering, the linked action and
capability, and a caller-supplied result. It proves that a trusted recorder
signed the supplied linked data; it does **not** independently prove that an
external deployment, deletion, or payment happened.

## Action Policy (`ActionPolicyV1`)

The deterministic policy file contains `version: 1`, `policyId`,
`delegationRequired`, and strict rules. Each rule binds sorted principal, agent,
tool, operation, resource, and scope sets, a maximum risk class, and exact or
numeric-maximum constraints. It has no wildcards, callbacks, remote lookups,
or model-generated decisions.

## Replay contract

Replay keys bind the action hash and nonce. `ReplayStore` has explicit
`verification-only` and `enforced` modes. A runtime configured with
`replayRequirement: "enforce"` must obtain atomic `consumed` status before
calling the handler; reuse or unavailability fails closed. Global one-time use
requires a customer-controlled shared store and is not implied by signatures.

## v1.1 reason-code families

Existing v1.0 codes remain frozen. v1.1 adds stable codes in these families:

- `SCHEMA_ACTION_INVALID`, `ACTION_VALID`, `EXPIRY_ACTION_EXPIRED`.
- `ACTION_ALLOWED`, `ACTION_NOT_GRANTED`, `ACTION_TOOL_NOT_GRANTED`,
  `ACTION_SCOPE_NOT_GRANTED`, `ACTION_RISK_EXCEEDED`,
  `ACTION_CAPABILITY_MISMATCH`, `ACTION_REQUEST_MISMATCH`,
  `SCHEMA_POLICY_INVALID`.
- `IDENTITY_PRINCIPAL_NOT_GRANTED`, `IDENTITY_AGENT_NOT_GRANTED`,
  `RESOURCE_NOT_GRANTED`, `CONSTRAINT_VIOLATION`.
- `DELEGATION_VALID`, `DELEGATION_EMPTY_CHAIN`,
  `SCHEMA_DELEGATION_INVALID`, `SIGNATURE_DELEGATION_INVALID`,
  `TRUST_DELEGATION_ROOT_UNTRUSTED`, `DELEGATION_WIDENING`,
  `TRUST_DELEGATION_KEY_REVOKED`,
  `DELEGATION_ACTION_NOT_GRANTED`, `DELEGATION_PARENT_MISMATCH`,
  `EXPIRY_DELEGATION_NOT_ACTIVE`, `DELEGATION_REQUIRED`.
- `CAPABILITY_VALID`, `SCHEMA_CAPABILITY_INVALID`,
  `SIGNATURE_CAPABILITY_INVALID`, `TRUST_CAPABILITY_ISSUER_UNTRUSTED`,
  `EXPIRY_CAPABILITY_NOT_ACTIVE`.
- `EVIDENCE_VALID`, `SCHEMA_EVIDENCE_INVALID`,
  `SIGNATURE_EVIDENCE_INVALID`,
  `TRUST_EVIDENCE_RECORDER_UNTRUSTED`, `EVIDENCE_LINK_MISMATCH`,
  `EVIDENCE_CAPABILITY_INVALID`, `EXPIRY_EVIDENCE_TIME_INVALID`.
- `REPLAY_CONSUMED`, `REPLAY_DETECTED`, `REPLAY_NOT_ENFORCED`,
  `REPLAY_STORE_UNAVAILABLE`, `REPLAY_INPUT_INVALID`.
- `SCHEMA_MCP_CALL_INVALID`, `ACTION_TOOL_MISMATCH`,
  `ACTION_REQUEST_INVALID`, `ACTION_REQUEST_MISMATCH`.
- `RUNTIME_CLOCK_INVALID`, `CAPABILITY_RESOLUTION_FAILED`,
  `EVIDENCE_CREATION_FAILED`, `EVIDENCE_RECORD_FAILED`,
  `ACTION_HANDLER_FAILED`.

## Conformance

`conformance/golden-v1.json` remains the immutable v1.0 vector.
`conformance/consequential-action-v1.json` is the immutable v1.1 positive
chain. `conformance/consequential-action-negative-v1.json` names the expected
failure codes for mutation, expiry, schema, delegation, and replay cases.
`npm run conformance` verifies all published bytes through the public SDK.

## Pre-execution authority and admission artifacts (additive)

These are new artifact types, each explicitly versioned `1`, with separate
domains. They do not extend or reinterpret the frozen capability/receipt
schemas. Unknown fields and versions fail closed. Existing conformance vectors
and canonicalization bytes are unchanged.

### External Authority v1

`ExternalAuthorityV1` is a trusted normalizer's signed attestation that external
claims were verified and mapped to the stated grants. It is not a bearer token
or the original IdP signature. All following fields are required:

| Fields | Contract |
|---|---|
| `artifactVersion`, `algorithm` | `1`, `ed25519` |
| `mechanism` | `oauth-access-token`, `mcp-ema-access-token`, `workload-identity`, or `besa-delegation` |
| `principalId`, `agentId`, `issuer`, `audience`, `normalizerId` | Nonempty trimmed NFC text, no controls, at most 512 characters each |
| `tools`, `operations`, `resources`, `scopes` | Nonempty sorted unique lists, at most 256 entries; rule-list validation follows ActionPolicyV1. No wildcard/prefix matching. |
| `constraints` | Existing DelegationConstraintsV1: `exact` JSON object and `maximums` nonnegative finite numeric map; only own data fields can satisfy a constraint |
| `notBefore`, `expiresAt`, `issuedAt` | Canonical UTC timestamps; nonempty authority interval and `issuedAt < expiresAt`; admission/execution require issuance and not-before no later than check time, and expiry strictly later |
| `assertionDigest` | Lowercase SHA-256 hex of the verified external assertion, or verified delegation-chain digest for `besa-delegation` |
| `delegationChainHash` | Null or lowercase SHA-256 hex; required non-null for `besa-delegation` |
| `publicKey`, `publicKeyId` | Canonical Ed25519 SPKI DER base64 and SHA-256 fingerprint of decoded key |
| `signature` | Canonical base64, exactly 64 decoded bytes |

Limit: 131072 canonical UTF-8 bytes. Signature covers the entire body excluding
`signature` in domain `besa:external-authority:v1`. Artifact hash covers the
complete signed authority in domain `besa:external-authority-artifact:v1`.
`hashAuthorityAssertion` hashes `besa:authority-assertion:v1`, a NUL byte and
the exact assertion bytes (1-1048576 bytes). It does not parse or emit them.

Verification requires a trusted normalizer key, matching issuer/principal/agent
against the Action Envelope, exact service audience, grants and constraints,
and authority validity encompassing the action expiry. Identity validation
alone is insufficient. External token verification and scope/actor mapping
are adapter responsibilities, never inferred from caller-provided JSON flags.
Delegation normalization also requires the host-authenticated agent ID to match
the signed leaf subject. Possessing a public signed chain is not authentication.
Any issuer/subject key explicitly revoked in the supplied trust store invalidates
the chain; unknown intermediary keys continue to derive trust from the root.

### Pre-execution Request v1

`PreExecutionRequestV1` has exactly `requestVersion`, `action`, `parameters`,
`context`, `audience`, `policy` and `requestedAt`.

- `requestVersion` is `1`; `action` is the existing strict ActionEnvelopeV1.
- `parameters` and `context` are plain finite JSON objects. Required
  `action.requestHash = hashRequest(parameters)` and
  `action.contextHash = hashRequest(context)`. Every action constraint must
  occur as an own parameter field with the same canonical value.
- `audience` is the exact protected-service identifier, using bounded NFC text
  as above. It must equal the operator-configured audience and authority audience.
- `policy` has exactly `id`, `version`, `hash`: bounded ID, positive safe integer
  version and lowercase SHA-256 digest. Only version `1` is admitted; other
  representable requested versions produce signed `POLICY_VERSION_UNKNOWN`.
- `requestedAt` is canonical UTC and cannot follow receipt issuance.
- Limit: 262144 canonical UTF-8 bytes.

Request digest: SHA-256 of `besa:pre-execution-request:v1`, NUL and the full
canonical request. Policy digest: SHA-256 of `besa:action-policy:v1`, NUL and
the validated canonical ActionPolicyV1 (including ID, version and every rule).
Constraints/operation/resource/risk must be derived by a trusted tool mapper;
hashing an attacker-supplied description does not establish truthful semantics.

### Pre-execution Admission Receipt v1

All fields below are required, with no unknown fields or legacy fallback:

| Fields | Contract |
|---|---|
| `artifactVersion`, `algorithm` | `1`, `ed25519` |
| `receiptId` | `adm_` plus canonical UUIDv4 |
| `requestDigest`, `actionHash` | Digests of the supplied request and Action Envelope |
| `principalId`, `agentId`, `audience` | Exact identities/service bound by the request |
| `authorityHash`, `assertionDigest` | Signed normalized authority hash and external assertion digest; both non-null for ALLOW, nullable only for DENY with schema-invalid authority |
| `delegationChainHash` | Verified chain hash or null when no chain was required/supplied |
| `policyId`, `policyVersion`, `policyHash` | Actual configured/evaluated policy ID, version `1`, full policy digest |
| `decision`, `reasonCode` | `allow` with `ACTION_ALLOWED`, or `deny` with another stable uppercase reason |
| `issuedAt`, `expiresAt`, `nonce` | Canonical issuance time, exact action expiry and nonce; ALLOW issuance must precede expiry. DENY can record an already expired action. |
| `issuerId`, `issuerPublicKey`, `issuerPublicKeyId` | Besa decision authority identifier, canonical Ed25519 SPKI DER base64 and key fingerprint |
| `capability` | Existing ActionCapabilityV1 for ALLOW, with identical action, issuer, issuance time, policy ID and delegation hash; null for DENY |
| `signature` | Canonical base64 Ed25519 signature (64 bytes) |

Identifiers follow the 512-character NFC/control bounds above; digest fields are
64 lowercase hex characters; nonce follows the existing action nonce pattern.
Limit: 262144 canonical UTF-8 bytes. No raw parameters, bearer credentials or
private keys occur in the receipt schema. Safe signed claims are supplied in
the separately verifiable ExternalAuthority artifact.

Signature domain: `besa:pre-execution-admission:v1`. Sign the entire receipt
body except its own `signature`, including the nested capability and that
capability's signature. Receipt hash: `besa:pre-execution-receipt-artifact:v1`
over the complete signed canonical receipt. The v1 ActionEvidence `receiptHash`
may link this hash without changing evidence schema/signature bytes.

An independent verifier must:

1. Strictly validate the receipt and supported schema; verify its domain-separated
   signature against a pinned trusted admission key.
2. Match exact request/action digests, principal/agent, audience, nonce/expiry
   and supplied authority/assertion digests. Reject missing or changed input.
3. Match the actual expected policy ID, version and digest. Never resolve a
   policy ID alone to a silently different policy.
4. For ALLOW, verify normalized authority and delegation were valid at issuance,
   evaluate exact-action policy, and verify the embedded capability's signature,
   links and identical issuer/issuance/policy/delegation fields.
5. For execution, additionally verify current expiry, authority, policy and
   active trusted keys. A valid DENY is evidence only, never authorization.
6. At the enforced execution boundary, await receipt storage, atomically consume
   the action/nonce replay key and repeat current checks before invoking the
   executor. Stateless receipt/audit verification does not consume replay state.

Audit mode verifies at receipt issuance for historical use, with current trust
lifecycle controls. It cannot authorize current execution. Revoked keys are
always rejected; audit results always carry `authorized: false`. Retired keys
can verify supported prior
artifacts. DENY signatures attest the issuer's negative decision; they do not
assert that malformed authority was valid or that a side effect occurred.

Malformed/non-canonical requests and signer/configuration failures have no
trustworthy signing input and are rejected without synthesizing a receipt.
Canonical but denied requests receive signed denial receipts. The receipt
cannot prove original IdP signature validity, live revocation, exactly-once
external effects, or authority normalizer honesty from a digest alone.

### Executor enforcement and local replay adapter

`withBesaExecutor` is an executor API, not a new signed artifact. It accepts the
same request/authority and a supplied admission receipt plus host-authenticated
`{ agentId, principalId }`. Both IDs must match the action. The existing signed
context must contain `executorId` equal to the configured executor. Changing it
changes context/request digests; no new field/domain is added to legacy artifacts.
The wrapper verifies, awaits the receipt commit, atomically consumes the action
replay key, and repeats current policy/authority checks before calling the executor.

`FileReplayStore` persists one exclusive claim per SHA-256 of
`besa:file-replay-key:v1`, NUL and the existing replay key, using a private local
directory. A claim contains `recordVersion: 1`, `keyDigest`, `expiresAt` and
`consumedAt`, never the raw key. Default `power-loss` mode requires file and
directory fsync; unsupported platforms fail unavailable. Explicit `process`
mode omits directory fsync. Partial claims are spent and expiry does not delete
claims. This deployment adapter coordinates one local filesystem, not hosts,
and does not provide side-effect transactions or result replay. Actual durability
depends on the filesystem and custody of the state directory.

`conformance/pre-execution-v1.json` freezes ALLOW/DENY requests, safe signed
authority, policy, public trust inputs, receipts and hashes. It contains no
original bearer assertion or private signing key. Existing conformance vectors
continue to cover unchanged historical artifact bytes.

### New reason codes and migration

Authority codes: `AUTHORITY_VALID`, `SCHEMA_AUTHORITY_INVALID`,
`AUTHORITY_MECHANISM_UNSUPPORTED`, `SIGNATURE_AUTHORITY_INVALID`,
`TRUST_AUTHORITY_NORMALIZER_UNTRUSTED`, `EXPIRY_AUTHORITY_NOT_ACTIVE`,
`AUTHORITY_AUDIENCE_MISMATCH`, `AUTHORITY_IDENTITY_MISMATCH`,
`AUTHORITY_ACTION_NOT_GRANTED`. Adapter rejection codes also include
`AUTHORITY_ASSERTION_VERIFICATION_FAILED`, `AUTHORITY_TOKEN_USE_INVALID`,
`AUTHORITY_ISSUER_MISMATCH`, `AUTHORITY_SCOPE_NOT_GRANTED`,
`AUTHORITY_IDENTITY_INVALID`.

Admission codes: `PRE_EXECUTION_REQUEST_VALID`,
`SCHEMA_PRE_EXECUTION_REQUEST_INVALID`, `ADMISSION_REQUEST_TIME_INVALID`,
`POLICY_VERSION_UNKNOWN`, `POLICY_DIGEST_MISMATCH`, `ADMISSION_RECEIPT_VALID`,
`SCHEMA_ADMISSION_RECEIPT_INVALID`, `SIGNATURE_ADMISSION_RECEIPT_INVALID`,
`ADMISSION_TIME_INVALID`, `TRUST_ADMISSION_ISSUER_UNTRUSTED`,
`ADMISSION_REQUEST_MISMATCH`, `ADMISSION_VERIFIER_ERROR`,
`ADMISSION_VERIFIER_UNAVAILABLE`, `ADMISSION_RECORD_FAILED`, plus existing
action/delegation/replay/runtime rejection codes.

Executor codes: `SCHEMA_EXECUTOR_INPUT_INVALID`, `ADMISSION_CALLER_MISMATCH`,
`ADMISSION_EXECUTOR_MISMATCH`. Replay adapters use the existing replay codes.

These additions are packaged in the additive v1.2.0 minor release; historical
artifact schemas, signatures and verification paths remain supported. See
[`docs/RUNTIME_ADMISSION.md`](docs/RUNTIME_ADMISSION.md#migration) for frozen
call snapshots, stronger opt-in runtime, explicit authority normalization,
historical verification and downgrade rules.
