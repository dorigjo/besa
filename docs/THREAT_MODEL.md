# Besa Threat Model

Status: beta (`0.1.0-beta.2`).

This document explains what Besa protects against today, what it does not protect against yet, and which risks still exist in the current MVP.

## Assets

Besa currently protects or records the following assets:

* **Trust anchors** - pinned public keys and their lifecycle status.
* **Rotation proofs** - old-key-signed transitions to replacement keys.

* **Tool manifests** — declared tools, capabilities, risks, scopes, budgets, and server metadata.
* **Signing keys** — the local Ed25519 key pair stored at `.besa/key.json`.
* **Signed manifests** — manifests combined with `manifestHash`, `signature`, `publicKey`, and `publicKeyId`.
* **Admission decisions** — allow or deny decisions for requested tool usage.
* **Receipts** — signed, tamper-evident records of admission decisions.
* **Action meter state** — local usage counts used for budget checks.

## Trust boundaries

### Untrusted inputs

Besa treats the following inputs as untrusted:

* raw manifest files
* signed manifest JSON files
* tool names passed to the CLI
* request metadata
* user-provided file paths
* generated signed manifest artifacts

These inputs must be validated or verified before they are trusted.

### Trusted components in the current MVP

The current MVP assumes the following local components are trusted:

* the machine running the CLI
* the operator running the CLI
* the local `.besa/key.json` file
* the local `.besa/trust.json` file
* the local `.besa/meter.json` file
* the local filesystem

This is acceptable for a local developer preview, but not enough for production or multi-user environments.

## Attacker goals

A realistic attacker may try to:

1. Modify a manifest after it was signed.
2. Replace a manifest with a different one.
3. Use a tool that should be denied.
4. Forge a signed manifest.
5. Forge or modify a receipt.
6. Swap the public key or public key ID.
7. Bypass or reset budget limits.
8. Reuse old receipts or signed manifests.
9. Steal the local signing key.
10. Commit private keys or generated artifacts by mistake.
11. Present a valid signature under an attacker-controlled, untrusted key.
12. Continue new admissions after a signing key is retired or revoked.

## Current mitigations

### Manifest tampering

Besa calculates a stable hash of the manifest.

If the manifest changes after signing, verification recomputes the hash and fails closed with:

```text
E_MANIFEST_HASH_MISMATCH
```

This protects against silent changes to declared tools, scopes, capabilities, risks, budgets, or server metadata.

### Signature tampering

Besa signs the complete manifest envelope with Ed25519, including the manifest,
manifest hash, algorithm, public key, public key ID, and signing timestamp.

If the signature is changed, malformed, or does not match the manifest, verification fails with:

```text
E_SIGNATURE_INVALID
```

### Public key mismatch

Besa checks that the declared `publicKeyId` matches the included public key.

If the key ID does not match, verification fails with:

```text
E_PUBLIC_KEY_ID_MISMATCH
```

This helps detect key swapping.

### Trust anchors and key continuity

A cryptographically valid signature is accepted only when its public key is in
the selected trust store. A rotation proof must be signed by the previously
trusted key before a consumer can promote the replacement key.

Retired keys remain valid only for artifacts timestamped before retirement and
cannot authorize new admissions. Revoked keys are rejected for all artifacts.

Artifact timestamps are covered by signatures but are supplied by the signing
host. Besa does not currently provide an external trusted timestamp authority.

### Unsupported algorithms

The current MVP only supports Ed25519.

If a signed manifest declares another algorithm, verification fails with:

```text
E_ALGORITHM_UNSUPPORTED
```

### Dangerous tool usage

The default policy denies destructive high-risk tools.

For example, a tool with:

```text
capability: destructive
risk: high
```

is denied by default.

### Unknown tools

If a requested tool does not exist in the signed manifest, Besa denies the request.

### Budget limits

Besa can deny a tool request when the configured local usage budget is exceeded.

Budget checks and increments are serialized with a local file lock. Meter
updates use atomic replacement so concurrent local processes cannot spend the
same remaining call.

This remains local-only and is not production-grade distributed rate limiting.

### Receipt tampering

Besa signs receipts.

If a receipt is modified after creation, receipt verification fails.

This creates a tamper-evident record of what Besa allowed or denied.

## Current MVP limitations

The current beta has important limitations:

* local unencrypted key storage
* no hosted verifier service
* no hardware-backed keys
* no hardware-backed or centrally governed key lifecycle
* no multi-user access control
* no caller identity binding
* no authentication layer
* no centralized receipt storage
* no distributed replay protection
* no shared production-grade meter state
* no dashboard
* no policy language beyond the current basic rules
* no formal compliance certification

## Key leakage risk

The private key is stored locally at:

```text
.besa/key.json
```

If an active key leaks, an attacker may be able to sign malicious manifests or
receipts until consumers apply a revocation or trusted rotation.

Current protections:

* `.besa/` is ignored by Git.
* demo keys are local-only
* generated private keys should never be committed
* local rotation proofs preserve public-key continuity
* consumers can mark compromised public keys as revoked

This is not production key management.

Future versions should use stronger protections such as hosted key management,
encryption at rest, governed rotation policies, and hardware-backed signing.

## Replay risk

The current MVP does not provide full distributed replay protection.

Receipts include timestamps, but there is no shared nonce store, no global receipt registry, and no distributed replay database.

The local meter prevents concurrent over-consumption on one host, but it does
not prevent replay across machines, environments, or after local state reset.

## Out of scope for the current beta

Besa does not currently provide:

* secrecy of tool payloads
* encryption of business data
* production identity management
* production authorization management
* enterprise audit retention
* SIEM integration
* compliance certification
* legal compliance guarantees
* prevention of all malicious agent behavior
* sandboxing of tool execution
* malware detection
* data loss prevention

Besa is a control and evidence layer, not a complete security platform.

## Future mitigations

Planned or possible future mitigations include:

* hosted verifier API
* hosted receipt API
* remote receipt retention
* shared ActionMeter state
* replay-resistant metering
* remotely distributed revocation and rotation state
* HSM-backed or hosted signing
* caller identity binding
* agent identity binding
* declarative policy files
* approval workflows
* audit export
* SIEM export
* organization-level controls
* production-grade dashboard

## Summary

Besa currently provides local tamper-evidence for tool manifests and admission receipts.

It helps answer questions such as:

* Was this tool definition changed after signing?
* Was this tool actually allowed or denied?
* Was this receipt modified?
* Did the requested tool exist in the signed manifest?
* Was the requested tool too risky?
* Was the local budget exceeded?

The current beta is useful for development, integration testing, security
review, and architecture validation.

It is not yet production security infrastructure.
