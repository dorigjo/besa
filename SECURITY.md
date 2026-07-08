# Security Policy

## Status: early access

Besa is an early-access **developer preview** (`0.1.0`).

The project is intended for local development, security review, and early integration feedback.

**Do not use Besa to protect production systems or real secrets yet.**

APIs, file formats, receipt formats, policy behavior, and CLI commands may change before a stable release.

## Key handling

`besa sign` creates a local Ed25519 key pair at:

```text
.besa/key.json
```

This key is for local development only.

`besa keys rotate` archives the previous private key under `.besa/keys/`,
creates a signed public rotation proof under `.besa/rotations/`, and updates
`.besa/trust.json`. Archived private keys remain sensitive.

Important rules:

* Never commit `.besa/`.
* Never commit `.besa/key.json`.
* Never reuse a demo key across environments.
* Delete archived demo keys when historical receipt signing is no longer needed.
* Do not treat the local MVP key store as production key management.

The current MVP does not include hosted key management, hardware-backed keys,
multi-user access control, or enterprise secret storage. Its rotation mechanism
provides signed key continuity, not secure custody.

## Files that must never be committed

The following files and folders must stay out of Git:

```text
.besa/
.besa/key.json
.besa/keys/
.besa/trust.json
.besa/rotations/
.besa/meter.json
.besa/receipts/
examples/manifest.signed.json
dist/
node_modules/
```

These files are ignored by default where appropriate.

Before committing, run:

```bash
git status --short
git diff --cached --name-only
```

Confirm that no generated keys, signed manifests, receipts, local meters, build outputs, or dependencies are staged.

## Security model

Besa provides **tamper-evidence**, not secrecy.

A signed manifest proves that the declared tool capabilities, scopes, risks, and metadata have not changed since signing.

A signed receipt creates a tamper-evident record of an admission decision.

Besa currently checks:

* manifest hash integrity
* Ed25519 signature validity
* public key ID consistency
* explicit public-key trust status
* signed key-rotation continuity
* whole-envelope manifest signatures, including `signedAt`
* supported signing algorithm
* declared tool capability
* declared risk level
* basic policy decisions
* budget limits
* receipt integrity

## Current MVP limitations

The current beta has important limitations:

* local key storage only (AES-256-GCM encrypted at rest; no hosted key management or HSM)
* local JSON-based meter state with single-host file locking
* no hosted verifier API
* no centralized receipt retention
* no multi-user access control
* no SSO
* no hardware-backed key storage
* no replay protection across distributed systems
* no externally trusted timestamp authority
* no hardware-backed or centrally governed key rotation
* no formal compliance certification
* no guarantee of regulatory compliance

Do not represent this beta as SOC 2, ISO 27001, DORA, AI Act, or GDPR compliant.

## Reporting a vulnerability

This is a pre-release project.

If you find a security issue, do not open a public issue with sensitive details.

Please report vulnerabilities privately using GitHub Private Vulnerability Reporting for this repository: open the Security tab and choose "Report a vulnerability".

Maintainers should enable Private Vulnerability Reporting in the repository Security settings before making the repository public.

## Threat model

A full threat model is maintained in:

```text
docs/THREAT_MODEL.md
```

The short version:

Besa is designed to help teams prove what an AI agent was allowed to do, what was blocked, and whether tool definitions or receipts were tampered with.

Besa does not yet replace production identity, authorization, key management,
audit storage, or compliance systems.
