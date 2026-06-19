# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.2] - 2026-06-19

### Added

* AES-256-GCM key encryption at rest with scrypt KDF (N=32768, r=8, p=1);
  `BESA_KEY_PASSPHRASE` is required for all key operations.
* `src/keystore.ts`: `sealKeyPair` / `openKeyPair` with AEAD authentication
  (public key DER used as AAD).
* `src/io.ts`: `readUtf8File` (1 MB limit, strict UTF-8), `readJsonFile`,
  `writeJsonAtomic` (write-temp-then-rename), `writeJsonExclusive`.
* Bounded canonical JSON: node limit (100k), depth (64), bytes (1 MB).
* Full 64-character SHA-256 public key fingerprints (was 16-character truncated).
* Domain-separated Ed25519 signature messages (`besa:<domain>:v1\0<canonical-json>`).
* Timing-safe public key comparison via `crypto.timingSafeEqual` in `validateKeyPair`.
* Symlink protection for key files and trust store paths.
* ASCII-only tool name validation (`^[a-zA-Z0-9._-]{1,256}$`) in both the
  manifest schema and the admission engine.
* Trust store path must end in `.json`; symlink writes are rejected.
* Atomic budget increment: `admitAndConsume` holds a cross-process file lock
  for the full check-and-increment cycle.
* PID-verified stale meter lock detection and recovery.
* S5 Sovereign Diamond logo on `npm install` (TTY only; skipped in CI).
* Installed-package smoke test covering npm tarball installation, SDK import,
  generated CLI binary, and the complete local trust flow.
* Dedicated security test suite covering key fingerprints, domain separation,
  canonical JSON limits, keystore encryption, fail-closed admission, schema
  strictness, trust timestamp validation, and bounded file reads.
* Stale-lock-owned-by-live-process regression test.

### Changed

* Manifest signatures now cover the entire artifact envelope, including
  `signedAt`, key identity, algorithm, and manifest hash — closing the
  `signedAt` injection vector.
* Canonicalization now accepts only finite JSON values and plain JSON objects;
  rejects circular references, accessors, non-JSON types, and non-plain objects.
* `besa admit` is explicitly labeled `[dry-run]`; budget is only consumed by
  `besa receipt`.
* Key rotation pre-computes both scrypt seals before any filesystem write.
* CLI parsing rejects unknown, duplicate, and valueless flags.
* The npm binary path uses npm's canonical package format.

### Security

* Private key material is encrypted at rest; plaintext keys on disk are
  migrated to AES-256-GCM sealed format on first load.
* RSA and other non-Ed25519 DER keys are rejected before signing or trust use.
* Meter lock release verifies lock token ownership before unlinking.
* Unsigned top-level fields are rejected from signed manifest artifacts.
* Trust store is validated and re-validated on every read and before every write.
* `npm audit --omit=dev` added to CI on all Node.js matrix versions.

## [0.1.0-beta.1] - 2026-06-18

### Added

* Explicit, versioned public-key trust stores.
* Signed Ed25519 key-rotation proofs with active, retired, and revoked states.
* `trust add`, `trust apply`, `trust revoke`, `trust list`, and `keys rotate`
  CLI commands.
* Parallel ActionMeter coverage using Node.js worker threads.

### Changed

* Verification, admission, and receipt verification now require a trusted key.
* Signing anchors the local publisher key in `.besa/trust.json`.
* Meter budget checks and increments now run under a cross-process file lock.
* Meter and CLI JSON writes use atomic temporary-file replacement.

### Security

* New admission under retired keys is denied while pre-rotation artifacts remain
  verifiable.
* Revoked keys are rejected for both current and historical artifacts.
* Stale meter locks can be recovered without silently resetting budget state.

## [0.1.0-beta.0] - 2026-06-18

### Added

* `verify-receipt` CLI command for end-to-end receipt trust-chain validation.
* Optional `--request <request.json>` input for receipt request hashing.
* Runtime validators for signed manifests, receipts, and local key pairs.
* Node.js 24 to the CI compatibility matrix.

### Changed

* Receipt signing now requires the local key to match the signed manifest key.
* ActionMeter keys are scoped by manifest hash and tool name.
* The smoke test now runs in an isolated temporary workspace.
* The test runner executes in-process for reliable Windows and sandbox support.
* Release documentation and package metadata now identify the beta consistently.

### Security

* Malformed signed manifests and receipts fail closed with explicit reason codes.
* Corrupt meter state fails closed instead of silently resetting call counts.
* Existing local key files are validated and restricted to mode `0600` where
  the operating system supports POSIX file permissions.

## [0.1.0-alpha.1] - 2026-06-15

Added a minimal grant / permission layer so admission can be scoped per agent.

### Added

* `agentId` support across admission decisions and receipts.
* Grant sets via `grants.yaml` (`examples/grants.yaml`), with `loadGrants` / `validateGrantSet`.
* `checkGrant` with reason codes `GRANT_OK`, `TOOL_NOT_GRANTED`, and `AGENT_NOT_FOUND`.
* Grant-aware admission: `admit` and `receipt` accept `--agent` and `--grants` (opt-in, backward-compatible).
* Receipts now carry `agentId` and `grantReasonCode` (signed; omitted when unused).
* Grant unit tests (`src/tests/grant.test.ts`) and grant-aware smoke steps.

### Changed

* Version bumped to `0.1.0-alpha.1`.
* npm `files` allowlist now includes `examples/grants.yaml`.

## [0.1.0-alpha.0] - 2026-06-14

Initial alpha / developer preview of Besa — signed trust infrastructure for AI-agent tools.

### Added

* Tool manifest loading from YAML and JSON.
* Manifest schema validation for server metadata, tools, capabilities, risks, scopes, input schemas, and budgets.
* Ed25519 key generation.
* Manifest signing.
* Signed manifest verification.
* Stable canonical hashing with SHA-256 `manifestHash`.
* Admission engine with explicit allow / deny decisions.
* Reason codes:

  * `ALLOWED`
  * `TOOL_NOT_FOUND`
  * `RISK_BLOCKED`
  * `BUDGET_EXCEEDED`
* Default policy that denies destructive high-risk tools.
* Mini ActionMeter with local per-tool call counts and budget enforcement.
* Signed, tamper-evident receipts.
* Receipt verification.
* CLI commands:

  * `keys`
  * `load`
  * `sign`
  * `verify`
  * `admit`
  * `receipt`
* TypeScript SDK exports.
* Example manifest at `examples/manifest.yaml`.
* Test suite with 19 tests.
* Cross-platform smoke test via `npm run smoke`.
* GitHub Actions CI workflow for Node.js 20 and 22.
* Security policy in `SECURITY.md`.
* Threat model in `docs/THREAT_MODEL.md`.

### Changed

* Package version set to `0.1.0-alpha.0`.
* Node.js engine set to `>=20`.
* npm package file allowlist tightened to include release-safe files only.

### Security

* `.besa/` is ignored by Git.
* Local private keys are excluded from source control.
* Local meter state and receipts are excluded from source control.
* Generated signed example manifests are excluded from source control.
* Verification fails closed on:

  * manifest hash mismatch
  * invalid signature
  * public key ID mismatch
  * unsupported algorithm

### Known limitations

* Alpha / developer preview only.
* Not production-ready.
* Local unencrypted key storage.
* Local JSON meter only.
* No hosted verifier API yet.
* No hosted receipt API yet.
* No distributed replay protection.
* No key rotation or revocation.
* No formal compliance certification.

[0.1.0-alpha.0]: https://github.com/dorigjo/besa/releases/tag/v0.1.0-alpha.0
[0.1.0-alpha.1]: https://github.com/dorigjo/besa/releases/tag/v0.1.0-alpha.1
[0.1.0-beta.0]: https://github.com/dorigjo/besa/releases/tag/v0.1.0-beta.0
[0.1.0-beta.1]: https://github.com/dorigjo/besa/releases/tag/v0.1.0-beta.1
[0.1.0-beta.2]: https://github.com/dorigjo/besa/releases/tag/v0.1.0-beta.2
