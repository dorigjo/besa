# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-12

Positioning patch. No protocol, artifact, or API changes.

### Changed

* Aligned CLI positioning with Besa's cryptographic admission and evidence
  infrastructure category (`besa --help` tagline).
* Removed outdated early-access wording from the CLI security guidance.
  Preserved explicit production security guidance (encrypted-at-rest keys,
  never commit `.besa/`) and added a pointer to review `SECURITY.md` and
  the trust model before production deployment.
* Synced `package-lock.json`'s version field, which had been left at
  `0.1.0` since before the 1.0.0 release.

## [1.0.0] - 2026-08-12

First stable release. The CLI surface, SDK exports, and every signed-
artifact format (`SignedManifest`, `Receipt`, `KeyRotation`,
`AdmissionAttestation`) are now frozen — a future breaking change to any
of them requires a major version bump. No independent third-party
security audit has been performed (see `docs/V1_SECURITY_RELEASE_REVIEW.md`).

### Added

* `SPEC.md` and `conformance/golden-v1.json` now ship inside the published
  npm package. The specification and its frozen test vectors were
  previously repo-only, which meant anyone building an independent
  verifier from the package alone had neither the normative rules nor a
  way to self-check against real signed artifacts. Independent
  implementability is the point of freezing a format, so the spec now
  travels with the code.
* `conformance/golden-v1.json` — publishable v1 conformance vectors
  (canonical-ordering vector, public key, hashes, a signed manifest, and a
  receipt). A test asserts the published file stays identical to the
  frozen in-repo fixtures and that the published bytes themselves verify,
  so the vectors external implementers receive can never drift from the
  implementation.
* `besa keys fingerprint` — prints the local signing key's SHA-256
  fingerprint in colon-grouped hex, without needing to parse `besa keys`'
  JSON output.
* `besa keys export-public` — prints the local public key (base64 DER)
  alone, for scripting and sharing.
* Key passphrases (`sealKeyPair`/`openKeyPair`) now require at least 8
  distinct characters in addition to the existing 16-1024 byte length
  check, rejecting trivially-guessable low-entropy passphrases that
  previously passed length validation alone.
* Windows ACL hardening for `.besa/key.json` and archived rotation keys:
  `icacls` now restricts the file to the current user (POSIX already did
  this via `chmod 0600`; Windows had no equivalent until now).
* `besa export-evidence <manifest> <receipt>` — exports an already-signed
  manifest + receipt as a structured "Evidence Envelope" JSON document for
  external audit / evidence-retention workflows (`docs/EVIDENCE_ENVELOPE.md`).
  Reuses the existing `verify`/`verify-receipt` verification path; issues no
  new signature and makes no new trust decision. Exported from the SDK as
  `createEvidenceEnvelope`.
* `npm run sbom` — generates a CycloneDX software bill of materials via the
  native `npm sbom` command (no new dependency).
* `besa serve` — a stateless hosted verifier over HTTP, wrapping the exact
  signature-verification functions the CLI already uses
  (`docs/HOSTED_VERIFIER.md`).
* `besa serve --trust <file>` — opt-in, non-consuming runtime admission
  endpoint (`POST /v1/admit`) issuing signed `AdmissionAttestation`s
  without ever acquiring the local meter lock, so it cannot block the
  server's event loop or be used to remotely exhaust budget
  (`docs/RUNTIME_ADMISSION.md`).
* `GET /metrics` on the hosted verifier — read-only, in-memory, per-process
  request counters (`requestsTotal`, `requestsByRoute`, `requestsByStatus`,
  `rateLimitedTotal`), reset on restart. Always available, no
  authentication (matches the rest of the server's public-endpoint model).
* `besa serve --rate-limit <n>` — opt-in, fixed-window rate limiting keyed
  by client remote address, off by default. Rejects with `429` and a
  `Retry-After` header before the request body is even read.
* `besa serve --host <addr>` — explicit opt-in for binding beyond loopback
  (see Security, below, for why this exists).
* Structured JSON access logging (method/route/status/duration) to stdout
  for every request the hosted verifier handles — metadata only, never
  headers, bodies, keys, or signatures.
* Graceful shutdown (`SIGINT`/`SIGTERM`) and a `clientError` handler for
  `besa serve`, so malformed low-level HTTP or a signal closes the server
  cleanly instead of dying mid-request.

### Security

* Fixed: `besa serve` bound to every network interface by default despite
  its startup banner saying "listening on http://localhost:<port>" —
  reachable from other machines on the same network without the operator
  realizing it. Now binds to `127.0.0.1` (loopback-only) by default;
  `--host` opts into a wider bind explicitly and prints a visible warning.
* Fixed: `readJsonFile()` labeled every file-read error — including a
  plain missing-file `ENOENT` — as `"invalid JSON at <path>"`, misleading
  anyone who pointed the CLI at a typo'd or missing path into debugging a
  JSON syntax error that didn't exist. A missing/unreadable file now
  surfaces its own real error.

### Documentation

* Corrected several stale "not implemented" / "coming soon" claims in
  `README.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/CI_GATE.md`,
  `docs/RUNTIME_ADMISSION.md`, and `docs/AGENT_GATEWAY.md` that understated
  what already exists (the hosted verifier, runtime admission, and
  rate limiting shipped in this same release).
* Replaced "early access, may change before a stable release" framing
  with a precise v1.0 stability statement: CLI/SDK/artifact-format surface
  is frozen; independent security audit and production track record are
  separate, still-open items, named as such rather than implied.
* New: `docs/V1_SECURITY_RELEASE_REVIEW.md` (cryptography/trust-model/
  runtime/supply-chain review), `docs/PHASE9_ADOPTION_READINESS_AUDIT.md`,
  `docs/PHASE10_EXTERNAL_VALIDATION_READINESS.md`.
* `SPEC.md`: corrected a contradiction that would have broken any
  independent implementation. The artifact sections stated "field order is
  significant (it is the signed byte order)" while the canonicalization
  section correctly described lexicographic key sorting. Only the latter
  is true — `canonicalize` sorts keys — so an implementer who serialized
  fields in table order and signed the result produced signatures this
  implementation rejects. The tables are now labelled as documentation
  order, with an explicit statement that lexicographic order determines
  the signed bytes. No code or artifact bytes changed; the specification
  was wrong, not the implementation.
* `SPEC.md`: filled the remaining gaps that blocked independent
  implementation — an ordered sign/verify algorithm, exact `publicKeyId`
  derivation (base64-decode → SHA-256 → lowercase hex), the rule that an
  absent request hashes the empty object, the requirement that absent
  optional receipt fields are omitted rather than emitted as `null`, and
  the previously undocumented `AdmissionAttestation` artifact (including
  its `besa:admission-attestation:v1` signature domain) and
  `EvidenceEnvelope` export format. The envelope is documented explicitly
  as unsigned and therefore not evidence on its own.

### Breaking Changes

None. Every addition is opt-in or purely additive; a plain `besa serve`
with no new flags is behaviorally unchanged except for the corrected
default bind address (a security fix, not an API change) and the
always-on `/metrics` route and access-log lines.

### Notes

* No new runtime dependencies. 167 tests pass (was 149 at the start of
  this release cycle); build, smoke, `smoke:server` (extended with
  metrics/performance/rate-limit checks against the real built binary),
  and package checks are green.

## [0.1.0] - 2026-07-08

First public release. Consolidates the beta series (beta.0 → beta.5) into a stable
`0.1.0` early-access developer preview. The signed-artifact formats are unchanged
since beta.2, so existing signed manifests, receipts, trust stores, and rotation
proofs remain verifiable.

### Changed

* Version promoted from `0.1.0-beta.5` to `0.1.0` (first public tagged release).
* Unified version references across `README.md`, `SECURITY.md`,
  `docs/THREAT_MODEL.md`, and `docs/RELEASE_CHECKLIST.md`, and reframed
  "public developer beta" as "first public release (early access)".
* README install guidance pins the exact version (`@dorigjo/besa@0.1.0`) instead
  of the `@beta` dist-tag.

### Notes

* Scope is unchanged: local, single-host tamper-evidence for AI-agent tool calls.
  Not production security infrastructure. See
  [Limitations](README.md#limitations).
* No new dependencies. 56 tests pass; build, smoke, package-smoke, and
  `npm pack --dry-run` are green on Node.js 20, 22, and 24.
* Besa does not guarantee compliance, prevent fines, or replace legal, security,
  risk, or compliance work.

## [0.1.0-beta.5] - 2026-06-23

### Changed

* Published to npm as primary distribution channel (`@dorigjo/besa@beta`).
* Updated README install section: `npm install @dorigjo/besa` is now the primary command; `@beta` pin is listed as secondary.
* Updated README quickstart to use `npx besa` throughout; removed all `node dist/index.js` invocations from public documentation.
* Updated the landing page (`site/` and `docs/`) quickstart to `npm install @dorigjo/besa` and `npx besa`.
* Removed "public release coming soon" badge and the "Early Access" tarball-install section from README.
* Updated beta note from beta.4 to beta.5 and from "local developer beta" to "public developer beta".
* Bumped the version reference in `SECURITY.md` to beta.5.
* "Build from source" is now a distinct `###` subsection under Install.

### Fixed

* Corrected the SHA-256 public-key fingerprint wording in the README security model to describe full 256-bit (64-hex-character) fingerprints.

### Notes

* On publish, the `latest` and `beta` dist-tags both point to this release, so `npm install @dorigjo/besa` resolves to it; the `alpha` dist-tag is unchanged.
* Besa does not guarantee compliance, prevent fines, or replace legal, security, risk, or compliance work.

## [0.1.0-beta.4] - 2026-06-22

### Changed

* Replaced postinstall ASCII-art diamond with a clean terminal wordmark (no shape characters, no mid-line ANSI color switches, PowerShell-safe).
* Updated public site background from parchment (`#FDF0D5`) to near-white (`#fafafa`) in `site/styles.css` and `docs/styles.css`.
* Removed unused `--parchment-50` CSS token from `site/styles.css` and `docs/styles.css`.
* Changed postinstall ANSI color from true-color (`\x1b[38;2;193;18;31m`) to standard 16-color (`\x1b[31m`) for broader terminal compatibility including Windows conhost.
* Added legal disclaimer footer to `site/index.html` and `docs/index.html`: Besa does not guarantee regulatory compliance, prevent fines, or replace legal or compliance counsel.
* Removed marketing-framing language from `README.md`: replaced "Every call is a liability" and "compliance team" copy with factual description; removed regulatory framework table.
* Updated browser theme-color meta tag from `#FDF0D5` to `#fafafa` in both HTML entry points.
* Updated page `<title>` and `<meta name="description">` to reflect current positioning: "Signed Trust for AI-Agent Tools".
* Updated Early Access README to reference the beta.4 tarball URL.

### Notes

* No npm publish for this beta; distribution remains GitHub Release tarball.
* Besa does not guarantee compliance, prevent fines, or replace legal, security, risk, or compliance work.

## [0.1.0-beta.3] - 2026-06-21

### Changed

* Prepared final beta release metadata.
* Clarified public-safe legal messaging boundaries.
* Updated release preparation workflow for GitHub Release tarball distribution.

### Notes

* No npm publish for this beta due to npm account access recovery.
* Distribution remains GitHub Release tarball.
* Besa does not guarantee compliance, prevent fines, or replace legal, security, risk, or compliance work.

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

[0.1.0]: https://github.com/dorigjo/besa/releases/tag/v0.1.0
