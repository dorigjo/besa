# Security Policy

## Supported release

The current supported line is `1.1.x`.

Besa v1.1 is additive. The frozen v1.0 signed formats (`SignedManifest`,
`Receipt`, `KeyRotation`, and `AdmissionAttestation`), their canonicalization,
signature domains, CLI behavior, and existing SDK exports remain compatible.
v1.1 adds versioned Action Envelope, Delegation, Capability, and Evidence
artifacts; it does not reinterpret legacy signed bytes.

No independent third-party security audit has been completed. The repository
includes self-authored tests, conformance vectors, a threat model, and audit
scope to make review easier, but those are not substitutes for an assessment of
your deployment and threat model.

## Security properties

Besa provides cryptographic tamper-evidence and deterministic admission for
supplied artifacts. It validates strict schemas, hashes canonical JSON, uses
domain-separated Ed25519 signatures, checks pinned key lifecycle state, and
binds a v1.1 capability to an exact action, resource, constraints, expiry, and
nonce.

It does not provide secrecy, agent identity, upstream authentication, payment
settlement, tool sandboxing, real-world execution observation, compliance
certification, or distributed replay prevention without a customer-controlled
atomic replay store. See `docs/THREAT_MODEL.md` for the complete boundary.

## Key and secret handling

- Never commit `.besa/`, private keys, key passphrases, bearer tokens, trust
  stores containing operational metadata, receipts, or evidence logs.
- Local Ed25519 keys are encrypted at rest with AES-256-GCM and scrypt, but
  local storage is not a replacement for a production secret manager or HSM.
- `besa keys rotate` provides signed continuity; it does not independently
  distribute revocation, secure archived keys, or govern who can authorize a
  rotation.
- `besa serve --action-trust` is the verification-only deployment and loads no
  private key. `--trust` enables a signing process and requires both
  `BESA_KEY_PASSPHRASE` and `BESA_ADMISSION_TOKEN`.
- Keep passphrases and bearer tokens in a deployment platform secret store. The
  provided `.env` example is documentation only; Besa never loads it.
- Do not expose a signing admission process to an untrusted executor when
  separation of duty is required.

## Hosted verifier operation

The self-hosted verifier has bounded JSON requests, header and request
timeouts, default per-address rate limits, secure response headers,
health/readiness probes, and token-protected admission routes. Operators still
must provide TLS termination, ingress authorization, network policy,
reverse-proxy limits, monitoring, backups, log retention, and incident
response. The container runs non-root and is tested read-only in CI.

`/metrics` and public verification endpoints are intentionally unauthenticated.
Use a reverse proxy or private network when their availability or metadata is
sensitive. See `docs/HOSTED_VERIFIER.md` for exact routes and configuration.

## Replay and evidence limits

An Action Envelope nonce is cryptographically bound but does not by itself make
an action globally one-time. `InMemoryReplayStore` enforces reuse only inside
one process and does not survive restarts. Use an atomic, durable
customer-operated `ReplayStore` for stronger guarantees.

`ActionEvidenceV1` proves a trusted recorder signed the supplied action,
capability, result hash, and timestamps. It does not prove an external side
effect occurred unless that recorder is independently trusted to observe it.
`AppendOnlyEvidenceLog` is a local fsyncing JSONL sink, not an immutable,
cross-process, retained ledger.

## Not a compliance claim

Do not represent Besa as SOC 2, ISO 27001, DORA, NIS2, GDPR, or EU AI Act
compliant, required, or certified. Its machine-verifiable artifacts may be
useful technical evidence in a customer-controlled security or audit workflow.

## Reporting a vulnerability

Do not disclose sensitive vulnerabilities, keys, tokens, evidence, or customer
data in a public issue. Use GitHub Private Vulnerability Reporting for this
repository: open the Security tab and select **Report a vulnerability**. Include
the affected version, deployment mode, prerequisites, a minimal reproducer,
impact, and expected versus actual behavior.

Maintainers should acknowledge reports promptly, coordinate a fix privately,
add a regression test where feasible, and publish a changelog/security note
after a fix is available. If Private Vulnerability Reporting is unavailable,
contact the repository owner privately before opening a public issue.
