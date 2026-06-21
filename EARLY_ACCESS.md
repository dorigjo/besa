# Besa Early Access — 0.1.0-beta.2

Besa is signed trust infrastructure for AI-agent tools.

It creates cryptographically signed **Agent Action Receipts** for every
admission decision — before the tool executes. Every call is verifiable,
tamper-evident, and auditable.

> **This is a local developer beta.** There is no hosted verifier, no hosted
> receipt API, and no distributed replay protection yet. Use for local security
> review and early integration only.

---

## What Besa does

1. **Sign** a tool manifest — declare capabilities, risk levels, scopes, and budgets.
2. **Verify** the signed manifest — fail closed on any tampering.
3. **Admit** a tool call — dry-run policy check against the signed manifest.
4. **Issue a signed receipt** — tamper-evident record of the admission decision.
5. **Verify the receipt chain** — end-to-end trust verification.

---

## Requirements

- Node.js >= 20
- A passphrase for key encryption: `BESA_KEY_PASSPHRASE` (minimum 16 UTF-8 bytes)

---

## Install from GitHub Release

Download the tarball from the [GitHub Release](https://github.com/dorigjo/besa/releases/tag/v0.1.0-beta.2):

```bash
npm install https://github.com/dorigjo/besa/releases/download/v0.1.0-beta.2/dorigjo-besa-0.1.0-beta.2.tgz
```

**Verify integrity before installing:**

```bash
curl -L -o dorigjo-besa-0.1.0-beta.2.tgz \
  https://github.com/dorigjo/besa/releases/download/v0.1.0-beta.2/dorigjo-besa-0.1.0-beta.2.tgz

sha256sum dorigjo-besa-0.1.0-beta.2.tgz
# expected: 61b5d1f11a106f7cb66efe1da075113a7f310da6e66741dd4533fa27d5c9dfb4
```

---

## Quickstart

Set your passphrase:

```bash
export BESA_KEY_PASSPHRASE="your-passphrase-at-least-16-bytes"
```

Run the core flow:

```bash
# Generate the local signing key
besa keys

# Sign the example manifest
besa sign examples/manifest.yaml

# Verify the signature
besa verify examples/manifest.signed.json

# Pin the publisher key as a trust anchor
besa trust add examples/manifest.signed.json

# Admission dry-run (does not consume budget)
besa admit examples/manifest.signed.json crm.lookup

# Issue a signed receipt (consumes budget)
besa receipt crm.lookup examples/manifest.signed.json \
  --request examples/request.json

# Verify the receipt chain end-to-end
besa verify-receipt .besa/receipts/<id>.json examples/manifest.signed.json
```

---

## Known limitations

- Local key storage only — no HSM or hosted key management
- File-based meter and trust state — single-host use only
- No distributed replay protection across machines
- No external trusted timestamp authority
- No hosted verifier, receipt retention, or SIEM export
- No production identity or multi-user authorization
- No formal compliance certification
- Key rotation uses 4 sequential writes — a crash between them needs manual `besa trust apply` recovery
- Trust store is plain JSON — local filesystem access is out of the threat model

---

## Security warning

This is a **local beta**. Private keys are encrypted at rest with AES-256-GCM,
but there is no hosted verifier and no network-level replay protection. Do not
use in production systems or expose `.besa/` to untrusted processes.

The `BESA_KEY_PASSPHRASE` environment variable protects your key at rest. Treat
it like any other secret — do not commit it, do not log it.

---

## Feedback

Open an issue: [github.com/dorigjo/besa/issues](https://github.com/dorigjo/besa/issues)

Early access feedback on the trust flow, CLI ergonomics, and SDK interface is
especially welcome.
