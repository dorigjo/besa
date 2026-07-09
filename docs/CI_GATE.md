# Besa as a CI/CD Gate

Besa can run in any CI pipeline to enforce manifest verification and policy checks as part of your build process. A failed signature or a denied tool call fails the build.

This is **Priority A** behavior: when Besa runs in CI, it becomes infrastructure — not a developer tool.

---

## What the CI gate enforces

1. **Manifest is signed** — any unsigned or tampered manifest fails the build
2. **Signature is trusted** — the signing key is pinned in the consumer trust store
3. **Tool calls pass policy** — declared tools that fail `admit` (wrong risk level, budget exceeded, etc.) fail the build
4. **Undeclared tools are absent** — if you test an undeclared tool, `besa admit` exits non-zero

---

## GitHub Actions example

Create `.github/workflows/besa-gate.yml`:

```yaml
name: Besa manifest gate

on:
  push:
    branches: [main]
  pull_request:
    paths:
      - 'examples/manifest.yaml'
      - 'examples/manifest.signed.json'

jobs:
  besa-gate:
    name: Verify manifest and policy
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install Besa
        run: npm install @dorigjo/besa

      - name: Verify signed manifest
        run: npx besa verify examples/manifest.signed.json
        # Fails if signature is invalid or signing key is untrusted

      - name: Gate: crm.lookup (expect allow)
        run: npx besa admit examples/manifest.signed.json crm.lookup
        # Exits non-zero if denied

      - name: Gate: crm.delete (expect deny RISK_BLOCKED)
        run: |
          result=$(npx besa admit examples/manifest.signed.json crm.delete 2>&1 || true)
          echo "$result"
          if echo "$result" | grep -q "RISK_BLOCKED"; then
            echo "OK: crm.delete correctly denied"
          else
            echo "FAIL: expected RISK_BLOCKED"
            exit 1
          fi
        # Verifies that high-risk destructive tools are blocked by default
```

---

## What each step does

| Step | What it checks | Fails if |
|---|---|---|
| `besa verify` | Signature valid, key trusted | Any tampering or unknown key |
| `besa admit <tool>` (allow case) | Tool is declared, risk accepted, budget ok | Denied for any reason |
| `besa admit <tool>` (deny case) | Tool blocked as expected | Tool was accidentally allowed |

---

## Using a consumer trust store in CI

If you are a consumer of someone else's manifest (not the signer), pin their public key in a trust store file committed to your repo:

```yaml
- name: Add publisher trust anchor
  env:
    BESA_KEY_PASSPHRASE: ${{ secrets.BESA_KEY_PASSPHRASE }}
  run: |
    npx besa trust add examples/manifest.signed.json \
      --trust ci-trust.json

- name: Verify against pinned trust store
  run: |
    npx besa verify examples/manifest.signed.json \
      --trust ci-trust.json
```

Commit `ci-trust.json` to the repository. Any new or rotated key fails the gate until explicitly trusted.

---

## Using secrets for signing in CI

If CI also signs manifests (you are the publisher), pass the key passphrase via a GitHub secret:

```yaml
env:
  BESA_KEY_PASSPHRASE: ${{ secrets.BESA_KEY_PASSPHRASE }}
```

Never commit `.besa/key.json` or `.besa/keys/` to the repository. See [SECURITY.md](../SECURITY.md).

---

## Making the gate branch-protective

In GitHub repository settings → Branch protection rules:

1. Require status checks to pass before merging
2. Add `besa-gate` as a required status check
3. Require branches to be up to date before merging

Once configured, no merge proceeds if manifest verification or policy checks fail.

---

## What the CI gate proves

- The manifest that ships in this repository is signed
- The signing key matches the declared trust anchor
- Declared tools pass your policy as of this commit
- A commit that changed the manifest without re-signing would block the merge

The CI gate is the first step toward treating agent tool declarations as first-class infrastructure artifacts — versioned, verified, and release-gated.

---

## Limitations (0.1.0)

- The trust store and signing key are local. CI runs must either generate a key per run (non-persistent verification) or use a key committed to secrets (more persistent but not HSM-backed).
- No distributed replay protection — duplicate build runs with the same manifest produce the same verification result, which is correct behavior for verification.
- No hosted verifier — consumers without the Besa CLI cannot verify receipts independently (on the roadmap).
