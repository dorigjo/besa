---
name: Bug report
about: Report something that is broken or behaves incorrectly
labels: bug
---

<!--
SECURITY: Do NOT paste private keys, key passphrases, tokens, signed manifests,
receipts, trust stores, or customer/production data. Redact anything sensitive.

If you are reporting a security VULNERABILITY, do NOT open a public issue —
follow the private process in SECURITY.md instead.
-->

## Summary

<!-- One sentence: what is broken? -->

## Which surface is involved?

<!-- Keep the ones that apply, delete the rest. -->

- [ ] Manifest signing (`besa sign`)
- [ ] Verification (`besa verify` / `besa verify-receipt`)
- [ ] Admission / policy gate (`besa admit`)
- [ ] Receipts (`besa receipt`)
- [ ] Grants (`--agent` / `--grants`)
- [ ] Trust store / key rotation (`besa trust` / `besa keys`)
- [ ] CLI / shell behavior
- [ ] npm install / package contents
- [ ] CI / GitHub Actions gate
- [ ] SDK (`@dorigjo/besa` import)

## Environment

- **Besa version:** (`npx besa --version`, or the installed `@dorigjo/besa` version)
- **Installation method:** (`npm install @dorigjo/besa` / release tarball / build from source)
- **Node.js version:** (`node --version`)
- **npm version:** (`npm --version`)
- **OS:** (e.g. Windows 11, macOS 14, Ubuntu 24.04)
- **Shell:** (e.g. PowerShell, bash, zsh)

## Exact command

```
<paste the exact command you ran — redact secrets>
```

## Expected behavior

<!-- What should have happened? -->

## Actual behavior / full output

```
<paste the complete output, including any reason code — redact secrets>
```

## Minimal reproducible example

<!--
The smallest manifest / grant set / sequence of steps that reproduces the issue.
Use synthetic values only — no real keys, tokens, receipts, or customer data.
-->

1.
2.
3.

## Additional context

<!-- Anything else that helps: recent changes, related CI logs, screenshots. -->
