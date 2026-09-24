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

## Severity

<!-- Pick one: Low / Medium / High / Critical -->

## Security impact

<!-- Answer explicitly, even if "no":
Can a wrong or tampered signature be accepted as valid?
Can a blocked/denied action still execute?
Can a trust, delegation, replay, admission, or evidence boundary be bypassed? -->

## Which surface is involved?

<!-- Keep the ones that apply, delete the rest. -->

- [ ] Manifest signing (`besa sign`)
- [ ] Verification (`besa verify` / `besa verify-receipt`)
- [ ] Action Envelope / action hashing
- [ ] Action policy / admission decision
- [ ] Signed Action Capability
- [ ] Delegation chain
- [ ] Runtime wrapper (`withBesa`)
- [ ] MCP wrapper (`withBesaMcp`)
- [ ] Replay store / one-time execution
- [ ] Action Evidence / evidence sink
- [ ] Hosted Verifier (`besa serve`)
- [ ] Legacy admission (`besa admit`)
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
The smallest Action Envelope, policy, capability, manifest, grant set, or
sequence of steps that reproduces the issue. Use synthetic values only — no
real keys, tokens, receipts, evidence records, or customer data.
-->

1.
2.
3.

## Regression

<!-- Last version where this worked correctly, and first version where it
broke, if known. Leave blank if this never worked / is not a regression. -->

## Additional context

<!-- Anything else that helps: recent changes, related CI logs, screenshots. -->
