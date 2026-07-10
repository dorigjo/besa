## What changed

<!-- One paragraph or bullet list. Focus on why, not what. The diff shows what. -->

## Checklist

### Build & tests

- [ ] `npm run build` passes
- [ ] `npm test` passes
- [ ] `npm run smoke` passes
- [ ] `npm run test:package` passes

### Release surface

- [ ] `npm pack --dry-run` includes only intended files
- [ ] No new files added to `.besa/`, `node_modules/`, or local release artifacts
- [ ] No stale `.tgz`, local receipts, generated keys, or temporary audit files committed
- [ ] No unnecessary npm lifecycle hooks added (`preinstall`, `install`, `postinstall`, `prepare`)

### Security & secrets

- [ ] No private keys, tokens, secrets, signed manifests, or local receipts committed
- [ ] No new dependency or GitHub Action added without a clear reason
- [ ] New or changed workflow permissions are minimal and justified

### Public claims & docs

- [ ] `CHANGELOG.md` updated if this is a user-visible change
- [ ] `SECURITY.md` / `docs/THREAT_MODEL.md` updated if this touches security behavior
- [ ] Public copy contains no unsupported compliance, enterprise, bank-ready, DORA, AI Act, SOC2, ISO, or production-proven claims
- [ ] No Claude, Codex, Anthropic, AI-author, `Co-authored-by`, or session-trace metadata added
