# Release Checklist

Release gate for the current version in `package.json`.

## Quality

```powershell
npm ci
npx tsc --noEmit
npm run build
npm test
npm run smoke
npm run smoke:server
npm run test:examples
npm run test:docs
npm run test:package
npm audit --omit=dev
```

- [ ] Clean install succeeds from `package-lock.json`.
- [ ] TypeScript compilation succeeds.
- [ ] Unit tests pass.
- [ ] The isolated smoke test covers load, sign, verify, allow, deny, receipt,
      receipt verification, trust pinning, key rotation, and grant checks.
- [ ] The hosted-verifier smoke test covers `/health`, `/v1/verify/*`,
      `/v1/admit` (enabled and disabled), rate limiting, `/metrics`, and the
      default loopback-only bind.
- [ ] `examples/` type-checks against the current SDK surface.
- [ ] The docs-receipt consistency check passes.
- [ ] The packed tarball installs in an empty project and exposes its SDK and CLI.
- [ ] Parallel worker tests prove local call budgets cannot be overspent.
- [ ] Production dependency audit reports no vulnerabilities.

## Package

```powershell
npm pack --dry-run
```

- [ ] Package contains root `dist/*.js` and `dist/*.d.ts`.
- [ ] Package contains the three files in `examples/`.
- [ ] Package contains `README.md`, `LICENSE`, and `package.json`.
- [ ] Package excludes `dist/tests/`, `src/`, `.besa/`, signed manifests,
      receipts, `node_modules/`, and local tool directories.

## Trust artifacts

```powershell
git status --short
git diff --cached --name-only
```

- [ ] No `.besa/key.json` or `.besa/keys/` archive is staged.
- [ ] No local trust store or generated rotation proof is staged.
- [ ] No meter, receipt, signed manifest, or private key is staged.
- [ ] `examples/manifest.signed.json` remains ignored.
- [ ] Only intentional release files are staged.

## Version and documentation

- [ ] `package.json` and `package-lock.json` use the same version number.
- [ ] `README.md`, `SECURITY.md`, and `docs/THREAT_MODEL.md` reference that
      same version and describe current capability accurately (no existing
      feature marked "not implemented," no planned feature marked as shipped).
- [ ] `CHANGELOG.md` has a dated entry for this version.
- [ ] PowerShell examples cover every CLI command.
- [ ] Limitations accurately state what has (and has not) been independently
      security-audited or run in production — never claim regulatory or
      compliance certification.

## Publish

Only after every gate is green:

```powershell
git commit -m "chore: release v<version>"
git tag v<version>
git push origin main
git push origin v<version>
npm login          # authenticate first (2FA if enabled)
npm publish --access public
```

Tagging and npm publication are explicit release actions. Do not perform them
as part of ordinary development or documentation changes.
