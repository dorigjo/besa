# Beta Release Checklist

Release gate for `0.1.0-beta.1`.

## Quality

```powershell
npm ci
npx tsc --noEmit
npm run build
npm test
npm run smoke
npm audit --omit=dev
```

- [ ] Clean install succeeds from `package-lock.json`.
- [ ] TypeScript compilation succeeds.
- [ ] Unit tests pass.
- [ ] The isolated smoke test covers load, sign, verify, allow, deny, receipt,
      receipt verification, trust pinning, key rotation, and grant checks.
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
- [ ] Only intentional beta release files are staged.

## Version and documentation

- [ ] `package.json` and `package-lock.json` both use `0.1.0-beta.1`.
- [ ] `README.md`, `SECURITY.md`, and `docs/THREAT_MODEL.md` say beta.
- [ ] `CHANGELOG.md` and `docs/releases/v0.1.0-beta.1.md` describe the release.
- [ ] PowerShell examples cover every CLI command.
- [ ] Limitations still state that Besa is not production-ready.

## Publish

Only after every gate is green:

```powershell
git commit -m "Add trust anchors and key rotation"
git tag v0.1.0-beta.1
git push origin main
git push origin v0.1.0-beta.1
npm publish --access public --tag beta
```

Tagging and npm publication are explicit release actions. Do not perform them
as part of ordinary development or documentation changes.
