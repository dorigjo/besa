# Beta Release Checklist

Release gate for `0.1.0-beta.0`.

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
      receipt verification, and grant checks.
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

- [ ] No `.besa/key.json` is staged.
- [ ] No meter, receipt, signed manifest, or private key is staged.
- [ ] `examples/manifest.signed.json` remains ignored.
- [ ] Only intentional beta release files are staged.

## Version and documentation

- [ ] `package.json` and `package-lock.json` both use `0.1.0-beta.0`.
- [ ] `README.md`, `SECURITY.md`, and `docs/THREAT_MODEL.md` say beta.
- [ ] `CHANGELOG.md` and `docs/releases/v0.1.0-beta.0.md` describe the release.
- [ ] PowerShell examples cover every CLI command.
- [ ] Limitations still state that Besa is not production-ready.

## Publish

Only after every gate is green:

```powershell
git commit -m "Prepare Besa beta release"
git tag v0.1.0-beta.0
git push origin main
git push origin v0.1.0-beta.0
npm publish --access public --tag beta
```

Tagging and npm publication are explicit release actions. Do not perform them
as part of ordinary development or documentation changes.
