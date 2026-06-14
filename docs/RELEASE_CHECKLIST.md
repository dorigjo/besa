# Release Checklist

Pre-release gate for Besa.

Every step must pass before tagging, publishing, or announcing a release.

## 1. Quality gates

Run:

```powershell
npm ci
npm run build
npm test
npm run smoke
```

Checklist:

* [ ] `npm ci` installs cleanly from the lockfile.
* [ ] `npm run build` succeeds.
* [ ] `npm test` is green.
* [ ] `npm run smoke` ends with `SMOKE OK`.
* [ ] The smoke test covers load, sign, verify, admit allow, admit deny, and receipt creation.
* [ ] The deny path for `crm.delete` exits with code `1` and is treated as expected behavior.

## 2. Package contents

Run:

```powershell
npm pack --dry-run
```

Checklist:

* [ ] Package includes `dist/*.js`.
* [ ] Package includes `dist/*.d.ts`.
* [ ] Package includes `examples/manifest.yaml`.
* [ ] Package includes `README.md`.
* [ ] Package includes `LICENSE`.
* [ ] Package includes `package.json`.
* [ ] Package does not include `dist/tests/`.
* [ ] Package does not include `examples/manifest.signed.json`.
* [ ] Package does not include `.besa/`.
* [ ] Package does not include `src/`.
* [ ] Package does not include `node_modules/`.
* [ ] Package does not include `.claude/`.

## 3. Secret safety

Run:

```powershell
git status --short
git diff --cached --name-only
```

Checklist:

* [ ] `.besa/` is not staged.
* [ ] `.besa/key.json` is not staged.
* [ ] `.besa/meter.json` is not staged.
* [ ] `.besa/receipts/` is not staged.
* [ ] `examples/manifest.signed.json` is not staged.
* [ ] No private keys are staged.
* [ ] No generated receipts are staged.
* [ ] No local meter state is staged.
* [ ] No build output is staged unless intentionally released through npm packaging.
* [ ] No dependency folders are staged.

## 4. Versioning

Checklist:

* [ ] `package.json` version is correct.
* [ ] `package-lock.json` version matches `package.json`.
* [ ] `CHANGELOG.md` has an entry for the release version.
* [ ] The version follows semantic versioning.
* [ ] Alpha releases use an alpha tag, for example `0.1.0-alpha.0`.

## 5. Documentation

Checklist:

* [ ] `README.md` explains alpha status.
* [ ] `README.md` includes install / build / test / smoke instructions.
* [ ] `README.md` shows the main CLI flow.
* [ ] `README.md` clearly says this is not production-ready.
* [ ] `SECURITY.md` exists.
* [ ] `SECURITY.md` warns against committing `.besa/`.
* [ ] `docs/THREAT_MODEL.md` exists.
* [ ] `CHANGELOG.md` exists.
* [ ] `docs/RELEASE_CHECKLIST.md` exists.

## 6. Final verification

Run:

```powershell
npx tsc --noEmit
npm run build
npm test
npm run smoke
npm pack --dry-run
git status --short
```

Checklist:

* [ ] TypeScript check passes.
* [ ] Build passes.
* [ ] Tests pass.
* [ ] Smoke test passes.
* [ ] Package dry run looks clean.
* [ ] Git status only shows intentional release files.

## 7. Stage review

Before committing, run:

```powershell
git add .github/workflows/ci.yml
git add .npmignore
git add package.json package-lock.json
git add src/manifest.ts src/tests/besa.test.ts
git add scripts/smoke.mjs
git add SECURITY.md CHANGELOG.md
git add docs/THREAT_MODEL.md docs/RELEASE_CHECKLIST.md
git diff --cached --name-only
git diff --cached --stat
```

Checklist:

* [ ] Only intentional files are staged.
* [ ] No generated secrets are staged.
* [ ] No `.besa/` files are staged.
* [ ] No `dist/` files are staged.
* [ ] No `node_modules/` files are staged.
* [ ] No `.claude/` files are staged.
* [ ] No temporary files are staged.

## 8. Tag and publish

Only after every previous gate is green:

```powershell
git commit -m "Harden Besa alpha release"
git tag v0.1.0-alpha.0
git push origin main
git push origin v0.1.0-alpha.0
```

Optional npm publish step:

```powershell
npm publish --access public --tag alpha
```

Checklist:

* [ ] Release commit created.
* [ ] Tag created.
* [ ] Main branch pushed.
* [ ] Tag pushed.
* [ ] npm publish completed only if package contents were verified.
* [ ] GitHub release created only after the final package and docs are verified.

## Alpha warning

Do not publish or announce this alpha unless:

* [ ] all quality gates are green
* [ ] package contents are clean
* [ ] no secrets are staged
* [ ] `SECURITY.md` is complete
* [ ] `README.md` clearly says this is an alpha
* [ ] the repository has a real security contact or GitHub private vulnerability reporting enabled