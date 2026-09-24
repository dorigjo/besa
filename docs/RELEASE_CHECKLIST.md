# Release Checklist

Release gate for the exact version in `package.json`. Run from a clean clone or
fresh worktree with the committed lockfile.

## Code and protocol gates

```powershell
npm ci
npx tsc --noEmit
npm run build
npm test
npm run conformance
npm run demo
npm run benchmark
npm run test:examples
npm run test:docs
npm run smoke
npm run smoke:server
```

- [ ] Node 20, 22, and 24 CI jobs pass.
- [ ] Full tests include strict schemas, malformed keys, mutation, expiry,
      replay, delegation narrowing, runtime failures, and HTTP abuse cases.
- [ ] Frozen v1.0 plus v1.1 positive and negative conformance vectors pass.
- [ ] The demo denies the mismatched production action without calling its
      executor, then signs and verifies the allowed path and evidence.
- [ ] Benchmark output records environment, method, median, p95, and p99.
- [ ] Compile-checked examples use only the public SDK.
- [ ] The canonical v1 Receipt remains identical on every public surface.

## Hosted Verifier and container

- [ ] `smoke:server` covers keyless `--action-trust`, signed action admission,
      bearer authentication, capability verification, rate limiting, metrics,
      health/readiness, and loopback default binding.
- [ ] Admission routes cannot start with an invalid key, policy, token, issuer,
      or trust store.
- [ ] Docker image builds from the pinned Node base image.
- [ ] Image config runs as `node`; a read-only container with only `/tmp` as a
      constrained tmpfs returns healthy and ready.
- [ ] Admission deployment instructions keep keys/config read-only and secrets
      outside image layers.

CI runs the container checks. If Docker is available locally, reproduce them
before release rather than relying only on CI.

## Package and upgrade

```powershell
npm run test:package
npm run verify:package-surface
npm pack --dry-run
npm publish --dry-run --access public
```

- [ ] Packed SDK and `besa` CLI install in an empty project.
- [ ] `npx besa demo` succeeds from that clean tarball installation.
- [ ] Upgrade smoke installs the immutable previous Git version, then the local
      v1.1.1 tarball, and confirms legacy plus additive exports.
- [ ] Required Docker, documentation, examples, launch notes, and conformance
      files are present.
- [ ] `src/`, `dist/tests/`, `.besa/`, private keys, operational trust stores,
      receipts, evidence logs, local projects, and tarballs are absent.
- [ ] Dry-run names exactly `@dorigjo/besa@1.1.1` and reports no bin warning.

## Supply chain

```powershell
npm audit --omit=dev
npm run --silent sbom > "$env:TEMP\besa-sbom.cdx.json"
node -e "const s=require(process.env.TEMP + '/besa-sbom.cdx.json'); if(s.bomFormat!=='CycloneDX') process.exit(1)"
```

- [ ] Production dependency audit has no known vulnerabilities.
- [ ] CycloneDX SBOM parses and identifies the release package/version.
- [ ] GitHub Actions are pinned to full commit SHAs and have read-only default
      permissions.
- [ ] No provenance, signing, audit, or compliance claim is made unless the
      corresponding external evidence actually exists.

## Repository and documentation

```powershell
git diff --check
git status --short
git diff --cached --name-only
```

- [ ] `package.json` and `package-lock.json` use the same version.
- [ ] Changelog and release notes are dated and match shipped behavior.
- [ ] Architecture, security, threat model, runtime, gateway, evidence, and
      Hosted Verifier docs state guarantees and non-guarantees consistently.
- [ ] No independent security audit or public Besa-operated verifier is implied.
- [ ] No `.besa/`, key, token, generated artifact, or unrelated local directory
      is staged.
- [ ] Four review passes are complete: protocol/crypto, runtime/MCP/replay,
      Hosted Verifier/deployment, and backward compatibility/release surface.

## Publish

Only after every gate is green and npm authentication is confirmed:

```powershell
npm whoami
git commit -m "Release v1.1.1"
git push origin main
npm publish --access public
npm view @dorigjo/besa@1.1.1 version dist.integrity dist.shasum
```

Create and push a Git tag or GitHub Release only as a separate, explicitly
approved release action. Never infer successful publication from a dry-run;
verify the immutable registry version after the real publish.
