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
- [ ] Frozen v1.0, v1.1 and pre-execution v1 positive/negative vectors pass.
- [ ] Executor adversarial tests include identity/executor substitution, storage
      failure, late revocation, restart replay and separate-process concurrency.
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
      release tarball, and confirms legacy plus additive exports.
- [ ] Installed TypeScript definitions compile and the real protected publisher
      runs on Node versions supporting type stripping.
- [ ] Required Docker, documentation, examples, launch notes, and conformance
      files are present.
- [ ] `src/`, `dist/tests/`, `.besa/`, private keys, operational trust stores,
      receipts, evidence logs, local projects, and tarballs are absent.
- [ ] Dry-run names exactly the version in package.json and reports no bin warning.
- [ ] Private traction reports, .claude/, personal/ and n8n-nodes-besa/ are absent.

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
- [ ] Lint and Docker results are reported only if actually executed; this
      repository has no standalone lint script. Docker CI is a required gate.

## Publish

Only after every gate is green and npm authentication is confirmed:

```powershell
npm whoami
npm publish --access public
$version = node -p "require('./package.json').version"
npm view "@dorigjo/besa@$version" version dist.integrity dist.shasum
$env:BESA_REGISTRY_VERSION = $version
npm run test:package
Remove-Item Env:BESA_REGISTRY_VERSION
```

Commit owned release changes on a branch, open a PR, satisfy main's protected
Node 20/22/24 checks and the container job, and merge through the legitimate
protected path. Publish from a fresh clean checkout of the reviewed commit;
never force-push or bypass protections. A tag/GitHub release requires release
authorization and must identify that same tested commit.

Never infer publication from a dry-run. The registry-mode package smoke installs
the exact public version in a new temporary consumer, verifies exports/types,
receipt generation/verification, CLI, executor, package contents and upgrade.
Verify registry integrity and report unavailable authentication honestly.
