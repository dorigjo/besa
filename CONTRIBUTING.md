# Contributing to Besa

Besa is a small protocol implementation. Changes should strengthen exact
pre-action admission and post-action evidence, not expand the project into an
identity provider, dashboard, payment rail, or generic agent platform.

## Development setup

```bash
git clone https://github.com/dorigjo/besa.git
cd besa
npm ci
npm run demo
npm test
npm run conformance
npm run test:examples
npm run test:docs
npm run smoke
npm run smoke:server
npm run test:package
npm run verify:package-surface
npm audit --omit=dev
```

Use Node 20, 22, or 24. CI runs all three versions and also builds the
read-only container image.

The demo should deny the production database action without calling its
executor, allow the exact staging deployment, and verify signed evidence. If it
does not, include the full command, Node version, operating system, exit code,
and sanitized output in a bug report.

## Useful contributions

Besa is under a feature freeze while adoption is tested. Useful changes are:

- security and critical reliability fixes with regression tests;
- reproducible installation or integration blockers;
- documentation corrections tied to current behavior;
- negative tests, conformance coverage, and failure-case clarity;
- small MCP, HTTP, or agent-framework examples requested by real users.

Do not start a broad protocol feature or framework package without an issue
that establishes the concrete boundary and demand. The current integration
priorities are documented in
[docs/adoption/INTEGRATION_TARGETS.md](docs/adoption/INTEGRATION_TARGETS.md).

Look for real open issues carrying `good first issue` or `help wanted`. If none
exist, do not manufacture one for activity; open a focused issue describing a
reproducible defect or proposed documentation/integration improvement.

## Issue labels

Maintainers use these labels when the underlying work actually exists:

| Label | Meaning |
|---|---|
| `good first issue` | Narrow, confirmed work with context and acceptance criteria |
| `help wanted` | Confirmed work where external implementation or review is useful |
| `security` | Security behavior or hardening; vulnerabilities still follow private reporting |
| `protocol` | Versioned artifacts, canonicalization, signatures, trust, replay, or conformance |
| `documentation` | Incorrect, missing, or unclear technical documentation |
| `integration` | A concrete execution-boundary adapter or interoperability test |

## Protocol change rules

- Do not change a frozen v1.0 artifact, its signature domain, or canonical
  serialization. Add a new versioned artifact instead.
- Any new security artifact needs strict schema validation, bounded canonical
  JSON, an explicit signing or hashing domain, stable reason codes, positive
  and negative conformance vectors, tests, and specification text.
- Unknown security-sensitive fields must fail closed.
- A security fix requires a regression test and a changelog entry. Preserve
  protocol compatibility unless the vulnerability makes that unsafe.
- Keep policy deterministic. No callbacks, remote policy fetches, wildcard
  semantics, or model-generated authorization decisions belong in the core.

## Test expectations

Add focused tests for behavior and failure modes. For parser and crypto-boundary
changes, include malformed values, Unicode, accessors/prototypes when relevant,
and mutation tests. Run the commands above before opening a change.

`npm run benchmark` is a measurement harness, not a pass/fail performance
promise. Record the machine and methodology when comparing results.

## Documentation expectations

Documentation must match the code and state limitations plainly. Do not claim
that Besa provides compliance, authenticates agents, proves real-world side
effects, prevents global replay without external state, or has been
independently audited when it has not.

Examples must compile with `npm run test:examples`. Commands copied into docs
must run from the context they describe. Avoid placeholders that look like
working production configuration; name trust, key, replay, and evidence
dependencies explicitly.

## Security reports

Follow `SECURITY.md` for private vulnerability reporting. Avoid filing public
issues containing exploit details before maintainers have had an opportunity to
assess and remediate the issue.
