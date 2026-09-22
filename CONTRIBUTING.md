# Contributing to Besa

Besa is a small protocol implementation. Changes should strengthen exact
pre-action admission and post-action evidence, not expand the project into an
identity provider, dashboard, payment rail, or generic agent platform.

## Development setup

```bash
npm ci
npm run build
npm test
npm run conformance
npm run test:examples
npm run smoke
npm run smoke:server
npm run test:package
```

Use Node 20, 22, or 24. CI runs all three versions and also builds the
read-only container image.

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

## Security reports

Follow `SECURITY.md` for private vulnerability reporting. Avoid filing public
issues containing exploit details before maintainers have had an opportunity to
assess and remediate the issue.
