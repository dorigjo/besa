# BESA Dashboard

The Dashboard is a local verification interface over the existing BESA SDK.
It is not a hosted control plane and does not create or authorize actions.

## Run

```bash
npx besa dashboard
```

The server binds to `127.0.0.1` and defaults to port `8790`. Use
`npx besa dashboard --port 9000` to choose another port. Open the printed
loopback URL. The server rejects non-loopback `Host` values, serves only the
bundled static files and fixed API routes, and sets a restrictive content
security policy. It has no authentication because it is intended for the local
operator only; do not expose or reverse-proxy it to a network.

## Verify artifacts

The signed sample is the neutral-domain v1 conformance fixture. Its embedded
trust store demonstrates verification mechanics only; it is not an independent
endorsement of the test key. Import a JSON bundle to verify artifacts against
the supplied trust context. The server accepts the legacy manifest/receipt
bundle and the `besa-pre-execution-bundle-v1` format containing an admission
input, signed admission receipt, exact policy, audience and trust stores.

For a pre-execution bundle the verifier checks the signed admission, authority,
delegation when supplied, exact action and parameters, audience, policy digest,
expiry and current execution authorization using BESA's existing verifier.
Historical signature validity after expiry is not a permission to execute.
The result distinguishes admission from optional signed action evidence. A
signed admission does not prove that execution happened; action evidence binds
a recorder-supplied result but does not independently prove an external
real-world side effect.

The local simulator runs the repository's existing SDK demo with ephemeral
test keys and mock callbacks. It demonstrates one DENY and one ALLOW path; it
does not perform refunds, deployment, network access or real tool calls. Its
fixed demonstration clock is test data, not a live clock or freshness check.

## Data handling and limits

* Verification is performed locally; no telemetry or BESA service is used.
* Uploaded bytes are limited to 256 KiB and are not persisted by the server.
* Verification reports can omit raw parameters. Exporting the original bundle
  requires explicit confirmation because it may contain sensitive data.
* The supplied trust store is caller-provided context. A cryptographically
  valid signature is not trusted unless the verifier is configured with an
  authentic trust anchor and suitable key lifecycle information.
* The dashboard does not provide tenant isolation or multi-user access control.
  Keep it loopback-only and use separate operator-controlled environments.
* No admission or protected side effect is performed by the Dashboard itself.

## Development checks

`npm test` includes the local HTTP boundary, hostile input, signature and
request-tampering checks, pre-execution admission verification, and simulator
ALLOW/DENY handler-count assertions. `npm run verify:package-surface` and
`npm run test:package` check that the CLI and static assets are present in a
clean package installation.
