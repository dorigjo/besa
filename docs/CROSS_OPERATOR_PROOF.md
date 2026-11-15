# Cross-Operator Proof

Run from the repository after `npm run build`:

```sh
node examples/cross-operator-proof.mjs
```

To exercise the packaged clean-room path, run `npm pack` from the repository,
create a new consumer directory, and install the resulting tarball there:

```sh
work=$(mktemp -d)
mkdir -p "$work/pack" "$work/consumer"
npm pack --pack-destination "$work/pack"
cd "$work/consumer"
npm init -y
npm install "$work/pack/dorigjo-besa-1.4.0.tgz"
node node_modules/@dorigjo/besa/examples/cross-operator-proof.mjs
```

Replace the tarball path with the exact file emitted by `npm pack` on your
platform. This flow uses the package contents rather than repository-local
imports. The 1.4.0 tarball is a local candidate until its release is approved.

The command starts three separate local Node processes and exchanges bounded
JSON artifacts through a fresh temporary directory:

1. Operator A creates a signed external-authority assertion and exact-action
   ALLOW admission receipt.
2. Operator B verifies the receipt at the protected executor, writes one file
   inside that temporary directory, and signs evidence for the supplied result.
   It then rejects a changed parameter and a replay; the handler call count
   remains one.
3. Operator C runs the BESA verifiers in a separate process using only public
   trust material, then emits a machine-readable verification report.

The package smoke test runs this example from a fresh installed-package
directory so package exports and example imports are exercised together.

Pass `--keep` to retain the proof bundle path printed by the command. The bundle
contains public trust data and signed artifacts only; it contains no private
keys. Do not treat the included demonstration trust configuration as an
independent endorsement of its test keys.

This is a reproducible local reference flow, not three independent customers,
operators, or production services. The launcher models host-authenticated
caller context with fixed test configuration; it does not implement network
authentication. Operator B uses an in-memory replay store, which is atomic only
within that process and does not establish restart-safe or multi-host replay
prevention. The file write is a temporary local effect. Signed execution
evidence binds the recorder-supplied result but does not prove an external
business system performed that effect. No network calls are made.

The artifacts retain the existing BESA admission and evidence schemas. The
example composes `admitPreExecution`, `withBesaExecutor`,
`verifyPreExecutionAdmission`, and `verifyActionEvidence`; it introduces no new
signature format or cryptographic primitive.
