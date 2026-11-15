# Cross-Operator Proof

Run after `npm run build`:

```sh
node examples/cross-operator-proof.mjs
```

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
