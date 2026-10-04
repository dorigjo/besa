## OpenShell boundary audit (2026-10-04)

> Historical research snapshot. This audit was originally performed against
> Besa 1.2.0 before the v1.3.0 JSON-boundary hardening. Product and security
> conclusions must be revalidated against current `main` before an OpenShell
> adapter is shipped.

**Conclusion: B. PARTIALLY SUBSTITUTED. Integration release: HOLD.**
OpenShell enforces. Besa proves the assertions made by its trusted authorities
and recorders. Neither a Besa signature nor an unsigned runtime log independently
proves that a downstream side effect happened or that every event was recorded.

### Evidence and scope

This audit inspected Besa commit `4d83fb177ebb0ffe5f3eb494278243946196c4f9`
(package version `1.2.0`) and OpenShell source at
[`71c3cd957abef062eb7f37010056717cd49f2ed3`](https://github.com/NVIDIA/OpenShell/tree/71c3cd957abef062eb7f37010056717cd49f2ed3).
OpenShell's latest release inspected was `v0.1.2`; its middleware protobuf is
identical to the inspected source. That does not establish live compatibility
of a Besa adapter. No adapter or live OpenShell test was added. Repository
`AGENTS.md` and `CLAUDE.md` match; `.claude/skills` is absent.

Primary implementation evidence:

- [Request enforcement and OCSF emission](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/crates/openshell-supervisor-network/src/l7/relay.rs):
  `evaluate_l7_request_once` evaluates `data.openshell.sandbox.allow_request`
  with destination, process, method, path, query, GraphQL and JSON-RPC inputs.
  `jsonrpc_policy_input` includes tool and parameters. A middleware denial
  returns before request forwarding. Audit-mode policy denials can be logged
  with OCSF `Allowed`; an event's action alone is not an authorization proof.
- [Middleware implementation](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/crates/openshell-supervisor-network/src/l7/middleware.rs):
  stages can change body and headers; body-aware policy is re-evaluated.
  `middleware_events` can emit an allowed event for a failed-open stage.
  These inspected event builders do not sign exact request bodies or bind
  delegated principal authority and the effective policy digest.
- [Middleware protocol](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/proto/supervisor_middleware.proto)
  exposes request ID, sandbox ID, process, target, headers and body at
  `PRE_CREDENTIALS`. It is not a signed admission artifact.
  [Middleware documentation](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/docs/extensibility/supervisor-middleware/index.mdx)
  explicitly calls the API evolving and excludes `tls: skip` inspection.
- [Extension authentication](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/docs/extensibility/overview.mdx)
  supports pinned gateway EdDSA JWTs over TLS, with issuer, audience, caller kind
  and sandbox checks. A reusable transport token is not a per-action signature
  or a principal's delegation. Insecure development transport is insufficient.
- [OCSF export](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/docs/observability/ocsf-json-export.mdx)
  provides portable JSON logs with bounded rotation; availability outside the
  control plane is not cryptographic authenticity or interval completeness.
  [Issue 2745](https://github.com/NVIDIA/OpenShell/issues/2745) discusses signed
  governance exports and sequence coverage. This is community design evidence,
  not proof of a shipped implementation or an NVIDIA roadmap commitment.
- [NVIDIA's Sentry announcement](https://investor.nvidia.com/news/press-release-details/2026/NVIDIA-Launches-Open-Agent-Safety-Platform-to-Secure-Agents-From-Testing-to-Deployment/default.aspx)
  describes hardware-separated enforcement, identity and attested telemetry.
  This audit did not establish a public per-action attestation/verifier contract.
  Sentry equivalence is therefore unverified, not ruled out.

### Gap matrix

OpenShell entries describe the inspected paths, not every possible extension.
Risk includes future bundling; absence in these paths is not a permanent moat.

| Capability | Besa 1.2.0 | OpenShell | Overlap | Complement | Substitution risk |
|---|---|---|---|---|---|
| Sandbox, egress, credentials | Host responsibility | Runtime-owned | No Besa product here | Compose, do not rebuild | High |
| Allow/deny policy | Deterministic action policy | OPA and middleware | Strong | Besa signs the decision | High |
| Exact parameters | Canonical request/action hashes | MCP params and middleware body inspection | Strong inspection overlap | Portable signed binding | High for inspection |
| Canonicalization | Frozen versioned JSON/domain rules | No equivalent signed-action format established | Partial JSON semantics | Existing conformance vectors | Medium |
| Principal/agent identity | Signed normalized authority; trusted host caller | Sandbox/process and gateway token identity | Partial | Explicit trusted identity mapping | Medium/high |
| Delegation provenance | Signed, narrowing chains | No equivalent chain in inspected event contract | Not established | Chain bound into admission | Medium |
| Executor binding | Signed context plus configured executor check | Runtime/sandbox target | Partial | Final tool independently checks receipt | Medium |
| Nonce and replay | Signed nonce; atomic external consume | Request IDs and log cursors | Different semantics | One-use executor boundary | Medium |
| Expiry | Checked before execution; audit never authorizes | Transport token expiry | Partial | Action-specific expiry | Medium |
| Policy identity/version | Admission binds full Besa policy digest | Policy names and revision control | Partial | Bind actual evaluated bytes, not labels | Medium/high |
| Signed admission | Ed25519 receipt and capability | No equivalent artifact in inspected events | Not established | Portable decision authority | Medium/high |
| Execution result | Signed result hash from trusted recorder | Runtime/HTTP observations | Partial | Link result and admission | Medium/high |
| Offline verification | Public artifacts, inputs and pinned trust | Exported OCSF JSON, not equivalent signature proof | Partial portability | Independent signature/link checking | Medium/high |
| Completeness/witness | Not implemented; append-only is not WORM | Retention/cursors; export proposal | Neither proves all effects | No present moat claim | High |

### Kill-test answers and smallest integration boundary

A: Do not build sandboxing, generic gateways, credential brokering, egress
policy, basic allowlists or general runtime audit collection as Besa products.
B: Exact delegated admission, execution binding and portable signed evidence
remain orthogonal in the inspected implementations, not intrinsically unbundleable.
C: Besa can consume a runtime observation as application-owned result data;
an unsigned OCSF `ALLOW` cannot safely become execution authority.
D: Existing `verifyPreExecutionAdmission` and `verifyActionEvidence` work offline
with the original inputs and pinned trust. They do not verify an OpenShell
producer signature that was never supplied.
E: Yes for trusted, signed authorization provenance and tamper-evident linkage;
no for proving an unsigned event's origin, log completeness or physical outcome.
Re-signing arbitrary logs alone fails this kill test.

The smallest credible integration reuses `PreExecutionRequestV1`,
`PreExecutionAdmissionReceiptV1`, `withBesaExecutor` and `ActionEvidenceV1`:

```text
authenticated principal/agent + verified delegation
  -> Besa exact-action admission
  -> OpenShell policy and required fail-closed middleware
  -> final protected tool verifies the actual invocation and signed receipt
  -> durable receipt commit + atomic nonce consume + revalidation
  -> exact side effect -> signed, linked result evidence
```

An adapter must authenticate the runtime source, map identities from trusted
configuration, pin a supported protocol, and reject missing action or policy
bindings rather than inventing them from a redacted log. It must preserve the
original normalized request and recheck the final invocation after all middleware
mutations. No other route or production credential may bypass the protected tool.
Transport identity alone cannot supply missing principal delegation.

No new core `RuntimeDecision` artifact is justified yet: runtime-specific
observations can be bound by existing result hashing, but their truth remains a
recorder trust claim. Denial evidence and successful execution evidence must not
be conflated. An unknown runtime/version, unavailable verifier, uncorrelated
event or unverifiable source must never produce executable ALLOW. Any future
adapter should remain experimental until its transport and end-to-end path are
tested; no NVIDIA dependency belongs in core exports.

### Verification and release limits

On Windows / Node `24.20.0`, before documentation changes: `npm test` passed
320/320 with zero failures or skips; `npm run conformance` passed 28/28 with
zero failures or skips. Build, typecheck, example typecheck, documentation
checks, demos, CLI/server smoke and package installation passed. Package surface
validation found 120 files, 55 required paths and no forbidden paths.
Production dependency audit found zero vulnerabilities using Node's system CA
store after the default CA lookup failed; TLS verification was not disabled.
Node 20/22 and live OpenShell/Docker were not executed locally.

HOLD applies to a new OpenShell integration, not a claim that regression tests
failed. OpenShell and Docker executables are unavailable here, so there is no
live conformance, outage, identity, post-mutation or bypass-path proof. The
adversarial audit also found duplicate-member acceptance in the then-existing HTTP JSON boundary; signature bypass was not demonstrated. That parser boundary was subsequently hardened and regression-tested in Besa v1.3.0. Any OpenShell adapter must still be revalidated against the current boundary behavior.
Some older trust/replay documents describe pre-v1.2 behavior; use current
implementation and SPEC rather than treating those historical claims as current.

This documentation-only audit changes no public API, artifact bytes, signature
domain, CLI, hosted route, package manifest or replay semantics. No migration is
needed. Besa adds no runtime, database, telemetry, infrastructure or operational
dependency here. Existing offline verification stays stateless; one-use execution
still needs deployment-owned replay state and cannot promise universal exactly-once
external effects. No OpenShell adapter, new conformance vectors or release is
claimed. Before shipping an integration, prove the stated flow on pinned OpenShell
with a real protected write, all zero-call rejection cases and a clean restart.
