# Vendor-neutral admission and evidence contract

Besa admits and proves signed statements. The host/runtime enforces access to
the protected side effect. Identity, sandboxing, egress, credentials, generic
gateway routing and observability are not Besa product surfaces.

## Actual trust object

The existing v1.2 artifacts already express the following chain without a new
core schema or runtime dependency:

```text
verified external identity -> signed normalized authority and delegation
  -> exact request + policy digest -> signed admission receipt
  -> independent executor verification + receipt commit + atomic replay consume
  -> current authority/policy revalidation -> protected effect
  -> signed linked execution evidence -> offline verification
```

| Security fact | Existing binding | Boundary |
|---|---|---|
| Principal, agent, authority issuer | Action Envelope, ExternalAuthority, receipt | Host authenticates caller; normalizer verifies upstream claims. |
| Delegation provenance | Signed narrowing chain, authority/capability/receipt chain digest | Root trust and current revocation must be supplied; no fabricated identity from a chain alone. |
| Tool, operation, resource, scopes, risk | Action Envelope hash, signed capability and receipt | Trusted mapper derives real tool semantics. |
| Exact parameters | requestHash, full pre-execution request digest | Executor uses the detached verified parameters, not an ambient replacement. |
| Execution context | contextHash and request digest | Arbitrary context is data; the host checks expected values. |
| Policy ID/version/hash | Request reference and signed receipt, verified actual policy | ID alone does not bind evaluated rules; no remote policy fallback. |
| Executor | Signed context.executorId and withBesaExecutor host check | Alternate credential/tool paths remain the host's responsibility. |
| Runtime/enforcer | May be pinned in the existing signed context | No automatic runtime authentication/attestation; an adapter must check the expected runtime identity. |
| Decision, reason, nonce, validity | Signed receipt/capability, execution-time checks | Stateless verification does not consume replay; audit never authorizes. |
| Authority/assertion/request digests | ExternalAuthority and admission receipt | Assertion digest does not independently prove the original IdP signature. |
| Result/evidence linkage | ActionEvidence resultHash, capabilityHash, receiptHash, recorder signature | Recorder trust, not magical proof of a physical effect. |

Delegations narrow operations/resources/scopes, exact/maximum constraints and
validity. Budget/risk/executor restrictions must be explicitly represented by
supported constraints and checked by the integration; there is no implicit
universal budget or executor-set delegation policy. Existing signed schemas,
hash domains and golden vectors remain unchanged.

## OpenShell evidence and substitution risk

Conclusion: **PARTIALLY SUBSTITUTED**, not fully substituted and not a claim of
an unbundleable moat. Runtime controls and basic policy/parameter inspection
are commodities for Besa. Signed portable authorization provenance remains
complementary in the inspected contracts.

Primary source checked at OpenShell
[`71c3cd957abef062eb7f37010056717cd49f2ed3`](https://github.com/NVIDIA/OpenShell/tree/71c3cd957abef062eb7f37010056717cd49f2ed3):

- [L7 policy evaluation](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/crates/openshell-supervisor-network/src/l7/relay.rs#L3228)
  passes MCP tool/parameters, destination, process and request information into
  `data.openshell.sandbox.allow_request`. This is real inspection overlap, not
  something only Besa can do.
- [Middleware request/decision protocol](https://github.com/NVIDIA/OpenShell/blob/71c3cd957abef062eb7f37010056717cd49f2ed3/proto/supervisor_middleware.proto#L583)
  identifies request, sandbox, process and HTTP destination. Sandbox/workspace
  display names are not authorization identity. The inspected protocol does
  not expose Besa-equivalent signed delegated exact-action admissions.
- [Middleware configuration](https://docs.nvidia.com/openshell/latest/extensibility/supervisor-middleware/configure)
  defines authenticated/TLS extension operation and fail-closed/fail-open policy.
  Middleware can mutate traffic. Required admission cannot use fail-open or
  uncovered inspection paths; final tool parameters must still match admission.
- [OCSF export](https://docs.nvidia.com/openshell/dev/observability/ocsf-json-export)
  provides portable runtime logs. Portability of JSON logs alone is not a
  per-action signature, delegation proof or proof of complete event coverage.

| Layer | Besa | OpenShell | Decision |
|---|---|---|---|
| Sandbox/process/filesystem/network/credentials | Does not implement | Runtime implementation | Do not compete. |
| ALLOW/DENY and parameter inspection | Deterministic action policy | L7 policy and middleware | Strong overlap; not an exclusive moat. |
| Signed exact delegated admission | Existing portable artifacts and verifier | Equivalent artifact not established in inspected protocol | Complement; future bundling risk remains. |
| Offline authorization/evidence verification | Pinned public trust + original inputs | OCSF export alone is not equivalent | Besa's current contract advantage, not adoption proof. |
| Replay | External atomic ReplayStore at exact executor | Request IDs/log correlation are different | Compose; neither implies exactly-once downstream effects. |
| Conformance/vendor neutrality | Frozen public artifact/decoder vectors | Vendor runtime extension contract | Useful interoperability surface; not an adopted standard. |
| Completeness/hardware attestation | Not provided | No equivalent per-action proof established by this audit | Do not claim victory over unverified Sentry capabilities. |

## Smallest external-enforcer integration

Use existing PreExecutionRequest/Receipt, withBesaExecutor and ActionEvidence.
Do not turn unsigned ALLOW logs into authorization. A forged runtime event must
never bypass independently verified authority, policy and admission.

1. Authenticate the runtime/host separately. Map principal/agent from verified
   claims and pin executor/runtime identity through trusted configuration.
2. Capture the final tool action/parameters and any required runtime-policy
   identity/digest in the signed request context before admission.
3. Require Besa admission and runtime permission. Neither replaces the other.
   The final privileged executor verifies the receipt against its actual call
   after all middleware transformations, commits it and consumes replay state.
4. Bind runtime observations as application-owned JSON in the existing signed
   execution result. Preserve correlation/action/policy digests and producer
   evidence where available; reject missing/conflicting information rather
   than claiming trusted runtime evidence from an uncorrelated log.
5. Offline verification checks signed links and recorder trust. It does not
   invent an OpenShell signature, upstream revocation feed or observed effect.

A small application-owned runtime observation can include runtime ID/version,
decision/time, effective policy reference, action digest, executor and evidence
digest. This is not a new core artifact, public parser or executable capability.
Its truth requires a trusted observer and validated producer/transport. Unknown
versions or unavailable verification must block a required integration.

OpenShell's middleware contract is evolving. No adapter, live compatibility,
outage coverage or GA interoperability is claimed here. A first adapter requires
a pinned supported protocol, real final-tool tests, fail-closed configuration
and proof that alternate routes cannot bypass admission. OpenShell/Docker were
not available locally in this audit. A separate Rust verifier is deferred:
the non-JCS ECMAScript contract and new decoder vectors warrant independent
review, but a second maintained runtime is not justified before external use.

Microsoft/Entra, Okta/EMA, MCP gateways and custom runtimes can supply verified
claims to existing authority normalizers and consume the same receipt at their
executor. Besa does not require platform replacement or vendor-specific core
fields. Those integrations still need their own identity/semantics/replay tests;
no vendor certification is implied.

## Compatibility, operations and adoption gate

Use parseArtifactJson at every untrusted JSON boundary before object verification.
The decoder vectors and SPEC define exact Unicode and decimal semantics; input
that another parser already collapsed cannot be retroactively made unambiguous.
No new cryptography, database, telemetry, dashboard or hosted dependency is added.
Offline receipt verification remains stateless; one-use execution still needs
deployment-owned atomic state behind ReplayStore.

The first external proof target is filesystem-mcp: protect parent mkdir plus a
single accepted write, exposing no alternate mutation routes. A local prototype,
clone, download or founder-owned example is not external adoption. At this audit
there is no confirmed independent maintainer integration. Major new adapters or
runtime surfaces remain on HOLD until external integration evidence earns them.
