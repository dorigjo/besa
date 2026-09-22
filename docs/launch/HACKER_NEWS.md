# Show HN: Besa - signed admission and evidence for exact AI-agent actions

Authentication can tell a service which agent is calling. It usually does not
prove that an exact action such as `DELETE production-db`, `deploy commit
abc123`, or `send EUR 100 to merchant-123` was authorized under exact
constraints immediately before execution.

I built Besa as a small TypeScript protocol and implementation for that control
point. v1.1 represents an action canonically, applies deterministic policy and
optional signed delegation, issues a signed allow/deny capability, guards the
handler, and records signed evidence linked to the supplied result.

The repository includes:

- SDK runtime wrappers and an MCP adapter
- a self-hosted HTTP verifier/admission service with Docker support
- immutable positive/negative conformance vectors
- fuzz-style mutation tests and Node 20/22/24 CI
- a reproducible benchmark command
- demos for deployment, destructive database access, a mock external payment
  rail, and an authenticated-but-denied privileged MCP call

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm install
npm run demo
npm run conformance
```

This is not IAM, a payment processor, an MCP gateway, a dashboard, or a claim
that signed evidence proves an outside-world effect. Global replay prevention
requires a customer-owned atomic store. There has been no independent security
audit yet; the repo includes a threat model, audit scope, specification, and
public vectors to make criticism concrete.

Repository: https://github.com/dorigjo/besa
npm: https://www.npmjs.com/package/@dorigjo/besa

I would particularly value review of canonicalization, delegation narrowing,
replay semantics, action/evidence binding, and the hosted verifier's trust
boundary.
