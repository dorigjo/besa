# I built an open protocol for admitting exact AI-agent actions before execution

An authenticated agent can still be over-authorized. Knowing that an agent may
call a deployment, database, or payment tool does not answer whether it may
perform this exact action on this exact resource under these exact constraints.

Besa v1.1 is an open-source TypeScript implementation of that narrower
boundary:

```text
existing identity/authentication
  -> canonical action
  -> deterministic policy + optional delegation
  -> signed ALLOW/DENY capability
  -> guarded handler
  -> signed linked evidence
```

The capability binds principal, agent, tool, operation, resource, request hash,
constraints, expiry, nonce, policy, and optional delegation-chain hash. Changing
staging to production or EUR 100 to EUR 10,000 changes the action identity and
invalidates the authorization link.

v1.1 includes an SDK wrapper, MCP adapter, self-hosted HTTP verifier/admission
service, Dockerfile, strict policy example, public conformance vectors,
fuzz-style mutation tests, benchmarks, and four runnable demos.

```bash
git clone https://github.com/dorigjo/besa
cd besa
npm install
npm run demo
npm run conformance
```

Important limits: Besa is not IAM, an MCP gateway, a payment rail, or proof that
an external side effect really happened. Distributed one-time use requires a
customer-owned atomic replay store. There has not been an independent security
audit. The threat model and audit scope are in the repo because those are areas
where I want serious review rather than trust-by-marketing.

Repository: https://github.com/dorigjo/besa
npm: https://www.npmjs.com/package/@dorigjo/besa

Feedback on the protocol fields, delegation narrowing, replay model, or hosted
verifier deployment boundary would be useful.
