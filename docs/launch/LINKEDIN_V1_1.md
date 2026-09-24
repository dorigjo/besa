# LinkedIn launch draft: Besa v1.1

Giving an AI agent valid credentials does not mean every action it can
technically perform should be allowed.

Identity and transport authorization can answer who connected and which system
or tool they may reach. A consequence-bearing service still needs to decide:

> May this exact operation execute on this exact resource, under these
> constraints, before this expiry?

That is the narrow boundary I built Besa to explore.

```text
Agent:      agent:deploy-agent
AWS access: accepted
Contract:   DEPLOY commit abc123 to staging
Request:    DELETE production-db

Besa:       DENY ACTION_NOT_GRANTED
Executor:   not called
```

Besa is an MIT-licensed TypeScript protocol, CLI, SDK, and self-hosted verifier.
It defines a canonical Action Envelope, a signed exact-action Capability, and
signed Evidence linking an admitted action to the supplied result. The runtime
can enforce narrowing delegation and consume replay state before execution.

It sits here:

```text
Agent -> IAM / OAuth / MCP Auth -> Besa -> consequential tool -> evidence
```

It does not replace IAM, OAuth, MCP authentication, cloud-native authorization,
observability, a payment rail, or an execution sandbox. It has not received an
independent third-party security audit, and signed evidence does not by itself
prove that an external real-world side effect occurred.

The local demo runs the real Ed25519 deny/allow and evidence-verification path:

```bash
npm install @dorigjo/besa
npx besa demo
```

Source, specification, threat model, conformance vectors, and benchmarks:
https://github.com/dorigjo/besa

I would value technical criticism from people building agent tools, MCP servers,
cloud automation, or authorization systems: is a provider-neutral exact-action
artifact useful at your execution boundary, and where does this model break?

## Publishing notes

- Attach the terminal GIF or architecture image, not generic AI imagery.
- Keep the no-audit and evidence-limit statements.
- Do not add customer, partnership, funding, market-size, or traction claims.
- Respond with implementation detail rather than moving discussion to DMs.
