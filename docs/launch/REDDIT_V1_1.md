# Reddit launch draft: Besa v1.1

Post in one relevant community at a time. Read its current rules first and
rewrite the opening for that community; do not paste the same submission across
multiple subreddits.

## Suggested title

**I built a signed exact-action admission layer for consequential AI-agent tool calls**

## Technical post

Disclosure: I am the author.

I have been working on a narrow authorization problem in agent systems:

```text
authenticated identity != authorization for this exact action
```

For example, an agent can have valid AWS credentials and access to a cloud tool,
while its approved contract permits only `DEPLOY staging`. If it requests
`DELETE production-db`, the protected handler should never run.

Besa is an MIT-licensed TypeScript protocol/SDK for that boundary. It uses:

- a canonical Action Envelope for principal, agent, operation, resource,
  constraints, expiry, nonce, and request hash;
- a signed Action Capability for the exact allow/deny decision;
- optional narrowing delegation and enforced replay storage;
- signed Action Evidence linking the admitted action to the supplied result.

The runnable demo generates real Ed25519 signatures, denies the mismatched
action, proves the executor was not called, allows the matching action, and
verifies the resulting evidence:

```bash
npm install @dorigjo/besa
npx besa demo
```

Code and threat model: https://github.com/dorigjo/besa

This is not IAM, MCP authentication, a cloud policy engine, or observability.
Those remain upstream/adjacent controls. Besa is also not independently audited,
and its signed evidence does not independently prove an external side effect.

I am looking for technical criticism: Is the Action Envelope / Capability /
Evidence split useful across trust boundaries, or would you keep this entirely
inside the native authorization system? Where does the model fail in a real
agent or MCP deployment?

## Community-specific emphasis

### Security engineering

Lead with key separation, trust anchors, replay, recorder independence, threat
model, and why cryptographic validity is not trust. Ask reviewers to challenge
the capability/evidence semantics.

### MCP engineering

Lead with `MCP Auth -> Besa -> tool handler`, request-hash binding, and the
typed `withBesaMcp` adapter. State that MCP can implement detailed authorization
and ask whether a portable signed invocation contract adds value.

### TypeScript / open source

Lead with the small dependency surface, ESM/Node 20 baseline, strict types,
frozen conformance vectors, and the 10–30-line adapters. Ask about API friction,
not business potential.

## Posting rules

- Confirm that self-authored project links are allowed before posting.
- Disclose authorship in the first paragraph.
- Do not mass-post, cross-post identical text, use alternate accounts, or ask
  for votes.
- Answer questions in the thread instead of sending unsolicited messages.
- Wait for measured results from one community before considering another.
- Remove any sentence that cannot be reproduced from the repository.

See [Reddit's spam policy](https://support.reddithelp.com/hc/en-us/articles/360043504051-Spam).
