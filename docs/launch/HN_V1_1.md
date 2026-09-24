# Show HN launch draft: Besa v1.1

## Recommended title

**Show HN: Besa – exact-action admission for consequential AI-agent tools**

Alternatives:

- Show HN: Besa – signed authorization for an AI agent's exact action
- Show HN: Besa – cryptographic admission before privileged agent actions

Use the recommended title first. Do not A/B post multiple submissions.

## Post body

AI agents increasingly reach tools that deploy code, mutate infrastructure, or
move money. Authentication tells the service who connected, but a valid identity
does not by itself answer whether this exact operation on this exact resource,
under these constraints, may execute.

I built Besa, an MIT-licensed TypeScript protocol, CLI, and SDK for that boundary.
It represents a proposed action canonically, verifies a signed allow/deny
capability immediately before the handler, consumes replay state, and records
signed evidence linking the admitted action to the supplied result.

The smallest example is an agent with valid AWS credentials whose contract
allows `DEPLOY staging`, asking to `DELETE production-db`. Besa returns
`ACTION_NOT_GRANTED` and the executor is not called.

Try the real local path:

```bash
npm install @dorigjo/besa
npx besa demo
```

Repository: https://github.com/dorigjo/besa

Besa does not replace IAM, OAuth, MCP auth, cloud-native policy, or observability.
There is no hosted Besa service and no independent third-party security audit.
I would value criticism of the trust model, artifact split, replay boundary, and
whether a provider-neutral exact-action contract is useful outside one stack.

## Preflight

Do not post until all are true:

- The npm version returned by `npm view @dorigjo/besa version` contains `besa demo`.
- A clean directory can install that exact version and run the demo.
- GitHub's latest release documents v1.1 rather than v0.1.0.
- CI, package smoke, conformance, and the security links are green.
- The founder can remain available to answer technical questions that day.

The [Show HN guidelines](https://news.ycombinator.com/showhn.html) prohibit
upvote solicitation and expect something people can run. Do not ask friends to
upvote, seed comments, or repeat-submit the project.
