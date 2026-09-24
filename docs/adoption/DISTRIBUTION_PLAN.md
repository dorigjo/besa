# Besa distribution plan

Date: 2026-09-23

This plan optimizes for technically qualified developers and attributable
learning. It does not treat posting volume as progress.

## Channel ranking

Scores are relative (1 low, 5 high). Founder time includes preparation and the
need to answer follow-up questions.

| Rank | Channel | Developer quality | Reach | Conversion likelihood | Founder time | Decision |
|---:|---|---:|---:|---:|---:|---|
| 1 | GitHub + npm package surface | 5 | 3 | 5 | 2 | Fix before sending any traffic |
| 2 | Hacker News Show HN | 5 | 5 | 4 | 4 | Primary launch wave after clean-room demo |
| 3 | Technical article / Dev.to | 4 | 3 | 4 | 3 | Publish after HN questions reveal confusion |
| 4 | One or two relevant Reddit communities | 4 | 4 | 3 | 4 | Native technical posts only; check each community's rules |
| 5 | Security, AI-infra, and MCP newsletters | 5 | 3 | 4 | 3 | Targeted outreach with runnable evidence |
| 6 | MCP ecosystem listings | 5 | 3 | 4 | 2 | Submit only where an official, maintained listing exists |
| 7 | X and LinkedIn | 3 | 3 | 2 | 2 | Supporting evidence thread, not primary conversion channel |
| 8 | Product Hunt | 2 | 4 | 2 | 5 | Defer until the package demo and visual assets are live |
| 9 | Generic startup/directory farms | 1 | 1 | 1 | 3 | Do not submit |

Show HN requires something users can run and recommends minimizing barriers;
the installed-package demo is therefore a launch gate, not polish. See the
[official Show HN guidelines](https://news.ycombinator.com/showhn.html).

Reddit forbids repeated or unsolicited mass engagement and delegates community
fit to moderators. Use one native post at a time and read current local rules;
see [Reddit's spam policy](https://support.reddithelp.com/hc/en-us/articles/360043504051-Spam).

Product Hunt prioritizes live, usable products and high-craft presentation. It
is lower priority for a protocol repository until the try path and media are
complete; see its [featuring guidelines](https://help.producthunt.com/en/articles/9883485-product-hunt-featuring-guidelines).

## Virality stages

These are internal heuristics, not external certifications.

| Stage | Evidence |
|---|---|
| 1 | <100 npm downloads/week and <25 legitimate GitHub stars |
| 2 | 100–500 downloads/week and 25–100 stars |
| 3 | 500–1,000 downloads/week and 100–250 stars |
| 4 | 1,000+ downloads/week, 250–500+ stars, external contributors, and external integrations |
| 5 | Sustained multi-channel organic growth with independent explanations and integrations |

Stage 4+ is roughly “virality 8/10.” Besa is currently below Stage 1 evidence
thresholds. Repository optimization can improve readiness but cannot advance
the actual traction stage by itself.

## Launch gates

Do not begin external waves until all are true:

- The next npm patch contains a tested `besa demo` command.
- A clean temporary project can install the tarball and run the demo.
- CI, tests, conformance, docs, examples, package smoke, and package-surface
  checks pass.
- GitHub's latest release accurately describes the current implementation.
- README, npm metadata, and GitHub About use the same category sentence.
- Security limitations and the absence of an independent audit remain visible.
- The traction report records the pre-launch baseline.

## Fourteen-day measured sequence

### Day 1: package and GitHub truth

Run every release gate, inspect the tarball, publish the patch only after manual
approval, update the GitHub release, About description, topics, and homepage.
Record the starting npm/GitHub metrics.

### Day 2: clean-room time to value

Give the npm instructions to one technically capable person with no verbal
context. Record time to install, demo success, first question, and failure. Fix
only adoption blockers or correctness defects.

### Day 3: evidence capture

Record the terminal GIF and export the architecture image using the documented
recipe. Verify that every visible claim can be reproduced from the repository.

### Day 4: Show HN

Post one short Show HN submission linking directly to the repository. Lead with
the authentication-versus-exact-action boundary and ask for architectural and
security criticism. Do not ask anyone to upvote or comment.

### Days 5–6: answer and classify

Answer technical questions directly. Classify feedback as category confusion,
demo failure, integration friction, security objection, or out-of-scope feature
request. Fix only confirmed blockers. Do not launch elsewhere yet.

### Day 7: first measurement

Run the traction report. Compare GitHub referral traffic, demo failures, npm 7d
downloads, stars, issues, and any public integration. Preserve source timing;
do not interpret CI clone spikes as users.

### Day 8: technical article

Publish the article updated with the strongest real objection from HN. Explain
the trust boundary, protocol artifacts, demo, limits, and reproducible numbers.
Link to the repository, not a signup page.

### Day 9: one Reddit community

Choose one community where the post is on-topic and allowed. Rewrite it as a
native architecture discussion. Disclose authorship, avoid cross-posting the
same text, and request critique rather than stars.

### Day 10: MCP integration outreach

Send the runnable MCP reference to a small number of relevant maintainers or
server authors with one concrete lifecycle question. No bulk DMs and no implied
partnership.

### Day 11: newsletter outreach

Contact at most three tightly relevant security, AI-infrastructure, or MCP
newsletters. Provide a one-sentence problem, runnable demo, architecture image,
and explicit no-audit limitation.

### Day 12: supporting social thread

Publish the same terminal evidence on X or LinkedIn, adapted to the platform.
Do not repost engagement claims or invented user stories.

### Day 13: second measurement and decision

Compare each wave's referral traffic and downstream actions. Continue only the
channels that produced qualified questions, installs, or integrations.

### Day 14: retrospective

Document funnel counts, repeated objections, demo completion, external work,
and the next single adoption experiment. Do not define v1.2 feature scope.

## Attribution without tracking users

- Run `npm run traction` at consistent times.
- Use GitHub's aggregate traffic/referrer views for the repository owner.
- Record the exact publication time and URL of each wave.
- Ask clean-room testers directly whether the demo completed; do not embed
  telemetry in the CLI or SDK.
- Count an integration only when a public repository or maintainer confirms it.

## GitHub metadata commands

Run these only after the repository changes are reviewed and merged. They do
not change visibility or destructive repository settings.

```powershell
gh repo edit dorigjo/besa `
  --description "Cryptographic admission and evidence for consequential AI-agent actions." `
  --homepage "https://dorigjo.github.io/besa/" `
  --remove-topic "agent-tools,nodejs,receipts,signed-manifests,trust-infrastructure" `
  --add-topic "ai-agents,agent-security,mcp,mcp-security,authorization,cryptography,security,developer-tools,ai-infrastructure,typescript"
```

Create or normalize contributor labels without creating fake issues:

```powershell
gh label create "good first issue" --color "7057ff" --description "Narrow confirmed work with context and acceptance criteria" --force
gh label create "help wanted" --color "008672" --description "Confirmed work where external implementation or review is useful" --force
gh label create "security" --color "d73a4a" --description "Security behavior or hardening; vulnerabilities use private reporting" --force
gh label create "protocol" --color "5319e7" --description "Artifacts, canonicalization, signatures, trust, replay, or conformance" --force
gh label create "documentation" --color "0075ca" --description "Incorrect, missing, or unclear technical documentation" --force
gh label create "integration" --color "1d76db" --description "Execution-boundary adapter or interoperability test" --force
```

The social preview requires a maintainer to export the approved 1280 x 640 PNG
from [the media specification](SHAREABLE_MEDIA.md) and upload it in repository
Settings. Do not use the small logo as the final preview.

After `@dorigjo/besa@1.1.1` is published and registry integrity is verified,
create the matching GitHub release as a separate approved action:

```powershell
git tag -a v1.1.1 -m "Besa v1.1.1"
git push origin v1.1.1
gh release create v1.1.1 --title "Besa v1.1.1: Installed Exact-Action Demo" --notes-file docs/launch/V1_1_RELEASE_NOTES.md
```

Do not enable Discussions yet. With no sustained contributor traffic, an empty
forum adds another unattended surface; issues are the clearer feedback path.

## Feature freeze

Until Besa reaches consistent Stage 2 evidence, accept only:

- security fixes;
- critical reliability fixes;
- demonstrated adoption blockers;
- documentation corrections;
- narrowly scoped integration examples backed by external demand.

Reject speculative v1.2 platform features, dashboards, hosted analytics,
billing, broad framework packages, and work whose primary justification is
“more features may create attention.”

## Decision rules

- High impressions with few repository visits means the title or category is
  unclear.
- Repository visits with few demo runs means the first screen or command fails.
- Demo runs with few installs or stars means the value or credibility case is
  weak.
- Installs without integrations means setup or production trust boundaries are
  too costly.
- Qualified objections are useful evidence; vanity engagement is not.
- After two low-conversion waves, pause promotion and interview the actual
  developers who reached the demo rather than increasing posting frequency.
