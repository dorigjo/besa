# Besa discovery audit

Audit period: 2026-09-23 to 2026-09-24

This audit evaluates the path from an unprompted search or launch-post click to
a first verified admission and a credible integration decision. Scores measure
repository readiness, not product-market fit or external adoption.

## Baseline evidence

- npm downloads: 5 in the latest 7-day window, 11 in the preceding comparable
  window, and 63 in the latest 30-day window.
- GitHub: 0 stars, 0 forks, 0 watchers, and no external issue activity.
- GitHub traffic snapshot: 10 views / 5 unique visitors and 84 clones / 29
  unique cloners over 14 days. A one-day CI/release spike makes clone counts
  unsuitable as organic adoption evidence.
- The latest GitHub Release is still `v0.1.0`, while npm and `main` are at
  v1.1.0. Its limitations are stale.
- The published `@dorigjo/besa@1.1.0` CLI returns `Unknown command: demo`.
- Search and npm-index snippets still surface older manifest/receipt wording.
- The repository has no purpose-built social preview and no homepage URL in the
  GitHub About panel.

These facts describe a distribution and conversion failure. They do not prove
that the protocol has or lacks product-market fit.

Final local-validation snapshot, using closed UTC windows ending 2026-09-23:
3 npm downloads in 7 days, 13 in the preceding 7 days, and 46 in 30 days;
0 stars, 0 forks, 0 open issues, 0 external issues, and latest GitHub Release
still `v0.1.0`. Repository work has therefore not increased the actual traction
score.

## Scorecard before optimization

Scale: 0 means absent or actively misleading; 5 means understandable with
effort; 10 means an unfamiliar senior engineer can verify the claim and act
without founder help.

| Area | Score | Evidence and blocker |
|---|---:|---|
| Positioning | 7/10 | Exact-action language is strong, but older discovery surfaces still lead with manifests and generic trust language. |
| README | 6/10 | Technically honest and detailed, but the first value proof required clone, install, build, and repository context. |
| First impression | 5/10 | The category is plausible, but no single concrete action made the boundary instantly memorable. |
| Demo | 2/10 | A real source demo exists; the installed CLI cannot run it. This is the largest conversion defect. |
| Installation | 7/10 | One normal npm package, ESM, Node 20+. Installation works; the next action is unclear. |
| Time to value | 3/10 | Published-package users cannot reach the advertised demonstration with one command. |
| Trust | 8/10 | Threat model, strict schemas, vectors, security review, release gates, and explicit limitations are unusually strong. No independent audit exists. |
| Shareability | 3/10 | No compact terminal moment, architecture SVG, GIF recipe, or social preview. |
| Searchability | 4/10 | Relevant terms exist, but stale snippets, name collisions, weak GitHub metadata, and an old release dilute discovery. |
| Developer appeal | 5/10 | The implementation is substantive; integration examples and contributor entry points are not yet effortless. |

Unweighted baseline readiness: **5.0/10**.

## Scorecard after local optimization (pre-release)

This score reflects the current repository and package candidate, not the live
npm or GitHub discovery surfaces. The patch release, repository metadata, and
social preview still require explicit founder actions.

| Area | Score | Evidence and remaining blocker |
|---|---:|---|
| Positioning | 9/10 | The category sentence, exact-action boundary, and concrete denial are now consistent across the README and site; external search snippets have not refreshed. |
| README | 9/10 | The first screen now provides the category, boundary, threat, install path, demo, architecture, and honest limitations. |
| First impression | 8/10 | The production-database denial is immediate and memorable; independent adoption proof is still absent. |
| Demo | 8/10 | `besa demo` is implemented, regression-tested, and exercised from a packed install; it is not available until v1.1.1 is published. |
| Installation | 8/10 | The intended path is one npm install plus one command, with clean-room package checks; the currently published v1.1.0 still lacks that command. |
| Time to value | 7/10 | Local and packed-package evaluation is under two minutes; the public package remains the release blocker. |
| Trust | 8/10 | Security limits, controls, benchmarks, conformance, and verifier guidance are prominent; no independent audit exists. |
| Shareability | 8/10 | A compact terminal moment, architecture SVG, capture recipe, social-image specification, and channel drafts now exist. |
| Searchability | 6/10 | Package keywords and copy are focused; GitHub About metadata, social preview, current release, and indexed snippets remain external work. |
| Developer appeal | 8/10 | MCP, HTTP, and generic boundaries plus clearer contribution paths lower evaluation cost; no external reference integration exists yet. |

Unweighted pre-release readiness after local optimization: **7.9/10**.

## Stranger test

Assume the visitor arrived from Hacker News with no context.

| Question | Baseline answer time | Finding |
|---|---:|---|
| What is Besa? | <15 seconds | The README sentence answers this. |
| Why does it exist? | 30–60 seconds | The authentication gap is explained, but the concrete boundary arrives too late. |
| Why is IAM not enough? | 1–2 minutes | Answered defensibly, but not as a first-screen example. |
| Why is MCP authorization not enough? | 2–4 minutes | Present across sections; no dedicated comparison page. |
| Where does it sit? | <30 seconds | The diagram is accurate but visually dense. |
| What problem does it prevent? | 1–2 minutes | Several scenarios compete instead of one memorable deny. |
| Can I try it in under two minutes? | **No from npm.** | `npx besa demo` fails in the published package. |
| Can I integrate it in under ten minutes? | Not reliably | The core wrapper is usable, but configuration and framework adapters require repository study. |
| Is it production-oriented or a toy? | 2–3 minutes | Security material, tests, verifier hardening, and limitations support a serious answer. |
| Why should I star or share it? | Unclear | No external integrations or adoption proof; the technical idea must carry the entire decision. |

## Discovery defects

1. **No installed-package payoff.** Installation succeeds but the obvious demo
   command does not exist in v1.1.0.
2. **Release mismatch.** GitHub presents an old release as the latest public
   milestone, undermining the current README and npm package.
3. **Stale search language.** Search snippets emphasize the v1.0 manifest flow
   rather than exact-action admission.
4. **Weak visual transmission.** There is no reusable architecture SVG or
   terminal capture recipe for launch posts and technical articles.
5. **Integration tax.** Correct runtime configuration is intentionally explicit,
   but the repository lacks three short framework-boundary examples.
6. **No external proof.** Zero stars, forks, external issues, or integrations
   means trust must come entirely from inspectable engineering evidence.
7. **Name collision.** “Besa” collides with unrelated products and organizations;
   category terms must accompany the name consistently.
8. **Contribution ambiguity.** The project explains protocol rigor but not where
   a first non-protocol contribution should start.

## Conversion funnel

| Stage | Metric | Primary friction | Repository fix |
|---|---|---|---|
| Impression | Search impressions and launch-post views | Category/name collision and stale snippets | Consistent exact-action language and focused metadata |
| GitHub visit | Unique visitors by source | No purpose-built social preview; old latest release | Honest visual assets and current release notes |
| README understood | Time to explain the boundary unaided | Abstract flow before memorable example | AWS credentials vs `DELETE production-db` above the fold |
| Demo run | Successful `besa demo` executions | Published command missing | Tested CLI command in the next patch package |
| npm install | 7-day downloads | No immediate post-install success | One install plus one command |
| Star | Legitimate GitHub stars / unique visitors | Value visible, but little external proof | Ask for critique, not stars; let demo and evidence carry the case |
| Integration | External repos, issues, and dependency use | Configuration and adapter friction | MCP-first reference plus HTTP and generic wrappers |
| Share | Independent posts, links, and explanations | No compact media or repeatable wording | Terminal capture, SVG, and factual launch assets |

No user tracking is required. GitHub traffic, npm downloads, public repository
events, and externally visible integrations are sufficient for the first stage.

## Priority corrections

### P0: must be true before launch

- Ship and test `besa demo` in an installable patch release.
- Make the first README screen explain IAM/MCP Auth -> Besa -> exact action.
- Publish current GitHub release notes and stop presenting v0.1.0 as latest.
- Keep the security limitations and no-independent-audit statement prominent.
- Verify package contents and the clean-room installed demo before publishing.

### P1: conversion support

- Add copy-paste MCP, HTTP, and generic TypeScript boundaries.
- Add factual Besa-vs-IAM, Besa-vs-MCP-Auth, and Besa-vs-observability pages.
- Surface measured local benchmark results with methodology.
- Provide reusable diagrams, a GIF recording recipe, and launch drafts.
- Add a local traction report using public APIs only.

### P2: external validation

- Build one MCP reference integration rather than many shallow plugins.
- Request technical criticism in measured launch waves.
- Track real downstream integrations and contributor activity.
- Do not create speculative v1.2 features while conversion remains unproven.

## Short-seller review

**Why would a developer not star Besa?** The problem may be real but uncommon
for their system, the runtime setup is explicit, and there is no adoption proof.
The repository should reduce evaluation cost, not manufacture social proof.

**Why would a security engineer dismiss it?** The executor can share control
with the issuer or recorder in a weak deployment, evidence does not prove an
external side effect, and no independent audit exists. Besa must keep those
limits explicit and show stronger split-control deployment models.

**Why would an MCP developer say OAuth already solves this?** A sufficiently
detailed authorization server can bind request context. Besa's narrower claim
is a portable exact-invocation artifact and evidence contract, not that OAuth or
MCP cannot express policy.

**Why would AWS build it?** A cloud vendor can provide stronger native controls
inside its own boundary. Besa is only differentiated where a provider-neutral
contract must cross identity, agent, tool, and execution systems.

**Why is this not just signed JSON?** The implementation adds strict schemas,
canonicalization, domain separation, trust anchors, narrowing delegation,
deterministic admission, replay semantics, linked evidence, frozen vectors, and
conformance tests. Each property is inspectable; none creates adoption by itself.

**Why is this not just a feature?** It may be a feature in many products. The
open-protocol case depends on multiple independent producers and verifiers using
the same artifacts. That interoperability remains to be demonstrated.

## Readiness versus traction

- **Virality readiness before optimization: 5.0/10.** Strong protocol and trust
  material, weak demo and transmission surface.
- **Virality readiness after local optimization: 7.9/10.** The repository and
  package candidate now support discovery, proof, integration, and sharing, but
  the patch release and external GitHub surfaces are not live.
- **Actual traction at baseline: 1.0/10.** Five weekly npm downloads, zero stars,
  and no verified external integration are below Stage 1 proof thresholds.
- **Virality 8/10 is not achieved by repository work.** It requires Stage 4
  evidence: 1,000+ weekly downloads, 250–500+ legitimate stars, external
  contributors and integrations, and sustained multi-channel growth.

See [Integration Targets](INTEGRATION_TARGETS.md) and the launch plan once those
artifacts are complete.
