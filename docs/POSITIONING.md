# Besa — Positioning Framework

## One-liner

The AI agent execution control plane.

## Hero subline

Policy-gated tool calls. Signed decisions. Verifiable audit evidence.

## GitHub repository description

Besa is an AI agent execution control plane. Policy-gated tool calls, signed allow/deny decisions, and tamper-evident execution receipts — before the tool call happens.

## Meta description (SEO)

Besa is the AI agent execution control plane. Declare what your agents can do, gate every tool call against policy, and prove every decision with a signed cryptographic receipt.

---

## Elevator pitch (30 seconds)

AI agents are calling real systems — CRMs, payment APIs, deployment pipelines. Every call is a real action with real consequences. When something goes wrong, or when compliance asks, most teams cannot answer: was that tool call inside policy before it happened? Who declared it? What was the decision?

Besa solves that. It sits in the agent's execution path — before the tool is called. It checks whether the action is declared, policy-approved, within budget, and attributable. Then it issues a signed cryptographic receipt for every decision — allow or deny — that any party can independently verify.

Not beside the workflow. In it.

---

## Sales pitch (2 minutes)

**Opening — the problem**

You are deploying AI agents. These agents call real systems. They delete records. They process payments. They trigger deployments. And when something unexpected happens — you get the question: what was your agent actually supposed to do, and was that action inside policy before it ran?

Right now, most engineering teams cannot answer that. There is no gate. There is no signed record. There is no verifiable proof that the action was admitted or denied before it happened.

That is the gap Besa closes.

**What Besa does**

Besa is the execution control plane for AI-agent tool calls. It works in three steps.

First: you declare. You write a manifest that says exactly which tools your agent can call, what capability type they carry — read, write, or destructive — what risk level they represent, what budget limits apply, and which scopes are permitted.

Second: Besa gates. Before every tool call, Besa checks the manifest against policy — fail-closed. Destructive high-risk tools are blocked by default. Budget limits cap runaway usage. Per-agent grant scoping restricts access to specific tools. Undeclared tools are denied. If the decision is deny, the tool call never happens.

Third: Besa proves. Every admission decision — allow or deny — produces a signed cryptographic receipt. The receipt records the tool name, the manifest hash, the decision, the reason code, the request fingerprint, and the signing key. Changing any field causes verification to fail.

**Why this matters**

When a security review asks: what could your agent do? You show the signed manifest.

When an incident happens: was the agent's action inside declared policy? You show the admission decision and the signed receipt.

When compliance asks: how do you know the agent followed policy before each call? You show the evidence chain — sign → verify → admit → receipt → verify-receipt.

**Who it is for**

Engineering teams building or deploying AI agents who need a verifiable, auditable control layer before their next security review, compliance audit, or production incident.

**Status**

Besa is a public developer beta. The core execution control artifacts — signed manifests, signed receipts, and the verification chain — are production-quality cryptography. The surrounding infrastructure (hosted verifier, HSM, SIEM export) is on the roadmap.

---

## Core value propositions

| Buyer pain | Besa answer |
|---|---|
| "We can't prove what our agent was authorized to do" | Signed capability manifest — any change is detectable |
| "We need an audit trail for AI decisions" | Signed receipt for every admission decision, allow or deny |
| "Security review blocked our agent deployment" | Show the signed manifest and admission policy |
| "An agent called something it shouldn't have" | Receipt chain proves the decision, reason, and request |
| "Compliance wants documentation of AI actions" | Tamper-evident receipt chain, independently verifiable |
| "We need this to run in CI/CD" | Besa runs in GitHub Actions — fails the build on undeclared tools |

---

## Positioning frame

**Category:** AI Agent Execution Control Plane

**Primary buyer today:** Engineering Lead / Senior Developer deploying AI agents

**Secondary buyer (future):** Head of AI, CISO, Compliance Lead

**Core pain:** No verifiable, fail-closed gate on what AI agents are allowed to do before they do it

**Purchase trigger:** Upcoming security review, compliance question, CI/CD integration need, or post-incident accountability

**Positioning statement:**

For engineering teams building AI agents, Besa is the execution control plane that lets you declare what each agent tool is authorized to do, gate every tool call against policy fail-closed, and produce a cryptographic proof of every decision. Unlike scattered logs or manual documentation, Besa makes the authorization record tamper-evident, verifiable before the action, and independent of any specific infrastructure.

---

## Why "execution control plane" is the correct frame now

"Audit layer" was accurate but passive. It implied Besa sits beside the workflow and records what happened. That frame undersells what the product actually does.

Besa is not passive. It sits in the execution path. The admit gate runs before the tool call. Denied calls never happen. The receipt documents the decision that occurred before the action, not after.

"Execution control plane" is the accurate description:
- Policy is checked before execution
- Behavior is gated, not just logged
- The evidence is produced before the tool call completes
- Fail-closed is a design property, not a feature flag

This framing is consistent with SECURITY.md. The infrastructure is beta. The control plane architecture is real — the signed manifest, policy gate, and admission receipt exist and work. We are not claiming production-readiness. We are claiming the correct architectural category.

---

## What would push purchase pressure to 9.5/10

Three additions that dramatically increase urgency (these are product surface changes, not messaging):

1. **CI/CD gate (done in beta.5):** Besa runs in GitHub Actions, verifies manifests, and fails the build on undeclared or high-risk tools. When Besa is in CI, it becomes infrastructure — not a nice-to-have. See `docs/CI_GATE.md`.

2. **Runtime gateway skeleton (next surface):** A minimal HTTP proxy that puts Besa on the agent's tool call path. Agent calls the gateway. Gateway calls `admit()`. If deny, the upstream system never receives the request. This makes the "execution control plane" claim visible in the architecture diagram.

3. **Regulatory hook (messaging):** EU AI Act Article 13 requires documentation of AI decisions. SOC 2 auditors want evidence of agent access controls. Besa's signed receipts are the most direct answer available. This ties Besa to existing compliance deadlines — fear of audit drives faster decisions than governance interest.

---

## Honest positioning limits (beta.5)

These claims are true:
- Besa gates tool calls against declared policy — fail-closed
- Undeclared tools are denied
- Destructive high-risk tools are blocked by default
- Every decision produces a signed, verifiable receipt
- The evidence chain is tamper-evident
- Besa runs in CI/CD (GitHub Actions)

These claims are not yet true and must not appear in public-facing copy:
- Production-ready (SECURITY.md says beta)
- SOC 2 / ISO 27001 / EU AI Act compliant (no certification exists)
- Hosted verifier (not built yet)
- HSM or multi-user support (not built yet)
- SIEM export (not built yet)
- Runtime HTTP gateway (skeleton only in examples/)

---

## Roadmap from control plane to enterprise infrastructure

| Stage | What exists | What it unlocks |
|---|---|---|
| beta.5 (today) | CLI gate, CI/CD, local enforcement, signed receipts | Developer adoption, CI integration |
| Next | Hosted verifier API | Consumer verification without local trust store |
| Then | Hosted receipt retention | Tamper-evident log, compliance evidence export |
| Then | Runtime gateway (GA) | Agent tool call interception in production |
| Then | Enterprise control plane | Org-level policy, SIEM, HSM, multi-user, SSO |
