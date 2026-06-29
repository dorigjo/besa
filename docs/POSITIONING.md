# Besa — Positioning Framework

## One-liner

The audit layer for AI-agent actions.

## Hero subline

Know what your AI agents were authorized to do — and prove it.

## GitHub repository description

Besa gives every AI-agent tool call a policy gate and a signed audit record. Approve, enforce, and prove every agent action.

## Meta description (SEO)

Besa gives every AI-agent action a signed, tamper-evident audit record. Know what your AI agents were authorized to do — and prove it.

---

## Elevator pitch (30 seconds)

AI agents are calling real systems — CRMs, payment APIs, deployment pipelines. Every call is a real action with real consequences. When something goes wrong, or when compliance asks, most teams cannot answer: what was this agent authorized to do?

Besa solves that. You declare what each agent tool is allowed to do. Besa enforces that policy before each call happens. And it issues a cryptographic receipt for every decision — allow or deny — that any party can independently verify.

Not a log. Proof.

---

## Sales pitch (2 minutes)

**Opening — the problem**

You are deploying AI agents. These agents call real systems. They delete records. They process payments. They trigger deployments. And when something unexpected happens — you get the question: what was your agent actually supposed to do?

Right now, most engineering teams cannot answer that. There is no signed record of what the agent was authorized to do. There is no policy gate that was enforced before the action happened. There is no verifiable proof that the action was admitted or denied.

That is the gap Besa closes.

**What Besa does**

Besa is the audit layer for AI-agent actions. It works in three steps.

First: you declare. You write a manifest that says exactly which tools your agent can call, what capability type they carry — read, write, or destructive — what risk level they represent, what budget limits apply.

Second: Besa enforces. Before every tool call, Besa checks the manifest against policy. Destructive high-risk tools are blocked by default. Budget limits cap runaway usage. Undeclared tools are denied.

Third: Besa proves. Every admission decision — allow or deny — produces a signed cryptographic receipt. The receipt records the tool, the manifest hash, the decision, the reason code, the request fingerprint, and the signing key. Changing any field causes verification to fail.

**Why this matters**

When a security review asks: what could your agent do? You show the signed manifest.

When an incident happens: what did the agent actually call? You show the signed receipt.

When compliance asks: how do you know the agent followed policy? You show the evidence chain.

**Who it is for**

Engineering teams building or deploying AI agents who need a verifiable record before their next security review, compliance audit, or production incident.

**Status**

Besa is a public developer beta. Open source, MIT license. The evidence artifacts are production-quality. The infrastructure is growing.

---

## Core value propositions

| Buyer pain | Besa answer |
|---|---|
| "We can't prove what our agent was authorized to do" | Signed capability manifest — any change is detectable |
| "We need an audit trail for AI decisions" | Signed receipt for every admission decision, allow or deny |
| "Security review blocked our agent deployment" | Show the signed manifest and admission policy |
| "An agent called something it shouldn't have" | Receipt proves the decision and why it was made |
| "Compliance wants documentation of AI actions" | Tamper-evident receipt chain, independently verifiable |

---

## Positioning frame

**Category:** AI Agent Governance / Agent Audit Layer

**Primary buyer today:** Engineering Lead / Senior Developer deploying AI agents

**Secondary buyer (future):** Head of AI, CISO, Compliance Lead

**Core pain:** No verifiable record of what AI agents were authorized to do

**Purchase trigger:** Upcoming security review, compliance question, or post-incident accountability need

**Positioning statement:**

For engineering teams building AI agents, Besa is the audit layer that lets you declare what each agent tool is authorized to do, enforce that policy at runtime, and produce a cryptographic proof of every decision. Unlike scattered logs or manual documentation, Besa makes the authorization record tamper-evident and independently verifiable.

---

## Why "AI Production Gate" is not the hero frame (yet)

"AI Production Gate" is a valid aspiration. But as of beta.5 it overpromises on two fronts:

1. SECURITY.md explicitly states the product is not yet recommended for protecting production systems or real secrets. Positioning as a "gate" for production creates a gap between promise and product state.

2. The primary buyer today is a developer, not a CISO. CISOs want SOC 2, SIEM integration, HSM. None of those exist yet.

"Audit layer" is honest and still powerful. It works for developers today, scales to compliance buyers later, and does not contradict the product's own security disclosure.

Use "Production Gate" as a sub-message when speaking to CISOs or Heads of AI — frame it as where Besa is heading, not what it is today.

---

## What would push purchase pressure to 9.5/10

Three additions would dramatically increase urgency:

1. **Regulatory hook:** "EU AI Act Article 13 requires documentation of AI decisions. Besa makes that automatic." — ties Besa to an existing compliance deadline with a concrete regulation number.

2. **Incident-driven framing:** Lead with a post-incident scenario. "After the incident, you couldn't explain what the agent was authorized to do. With Besa, you'd have the signed proof before the call happened." — fear of accountability drives faster decisions than governance.

3. **GitHub Actions / CI integration:** A working `besa-action` in a developer's pipeline removes the "nice to have" barrier. When Besa runs in CI and fails the build on undeclared tool calls, it becomes infrastructure.

These are not messaging changes. They are product surface changes that make the positioning credible.
