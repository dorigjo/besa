# VC Attack Surface

**Format:** Investment Committee mode. Every objection is stated as brutally as an IC member would state it. Every response is the honest counter, not marketing.

This document is for internal use. It must not contradict SECURITY.md, LIMITATIONS.md, or the public README.

---

## Objection 1: "This is a library, not a company."

**The attack:**
Besa is a TypeScript package that wraps `@noble/ed25519` and does JSON signing. Any developer could build this in a day. Why is this a business?

**The honest counter:**
The code is not the moat. The artifact chain is.

Every signed manifest, every pinned public key, every receipt issued creates a dependency on the Besa format. Once an agent runtime, a CI pipeline, or a compliance process is built around Besa artifacts, switching means re-signing all historical manifests, renegotiating trust with all consumers, and rebuilding the audit trail.

This is the same lock-in that made Git win. Git is also just a library. But the artifacts it produces — commits, hashes, remotes — became infrastructure. Besa bets on the same pattern: the format and the artifact chain become stickier than the code.

The risk: we have to get to adoption before someone else does. This is a land-grab window, not a permanent moat.

---

## Objection 2: "The big platforms will ship this."

**The attack:**
Anthropic ships Claude. OpenAI ships GPT. AWS ships Bedrock. Any of them can add a "tool verification" feature in a quarterly update. You get killed by a changelog entry.

**The honest counter:**
Platform-native tool verification locks you to one platform. Besa is cross-platform by design. An agent that uses Claude today and switches to a local model tomorrow needs a trust layer that travels with the manifest — not one that lives inside Anthropic's API.

The more credible threat is Microsoft (Azure AI + GitHub + GitHub Actions) because they own the CI surface. That's real. Besa has to win on the developer-first, portable, open-artifact story before Microsoft decides this is worth shipping.

The honest assessment: if any of the major platforms moves fast on this, the window closes. The bet is on them moving slow — which historically they do on developer trust infrastructure until a compliance event forces their hand.

---

## Objection 3: "There's no market yet. You're building for a problem that doesn't exist at scale."

**The attack:**
Enterprises aren't deploying AI agents in production at the scale where tool governance becomes a real problem. You're building for a market that might be 3-5 years away. You'll run out of runway before the market arrives.

**The honest counter:**
This is the strongest objection and deserves a real answer.

The near-term real market is not enterprises. It's:
1. Developers building MCP servers who want a credible way to publish what their tools can do
2. Regulated-industry teams (finance, healthcare, legal) facing early pressure to demonstrate "AI oversight" — even if informal
3. AI infrastructure companies (LangChain, LlamaIndex, Cursor, etc.) who need something to point to when asked "how do you know this agent won't call a destructive tool?"

The revenue path requires these early adopters to pay before the enterprise market arrives. That's the actual risk: can we find 50-100 teams willing to pay for this in the next 18 months?

If not, the bet fails regardless of how good the technology is.

---

## Objection 4: "You can't monetize open source signing infrastructure."

**The attack:**
If the format is open and the library is MIT-licensed, anyone can verify Besa artifacts without paying you. You have no pricing lever. HashiCorp built Terraform and then had to BUSL it in desperation.

**The honest counter:**
The library stays open. The infrastructure around it is where revenue lives:

- **Hosted verifier:** Consumers verify manifests without running the CLI (receipt verification endpoint)
- **Receipt retention and audit API:** 12-month tamper-evident receipt storage with query API
- **Enterprise key management:** Team key rotation, revocation lists, policy namespaces
- **CI Gate SaaS:** Besa runs in your CI without you managing the binary

None of these require closing the library. The format being open is a feature — it creates the audit trail that enterprises need to buy against.

The risk: each of these hosted features requires infrastructure spend before revenue. The pricing model has to be validated before the company runs on VC math.

---

## Objection 5: "Security infrastructure requires security credibility. You have none."

**The attack:**
You're a solo founder shipping a TypeScript package. Enterprise security teams will not buy signing infrastructure from an unaudited, unproven vendor. They'll wait for CrowdStrike or Palo Alto to ship a version.

**The honest counter:**
This is true and serious.

The immediate response: don't sell to enterprise security teams yet. Sell to developer teams making early AI agent decisions before the enterprise security team is even in the room.

The honest path to credibility:
1. Open source the core — the code is auditable today
2. Ship a third-party audit before any enterprise sales conversation
3. Get one credible design partner to publicly use Besa in a non-trivial way
4. Build the audit trail that proves the library does what it says

The risk: this takes 12-18 months to establish and requires either a security-credentialed co-founder or enough revenue to buy an audit. We have neither yet.

---

## Objection 6: "Ed25519 is fine but the threat model is wrong."

**The attack:**
The real threat in AI agent systems isn't a tampered manifest. It's prompt injection, model hallucination, and API key exposure. Besa solves the wrong problem. You're putting a lock on the front door while the back wall is missing.

**The honest counter:**
This is a fair framing challenge, not a product failure.

Besa does not prevent prompt injection. It does not prevent hallucination. It is not a full security stack.

What it does: it creates a verifiable record of what tool was authorized, under what declared capabilities, at what time, with what budget limit. When something goes wrong — and something will go wrong — Besa answers "was this tool call within the declared policy or outside it?"

That's not the whole security story. It's the accountability and attribution layer. The positioning must be honest: Besa is the signing and receipts layer, not the complete AI security solution.

The risk: if Besa positions itself as "security infrastructure" without this caveat, enterprise buyers will expect it to solve problems it doesn't solve. That's a trust failure. The honest positioning is "execution control and audit evidence layer."

---

## Objection 7: "Solo founder can't build trust infrastructure. It needs a team."

**The attack:**
Trust infrastructure requires long-term commitment, security expertise, legal defensibility, and enterprise relationships. A solo founder cannot credibly maintain this. The first time there's a bug in the signing code, the whole value proposition collapses.

**The honest counter:**
Correct on the long-term. Wrong on the MVP.

The MVP goal is to prove the architecture is correct and that developers will use it. A solo founder can do that. Building the company that operates this as infrastructure requires a team — co-founder with security background, legal counsel, and eventually a sales motion into enterprise.

The honest timeline: solo founder takes this to first 50 developers and first revenue. Then raise, hire, and build the team that can operate it at scale.

The risk: the window between "MVP proves the idea" and "team is in place" is where most solo-founder infrastructure startups die. This is a known failure mode and the plan needs to address it explicitly.

---

## Summary: What the IC would approve

The strongest version of the Besa pitch is:

1. The format and artifact chain create durable lock-in even if the code is open
2. The near-term market is developers, not enterprises
3. Revenue comes from hosted infrastructure around open signing
4. The solo-founder MVP is honest about its scope and limitations
5. The path to defensibility requires a security audit and at least one credible design partner in the next 12 months

The strongest version of the kill argument is:

1. Microsoft ships this in GitHub Actions in 2026 and it's free
2. The developer market doesn't pay for signing infrastructure
3. The enterprise market requires security credibility we don't have yet
4. We run out of runway before any of the monetization paths work

Both arguments are honest. The IC decision depends on whether the execution speed and timing bet is credible.
