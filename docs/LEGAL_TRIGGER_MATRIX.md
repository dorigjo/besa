# Legal Trigger Matrix — Germany / EU SaaS / AI SaaS

**This document is NOT legal advice.** It is a launch-readiness checklist that maps Besa's current
and planned activities against legal areas that commonly apply to a German-based, EU-facing
software/SaaS business. It was produced by an AI coding assistant from the current state of the
repository and public product copy — it has not been reviewed by a lawyer or tax advisor.

Every row below is a starting point for a real conversation with a **Rechtsanwalt** (and, for A,
a **Steuerberater**), not a substitute for one. Where the correct classification depends on facts
this document cannot know (revenue, customer type, actual go-to-market timing), it is marked
`unclear / lawyer needed` on purpose rather than guessed.

Status legend: `applies now` · `applies later` · `likely not applicable` · `unclear / lawyer needed`

---

## A) Gewerbeanmeldung (§ 14 GewO)

- **Status:** unclear / lawyer needed (classification), applies later (registration timing)
- **Why:** Once Besa is sold for money on a sustained, independent basis (Risk Assessment Sprints,
  Design Partner engagements, subscriptions), that is a "selbstständige, dauerhafte, entgeltliche
  Tätigkeit" and generally requires either a Gewerbeanmeldung or, if it qualifies as a
  freiberufliche Tätigkeit (e.g. software engineering can sometimes qualify depending on the
  activity mix), registration with the Finanzamt instead. Whether Besa's activity counts as
  gewerblich or freiberuflich is a real classification question — **needs a Steuerberater**, not
  a guess.
- **Repo action:** None. No public claim of business registration status either way.
- **Business action / blocker:** **Blocker for the first paid invoice.** Register before the first
  commercial sale closes, not after. Free/open-source distribution (current state) does not
  require this by itself.

## B) Impressum / Anbieterkennzeichnung (§ 5 DDG)

- **Status:** unclear / lawyer needed on exact timing, but treat as **applies now or very soon**
- **Why:** German case law interprets "geschäftsmäßige Telemedien" broadly — a site promoting a
  commercial product under a real business identity (not a purely private hobby page) is commonly
  found to require an Impressum even before the first sale. The current site markets a
  soon-to-be-commercial product under a real name.
- **Repo action:** Already done in a prior session — the footer states a real Legal Notice is "not
  yet published, to be added before commercial operation" rather than inventing one or omitting
  the topic. Do not fabricate operator details (name/address) in the repo.
- **Business action / blocker:** **Business blocker before any paid marketing push or commercial
  operation.** Draft a real Impressum with actual operator name, address, and contact details —
  this document cannot invent them.

## C) Datenschutz / DSGVO (Art. 13/14 transparency duties)

- **Status:** applies now (hosting-level processing exists), applies later (deeper duties once
  forms/CRM/hosted verifier exist)
- **Why:** GitHub Pages processes technical access data (IP addresses in server logs) regardless of
  whether Besa adds its own tracking. No forms, analytics, or cookies currently exist on the site
  (verified by sweep). Once contact forms, a CRM, email outreach, or a hosted verifier that
  processes customer data exist, Art. 13/14 transparency duties expand substantially.
- **Repo action:** Footer already avoids the absolute claim "no personal data is processed" (that
  claim would be false given hosting-level logs). `docs/DATA_FLOW.md` added alongside this file to
  track what data actually flows where, kept current as features ship.
- **Business action / blocker:** **Business blocker before lead-gen or commercial operation.** A
  real Datenschutzerklärung is required before contact forms, email capture, or a hosted verifier
  go live — this document cannot draft the legally binding version.

## D) Cookies / Tracking / Local Storage (§ 25 TDDDG)

- **Status:** likely not applicable today
- **Why:** Sweep confirmed: no cookies, no `localStorage`/`sessionStorage` usage, no analytics, no
  trackers, no embedded third-party scripts anywhere in `site/` or `docs/`.
- **Repo action:** None needed. **Do not add a cookie banner** while this remains true — an unused
  banner is itself confusing/dishonest UX.
- **Business action / blocker:** No blocker today. Re-run the sweep before adding any analytics or
  embedded widget in the future — that is the trigger to revisit this row.

## E) Cold Outreach / Marketing (§ 7 UWG)

- **Status:** applies later
- **Why:** No outreach system exists in this repo today (no email sending code, no CRM
  integration). B2B cold email in Germany has real restrictions (existing business relationship or
  consent generally required).
- **Repo action:** None — public copy should not imply mass/automated outreach ("we'll reach
  everyone", spam-adjacent framing).
- **Business action / blocker:** Not a repo blocker. Get outreach copy and process reviewed before
  building any automated sending system — do not build an automated cold-email system without that
  review first.

## F) B2C / Fernabsatz / Widerrufsrecht (§ 312d, § 312g BGB, Art. 246a EGBGB)

- **Status:** likely not applicable if kept strictly B2B
- **Why:** Consumer withdrawal-right and pre-contract information duties are triggered by selling to
  **Verbraucher** (private individuals), not businesses. Besa's current and drafted pricing (sprints,
  subscriptions, enterprise contracts) is inherently B2B-shaped — no consumer checkout exists.
- **Repo action:** Recommend public copy explicitly frame Besa as "for organizations" / "B2B security
  infrastructure" rather than leaving the buyer type ambiguous — this is the cheapest way to stay
  out of consumer-protection scope. Not yet applied to site copy — pending a separate decision.
- **Business action / blocker:** Blocker only if Besa ever adds a self-serve consumer checkout —
  don't build one without AGB, Widerrufsbelehrung, and Art. 246a EGBGB info duties in place first.

## G) Preisangaben (PAngV)

- **Status:** likely not applicable today (no public prices), unclear / lawyer needed if published
- **Why:** `docs/PRICING.md` is currently untracked/unpublished and explicitly marked "no public
  price list, direct contact only." PAngV mainly bites when prices are advertised to consumers;
  B2B-only pricing has more latitude but should still be clearly excl. VAT where relevant.
- **Repo action:** See the separate pricing decision — not resolved in this document, handed to the
  founder separately.
- **Business action / blocker:** If pricing is ever made public: state B2B-only, "prices exclude
  statutory VAT where applicable," and do not advertise consumer-style pricing.

## H) EU AI Act (Regulation (EU) 2024/1689)

- **Status:** applies now (marketing-claim restriction), likely not applicable (Besa as regulated
  AI system)
- **Why:** Besa itself does not appear to use machine learning or make autonomous decisions on data
  it wasn't explicitly configured with — the codebase (`src/*.ts`) is deterministic cryptographic
  signing/verification/policy logic, not an AI system under Art. 3's definition. That makes Besa
  **likely not** a "provider" of an AI system under the Act in its own right. What **does** apply
  now, regardless: Besa's marketing must not claim it makes *customers* AI-Act-compliant or that
  Besa itself is "AI Act compliant" — no certification exists for either claim.
- **Repo action:** Already satisfied — `SECURITY.md` explicitly forbids representing Besa as
  AI Act compliant. Keep positioning as "supports audit evidence, admission records, and execution
  receipts relevant to Art. 12 (logging) and Art. 13 (transparency) style obligations" — never
  "makes you compliant" or "AI Act compliant."
- **Business action / blocker:** No blocker today. Revisit if Besa itself starts making autonomous
  decisions using ML (it currently does not).

## I) Cyber Resilience Act (Regulation (EU) 2024/2847)

- **Status:** unclear / lawyer needed
- **Why:** Besa ships "digital elements" (an npm package with network-adjacent functionality is in
  scope territory generally). The CRA has a non-commercial open-source exemption (Art. 2(4)) whose
  exact boundary — especially once a commercial entity sells services around the same open-source
  code, as `docs/PRICING.md` plans — is a genuine open legal question that needs counsel, not a
  guess from this document.
- **Repo action:** `SECURITY.md` already documents a vulnerability disclosure process and
  version/support expectations for the beta. Keep that current as a CRA-relevant good-practice
  baseline regardless of the exemption question.
- **Business action / blocker:** Business blocker before scaled commercial sale of the packaged
  product — get counsel on the open-source exemption boundary before that point, not after. No
  "CRA compliant" claim without legal verification.

## J) NIS2 (Directive (EU) 2022/2555)

- **Status:** likely not applicable today, applies later (conditional)
- **Why:** NIS2 targets operators of essential/important entities and certain digital
  infrastructure/managed-service providers at scale. A local CLI/SDK tool with no hosted service is
  not in scope today.
- **Repo action:** None. No NIS2 claims anywhere (confirmed by sweep).
- **Business action / blocker:** Only relevant if/when Besa operates a hosted verifier at scale
  serving customers in NIS2-covered sectors — revisit at that point, not now.

## K) Data Act (Regulation (EU) 2023/2854)

- **Status:** likely not applicable today, applies later (once hosted verifier exists)
- **Why:** Data Act obligations (switching, portability, deletion) target cloud/data-processing
  services. Besa today produces local JSON artifacts the user already fully controls — there is no
  vendor-held customer data to port or delete.
- **Repo action:** `docs/DATA_FLOW.md` (added alongside this file) documents the current
  receipt/export/deletion model so this is easy to re-assess once a hosted verifier ships.
- **Business action / blocker:** No blocker today. Design the hosted verifier's export/deletion
  model before launch, not after — and do not claim "no lock-in" publicly until that model exists
  and is documented.

## L) Digital Services Act (Regulation (EU) 2022/2065)

- **Status:** likely not applicable
- **Why:** Besa is not a hosting intermediary, marketplace, or platform distributing third-party
  user-generated content for public dissemination. This changes only if a future hosted feature
  stores and republishes user content publicly — nothing in the current or planned roadmap does
  that.
- **Repo action:** None.
- **Business action / blocker:** None currently foreseeable.

## M) Product Liability / Software Liability (Directive (EU) 2024/2853)

- **Status:** unclear / lawyer needed
- **Why:** The revised Product Liability Directive extends defective-product liability concepts to
  software; national transposition (including in Germany) is still in progress. Whether and how it
  applies to an MIT-licensed open-source component versus the commercial services built around it
  is a real open question needing counsel.
- **Repo action:** Keep the MIT license's "AS IS, WITHOUT WARRANTY" disclaimer intact, keep
  `SECURITY.md`'s limitations section honest, do not add "guaranteed," "risk-free," or "audit-proof"
  language anywhere (checked in Phase 8 sweep — none found).
- **Business action / blocker:** Get counsel on transposition status in Germany before any
  enterprise contract that could be read as an indemnity or risk-shield promise.

## N) DORA — Digital Operational Resilience Act (financial services)

- **Status:** likely not applicable today, applies later (conditional on customer type)
- **Why:** DORA applies to financial entities and their "critical ICT third-party providers." Besa
  has no financial-sector customers today. The drafted pricing document mentions Fintech as a target
  vertical for higher tiers — if that materializes, Besa could become an ICT third-party provider to
  a DORA-regulated entity.
- **Repo action:** `SECURITY.md` already forbids a "DORA compliant" claim. Keep using "designed to
  support evidence workflows relevant to regulated environments" instead.
- **Business action / blocker:** Business blocker specifically for the first Fintech/financial-entity
  contract — get counsel on DORA third-party-provider obligations before signing, not after.

## O) Contracts / AGB / SLA / Support Promises

- **Status:** applies later (only if/when public commercial terms are published)
- **Why:** No public SLA, AGB, or support-response guarantee currently exists on the site (verified
  by sweep). The drafted higher pricing tiers reference SLA definitions and response-time
  guarantees — publishing those without a matching, deliverable support operation would be a real
  promise the business may not be able to keep.
- **Repo action:** None needed today — nothing published. Do not publish SLA/uptime/response-time
  numbers on the public site until they are contractually and operationally real.
- **Business action / blocker:** Blocker before publishing any tier that names a specific SLA or
  response time — confirm it's actually deliverable (and get it reviewed) first.

---

## Summary: items that are blockers before commercial operation

1. **B — Impressum:** real operator details needed before commercial push (repo already has an
   honest placeholder, not a fake one).
2. **C — Datenschutzerklärung:** real privacy policy needed before lead-gen/forms/hosted verifier.
3. **A — Gewerbeanmeldung/Steuerberater classification:** needed before the first paid invoice.
4. **I — CRA open-source exemption boundary:** needs counsel before scaled commercial sale of the
   packaged product.
5. **G/O — Pricing and SLA publication:** only a blocker if/when `docs/PRICING.md` (or any SLA
   language) is made public — see the separate pricing decision.

Nothing in this list blocks continuing to develop and distribute the current free, open-source
beta CLI/SDK as-is.
