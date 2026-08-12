# Replay Protection Analysis

Analysis only — no implementation. Answers three questions precisely, backed
by the actual verification code, not assumption: can an old artifact be
replayed, what would a fix touch, and whose responsibility is a fix.

## Question 1: Can an old Receipt or SignedManifest be replayed as valid evidence?

**Yes.** Confirmed by reading `verifySignedManifest` and `verifyReceiptDetailed`
(`src/signing.ts`) in full: both answer exactly one question — "does this
signature verify against this artifact's own recorded public key" — and
nothing else. Neither function:

- checks whether `receiptId` (`src/signing.ts:521`, `"rcpt_" + randomUUID()`)
  has been seen before,
- checks whether `timestamp`/`signedAt` falls within any freshness window,
- consults any store of previously-verified artifacts.

A byte-for-byte copy of a Receipt issued yesterday verifies exactly as
successfully today as it did the moment it was created. `verifyReceipt`
(the boolean wrapper) and `verifyTrustedSignedManifest` (the trust-anchored
manifest wrapper) inherit this — neither adds freshness or uniqueness
checking on top.

**What replaying it actually gets an attacker:** a Receipt is evidence that
"tool X was allowed/denied for manifest Y at time T," carrying a valid
Ed25519 signature. Replaying it lets an attacker present old evidence as if
it were newly produced to any third party that only calls `verifyReceipt`
and trusts a `true` result without separately checking `timestamp` is
recent. The local meter (`admit.ts`) is not touched by verification at
all — replaying a receipt does not consume budget or interact with the
meter in any way, so replay is purely a "convince a verifier this happened
now" attack, not a "spend budget twice" attack (double-spend is already
prevented by the meter's file-lock + atomic-write design, independent of
this gap).

## Question 2: What would change to fix this?

Two structurally different fix shapes exist, evaluated for what each
requires:

### A. Freshness window (bounded-time acceptance)

Reject any artifact whose `timestamp`/`signedAt` is older than some
configured window (e.g. 5 minutes), similar to `checkTrustedKey`'s existing
`MAX_CLOCK_SKEW_MS` future-dating check (`trust.ts:21`, already enforced —
an artifact timestamped too far in the *future* is already rejected today).

**What this touches:** `verifySignedManifest`, `verifyReceiptDetailed` gain
a new parameter (a reference "now" and a window, mirroring
`checkTrustedKey`'s existing `now`/skew pattern) — an additive, non-breaking
signature change if given a default. **Consequence:** legitimately reusing
a receipt as evidence *later* than the window (e.g. an audit six months
later re-verifying an old receipt's authenticity) would now fail — this
would break the useful, currently-supported "receipts remain independently
verifiable forever" property that the golden-vector tests exist specifically
to guarantee (`golden.test.ts`, `PHASE3_SECURITY_AUDIT.md`'s entire premise:
"a receipt signed today still verifies in five years"). A freshness window
trades away permanent verifiability for replay resistance — it cannot do
both with the artifact format as it exists today, because nothing
distinguishes "verifying this old receipt is still authentic" from
"accepting this old receipt as if it just happened."

### B. Seen-artifact ledger (nonce/uniqueness tracking)

Reject any artifact whose `receiptId` (or `manifestHash` + `signedAt` pair,
for manifests, which have no unique ID field today) has been verified
before.

**What this touches:** requires a new piece of state — a store of every
`receiptId` ever verified, checked and updated on every `verifyReceipt`
call. This is fundamentally different from everything else in
`signing.ts`/`trust.ts`, which are pure functions of their inputs (no I/O,
no persisted state, explicitly documented as a core design property —
`checkTrustedKey`/`verifySignedManifest` never touch a filesystem or
network). Adding this means either:
- a local file-backed ledger (works for one host, not across the multiple
  independent consumers who each run `besa verify` — a receipt replayed
  against a *different* consumer's ledger looks first-seen there), or
- a shared/hosted ledger (solves cross-consumer replay, but requires the
  hosted trust plane that is explicitly out of MVP scope).

A local-only ledger only prevents replay against the same verifying host —
which is a real but narrow protection, not the general case a security
reviewer will ask about (attacker replays a receipt against a *different*
relying party than the one that originally saw it).

### Why neither is a "smallest correct fix"

Option A silently breaks a property the project already committed to and
tests for (permanent verifiability). Option B requires new persistent state
that either doesn't solve the general problem (local ledger) or requires
infrastructure explicitly excluded from this phase (hosted ledger). There
is no version of this fix that is purely a code change to existing pure
functions — every real option changes what verification *means* (bounded
freshness) or adds state verification never needed before.

## Question 3: Core-library responsibility or hosted-layer responsibility?

**Hosted-layer, by the nature of the general case.** Reasoning:

- Replay resistance that actually matters (cross-consumer, cross-time) needs
  a shared source of truth about "which receipts has anyone already
  accepted" — that is definitionally a shared/hosted concern, not something
  one local `besa verify` invocation can determine on its own, no matter how
  the core library's functions are restructured.
- A **local, single-host** freshness or uniqueness check (Option A or a
  local variant of B) *could* live in the core library — but it only
  protects the narrow case of "replay against the same host that already
  saw this artifact," which is a real but partial mitigation, not the
  answer to the general threat.
- This mirrors the project's own existing architecture split: the local
  meter (`admit.ts`) already handles single-host, single-process
  double-spend prevention via file locks — an equivalent, narrower,
  local-only mechanism *could* be built for replay the same way, and would
  be consistent with the core library's existing scope (see
  `admitAndConsume`'s meter-lock pattern as the precedent for "local,
  file-based, no hosted dependency").

## Recommendation: build a local, narrow mitigation now; defer the general fix

**Build now (small, in scope, does not require hosted infrastructure):**
nothing, in this pass — see "why not now" below. This analysis's job was to
determine whether a narrow, local, non-hosted fix exists that is worth
building immediately; it does, in principle (a local seen-`receiptId`
ledger mirroring the meter-lock pattern), but building it was not requested
by this task and would itself require new design decisions (ledger file
format, retention/pruning policy since a ledger that grows forever is its
own liability, interaction with `--request` matching in the `verify-receipt`
CLI command) that deserve their own scoped task rather than being folded
into an analysis-only deliverable.

**Defer the general (cross-consumer) fix**, explicitly, to the hosted trust
plane already named in `V1_ROADMAP.md` ("replay-resistant metering,"
"hosted receipt API") — this is not a new deferral, it is this analysis
confirming the existing deferral was the correct call, with the reasoning
now written down instead of asserted.

## Why now vs. deliberately postponed

**Postponed**, for three concrete reasons this analysis surfaced:

1. No fix exists that is both correct for the general threat and free of
   new state/infrastructure — the "smallest correct fix" standard this
   phase operates under has no candidate here.
2. The most defensible local-only mitigation (a seen-receipt ledger) is
   itself a small feature with its own design surface (retention, format,
   interaction with existing CLI commands) — building it inside a
   Task-1-analysis deliverable would violate this phase's own "not
   automatically implement" instruction.
3. The risk is already disclosed, not hidden: `THREAT_MODEL.md`'s "Replay
   risk" section and `PROVIDER_FAILURE_MODEL.md` §6 both already state this
   gap plainly to anyone evaluating Besa for production use. A rushed local
   mitigation that only partially solves the problem risks being read as
   "replay is handled" when it is not — worse than the current honest "not
   handled, documented" state.

**Trust boundary today, stated plainly:** anyone who can obtain a copy of a
previously issued, validly signed Receipt or SignedManifest can present it
again, at any later time, to any verifier that does not independently apply
its own freshness check outside of Besa's `verifyReceipt`/
`verifySignedManifest`. Besa's verification functions guarantee the artifact
is authentic and untampered; they do not and currently cannot guarantee it
is *new*.
