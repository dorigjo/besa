# Data Flow — What Besa Actually Does With Data Today

This document describes the current, factual data flow of Besa as implemented in this repository.
It exists to support the privacy-relevant rows in `docs/LEGAL_TRIGGER_MATRIX.md` (C, K) with facts
instead of guesses. It is not a Datenschutzerklärung and makes no legal claims.

## 1. The CLI/SDK (`src/**`, distributed via npm)

Everything below runs **entirely on the user's own machine**. Besa the software does not make any
network calls of its own (confirmed: no `fetch`/`http`/`https` client usage in `src/**` outside of
the optional example gateway skeleton in `examples/agent-gateway/server.ts`, which is explicitly
documented as a non-production skeleton the user runs themselves).

| Artifact | Where it lives | Contains | Leaves the machine? |
|---|---|---|---|
| Signing key (`.besa/key.json`) | Local disk, AES-256-GCM encrypted | Ed25519 key material | No |
| Signed manifests | Wherever the user writes them | Tool metadata the user authored | Only if the user commits/shares them (their choice) |
| Trust store (`.besa/trust.json`) | Local disk | Public key fingerprints the user pinned | No |
| Meter state (`.besa/meter.json`) | Local disk | Call counts per manifest hash | No |
| Receipts (`.besa/receipts/*.json`) | Local disk | Admission decisions, request hashes, signatures | Only if the user exports/shares them |

**Personal data in these artifacts:** receipts and manifests can contain whatever the *user*
chooses to put in a tool's `requestPayload` or manifest metadata — Besa does not inspect or
restrict that content. If a user signs a request payload containing personal data, that data ends
up in the local receipt/request-hash the same way it would in any local log file the user
controls. Besa does not transmit it anywhere.

## 2. `postinstall.mjs` (runs on `npm install`)

Reads the local `package.json` version and prints a banner to the terminal. No network calls, no
file writes outside the terminal, no data collection. Skips entirely in CI/non-TTY environments.

## 3. The marketing site (`site/index.html` / `docs/index.html`, GitHub Pages)

- No contact forms, no analytics scripts, no advertising trackers, no custom cookies, no
  `localStorage`/`sessionStorage` usage (verified by repo-wide sweep).
- **Hosting-level processing is outside Besa's control:** GitHub Pages, as the hosting provider,
  processes standard web server access data (IP address, user agent, requested path, timestamp) for
  every visitor, under GitHub's own privacy policy — this is true of any GitHub Pages site and is
  not something this repository's code does or can disable. This is why the footer says "hosting
  providers may process technical access data under their own policies" rather than claiming no
  data is processed at all.

## 4. What does not exist yet (and therefore has no data flow to describe)

- No hosted verifier API
- No CRM or email capture
- No customer account system
- No analytics or product telemetry of any kind
- No cold outreach / email sending system

## 5. Export and deletion (for future Data Act / DSGVO relevance)

Today, "export" and "deletion" are trivial because everything is already local files the user
fully owns:

- **Export:** the user already has direct filesystem access to `.besa/receipts/`,
  `.besa/trust.json`, and any signed manifests — no export mechanism is needed because nothing is
  held remotely.
- **Deletion:** deleting the local `.besa/` directory removes all Besa-generated state. Nothing is
  retained elsewhere.

**This section must be revisited and rewritten once a hosted verifier or any service that stores
customer data server-side ships** — at that point this document should describe what is stored,
for how long, how a customer can export it, and how a customer can request deletion, matching
whatever is actually implemented rather than a promise made in advance.
