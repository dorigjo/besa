# BESA v1.4 Competitive and Regulatory Review

Research snapshot: 2026-11-15. This is a source-based desk review, not legal
advice, customer validation, or an independent verification of vendor claims.

## Competitive boundary

| System | Publicly documented capability | BESA overlap | Status / implication |
| --- | --- | --- | --- |
| AWS Bedrock AgentCore Policy | Policy conditions can inspect tool input fields and apply allow/deny decisions at the gateway. | Exact tool-argument policy and pre-tool enforcement. | Confirmed in AWS documentation. Generic argument-aware allow/deny is bundling risk, not a BESA moat. |
| RSA Agent ID Secure | RSA describes per-call tool/argument authorization and attributable records. | Per-call authorization and auditability. | Vendor-described capability; public materials reviewed here do not establish portable offline receipts. Do not claim absence or superiority without an artifact-level comparison. |
| SailPoint Agentic Fabric | Agent discovery, identity governance, access controls and audit/reporting are positioned as product capabilities. | Identity/authority governance and action controls. | BESA should integrate with, not rebuild, identity lifecycle and governance. |
| Microsoft Agent Governance Toolkit receipt proposal | A public proposal describes signed compliance receipts and verification. | Signed evidence and verifier contract. | Proposal status, not evidence of a generally available product. The proposal itself notes that a signature by a self-asserted signer does not establish external trust. |
| Prismer AI Signet | Its repository describes signed/hash-chained action receipts, offline verification and pre-approval artifacts. | Significant conceptual and protocol overlap. | Repository claims require independent interoperability/security testing. Signed receipts alone are not a unique BESA claim. |
| Cloudflare MCP security | Cloudflare documents OAuth-based MCP protection and gateway/control-plane functions. | Authentication and runtime/gateway policy boundary. | BESA must not claim transport authentication, sandboxing or egress protection; integrate after trusted identity is established. |
| OpenAI ChatGPT Wallet / commerce | Official material describes transaction detail and user approval in its wallet/payment flow. | Exact transaction authorization and consent context. | Different product boundary and early ecosystem; no evidence reviewed establishes a need for an additional BESA commerce subsystem. Test buyer demand before building. |
| Visa Trusted Agent Protocol | Visa publishes an agent identity/payment protocol with signed transaction-related data and nonce/validity context. | Transaction binding and replay-adjacent evidence. | Payment-network participants and merchant-side state remain part of the trust model. Do not claim BESA replaces payment authorization or settlement. |
| Mastercard Agent Pay | Mastercard describes agent recognition and agent-payment ecosystem controls. | Agent/payment authorization context. | Payment network-specific ecosystem; BESA should not compete as a payment rail or fraud system. |
| American Express agent payments | Shareholder material refers to agentic-commerce pilots and planned developer work. | Potential future transaction authorization overlap. | Announced/limited public detail; exact technical contract remains unknown. |
| W3C WebMCP Community Group draft | A draft describes browser-page JavaScript tools exposed to agents. | Tool invocation boundary. | Draft, not a W3C Standard. It does not by itself establish portable signed admission evidence. |

### Competitive conclusion

Runtime policy engines already make exact-input allow/deny a credible bundled
capability. BESA's remaining candidate distinction is not the decision itself:
it is a vendor-neutral artifact contract that binds the decision to a canonical
action and configured authority, can be checked offline with independently
configured trust material, and can link to separately signed recorder evidence.
That distinction is technically plausible but commercially unproven. The
Dashboard is an inspection surface, not evidence of adoption or a moat.

Do not claim that BESA is the only system with portable receipts, that a signed
recorder result proves a real-world side effect, or that competitors lack
replay, offline verification, or action binding unless a current documented
comparison demonstrates it.

## EU Digital Fairness Act

Status on this snapshot date: **OFFICIAL LEGISLATIVE PROPOSAL**, not enacted law.
The Commission proposal is identified as COM(2026) 1100 final and the European
Parliament procedure is 2026/0356(COD). Legislative text may change; applicability
dates depend on adoption and entry into force.

| Provision | Text-level subject | BESA implication |
| --- | --- | --- |
| Article 2 | Scope, including relevant trader/consumer practices and automated systems. | Determine customer and workflow applicability with counsel; no BESA API is specified. |
| Article 3 | Definitions, including automated systems and automated contracting tools. | Product classification is fact-specific; a receipt does not establish legal compliance. |
| Article 4 | Relationship to other Union law. | The proposal is not a substitute for sectoral rules. |
| Article 26 | Consumer controls for automated contracting tools, including choices about confirmation/criteria, durable confirmation and disclosures in relevant circumstances; the text includes a financial-services exclusion. | These are obligations on covered actors and workflows. The reviewed text does not mandate a third-party cryptographic authorization service. |
| Article 40 | Application timing tied to the proposal's legislative commencement provisions. | No operative application date should be promised before enactment and final text. |

The Commission's proposal document and annexes, and the Parliament procedure
file, are linked below. Any compliance product claim requires a separate legal
analysis of the final enacted text and the customer's role.

## Evidence and market questions

* Technical: third-party implementations must be able to validate frozen
  vectors without BESA-hosted services. Existing BESA vectors are useful but do
  not yet demonstrate an independent implementation in another language.
* Product: no buyer interviews, paid pilot, or external production integration
  are established by this repository work. Willingness to pay is unknown.
* Build gate: avoid a transaction-consent subsystem until a buyer identifies a
  concrete gap not covered by its payment provider, runtime policy, and IAM.
* Commercial kill test: if an existing enterprise policy engine plus its
  durable audit path satisfies the buyer's independent-verification and
  incident-evidence requirements, the overlapping BESA workflow is DROP.

## Primary sources

* [AWS AgentCore policy conditions](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-conditions.html)
* [RSA Agent ID Secure](https://www.rsa.com/products/rsa-agent-id/secure/)
* [RSA Agent ID announcement](https://www.rsa.com/news/press-releases/rsa-agent-id/)
* [SailPoint Agentic Fabric](https://www.sailpoint.com/products/agentic-fabric)
* [Microsoft receipt proposal](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/proposals/verifiable-compliance-receipts.md)
* [Signet repository](https://github.com/Prismer-AI/signet)
* [Cloudflare MCP security](https://developers.cloudflare.com/agents/model-context-protocol/guides/securing-mcp-server/)
* [OpenAI ChatGPT Wallet](https://openai.com/index/introducing-chatgpt-wallet/)
* [OpenAI commerce payment guide](https://developers.openai.com/commerce/guides/accept-payments)
* [Visa Trusted Agent Protocol specification](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications/)
* [Mastercard Agent Pay paper](https://www.mastercard.com/content/dam/mccom/eu/news-and-trends/business-thought-leadership/digital-payments/pdfs/Get_ready_for_AI-powered_shopping_experiences.pdf)
* [American Express 2026 shareholder letter](https://www.americanexpress.com/content/dam/amex/en-us/newsroom/pdfs/AXP-2026-Chairmans-Letter-to-Shareholders.pdf)
* [WebMCP Community Group draft](https://webmachinelearning.github.io/webmcp/)
* [European Commission COM(2026) 1100 final proposal](https://commission.europa.eu/document/download/0575d59f-554f-4a9e-b54b-e6b717175809_en?filename=Proposal+for+a+Digital+Fairness+Act_0.pdf&prefLang=hu)
* [European Commission proposal annexes](https://commission.europa.eu/document/download/a0539d90-2758-48e5-9010-1e856030d166_en?filename=Annexes+to+the+Proposal+for+a+Digital+Fairness+Act.pdf)
* [European Parliament procedure 2026/0356(COD)](https://oeil.europarl.europa.eu/oeil/en/procedure-file?reference=2026%2F0356%28COD%29)
