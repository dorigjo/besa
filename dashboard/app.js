"use strict";

(() => {
  const MAX_BYTES = 262144;
  const state = { loaded: 0, valid: 0, rejected: 0, bundle: null, report: null };
  const byId = (id) => document.getElementById(id);
  const input = byId("bundle-input");
  const statusText = byId("live-message");

  function setMessage(message, error = false) {
    statusText.textContent = message;
    statusText.classList.toggle("error", error);
  }

  function showView(name) {
    document.querySelectorAll("[data-panel]").forEach((panel) => {
      panel.hidden = panel.dataset.panel !== name;
    });
    document.querySelectorAll("[data-view]").forEach((button) => {
      const active = button.dataset.view === name;
      button.classList.toggle("selected", active);
      if (active) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function row(parent, label, value) {
    const container = element("div", "detail-row");
    container.append(element("dt", "", label));
    const valueNode = element("dd", "", value === undefined || value === null ? "Not present in this artifact" :
      typeof value === "string" ? value : JSON.stringify(value, null, 2));
    container.append(valueNode);
    parent.append(container);
  }

  function download(name, data, type) {
    const blob = new Blob([data], { type });
    const url = URL.createObjectURL(blob);
    const anchor = element("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function updateCounts() {
    byId("count-loaded").textContent = String(state.loaded);
    byId("count-valid").textContent = String(state.valid);
    byId("count-rejected").textContent = String(state.rejected);
    byId("trust-configured").textContent = state.report?.verification?.issuerTrust?.status === "TRUSTED" ? "Yes" : "No";
  }

  function renderChecks(report) {
    const checks = byId("checks");
    checks.replaceChildren();
    const v = report.verification;
    const fields = report.format === "PRE_EXECUTION_ADMISSION_V1" ? [
      ["Signed admission and bound context", v.admissionVerification.valid ? "VALID" : v.admissionVerification.reasonCode],
      ["Admission issuer trust", v.issuerTrust.status],
      ["Exact request digest", v.requestBinding],
      ["Action and parameters", v.actionBinding],
      ["Policy identity and digest", v.policyBinding],
      ["External authority", v.authority],
      ["Delegation chain", v.delegation],
      ["Current execution authorization", v.currentAdmission.authorized ? "AUTHORIZED" : v.currentAdmission.reasonCode],
      ["Expiry", v.expiry],
      ["Execution evidence", v.executionEvidence.status],
    ] : [
      ["Manifest signature", v.manifestSignature.valid ? "VALID" : v.manifestSignature.reasonCode],
      ["Receipt signature", v.receiptSignature.valid ? "VALID" : v.receiptSignature.reasonCode],
      ["Manifest link", v.manifestHashMatches ? "MATCH" : "MISMATCH"],
      ["Declared tool", v.toolDeclared ? "MATCH" : "NOT FOUND"],
      ["Request binding", v.requestBinding],
      ["Issuer trust", v.issuerTrust.status],
    ];
    for (const [label, value] of fields) {
      const item = element("div", "check");
      item.append(element("span", "", label), element("strong", "", value));
      checks.append(item);
    }
  }

  function renderDetails(report) {
    const action = report.action;
    const detail = byId("action-detail");
    detail.replaceChildren();
    const isAdmission = report.format === "PRE_EXECUTION_ADMISSION_V1";
    const actionRows = isAdmission ? [
      ["Decision", action.decision], ["Reason code", action.reasonCode], ["Principal", action.principalId],
      ["Agent", action.agentId], ["Tool", action.toolName], ["Operation", action.operation],
      ["Resource", action.resource], ["Exact parameters", action.parameters], ["Execution context", action.context],
      ["Audience", action.audience], ["Policy", `${action.policyId ?? "unknown"} / v${action.policyVersion ?? "unknown"}`],
      ["Policy digest", action.policyHash], ["Delegation digest", action.delegationHash],
      ["Request digest", action.requestHash], ["Receipt ID", action.receiptId],
      ["Signer key ID", action.publicKeyId], ["Issued at", action.timestamp], ["Expires at", action.expiresAt],
    ] : [
      ["Server", action.serverName], ["Tool", action.toolName], ["Decision", action.decision],
      ["Reason code", action.reasonCode], ["Agent", action.agentId], ["Receipt ID", action.receiptId],
      ["Timestamp", action.timestamp], ["Manifest digest", action.manifestHash],
      ["Request digest", action.requestHash], ["Public key ID", action.publicKeyId], ["Supplied request", action.request],
    ];
    for (const [label, value] of actionRows) row(detail, label, value);

    const verification = byId("verification-detail");
    verification.replaceChildren();
    const verificationRows = isAdmission ? [
      ["Overall", report.overall], ["Admission verification", report.verification.admissionVerification.reasonCode],
      ["Issuer trust", report.verification.issuerTrust.status], ["Admission now executable", report.verification.currentAdmission.authorized],
      ["Request / action / policy", `${report.verification.requestBinding} / ${report.verification.actionBinding} / ${report.verification.policyBinding}`],
      ["Authority", report.verification.authority], ["Delegation", report.verification.delegation],
      ["Expiry", report.verification.expiry], ["Execution evidence", report.verification.executionEvidence.status],
      ["Evidence detail", report.verification.executionEvidence.reasonCode],
    ] : [
      ["Overall", report.overall], ["Manifest signature", report.verification.manifestSignature.reasonCode],
      ["Receipt signature", report.verification.receiptSignature.reasonCode],
      ["Manifest binding", report.verification.manifestHashMatches ? "MATCH" : "MISMATCH"],
      ["Action parameter binding", report.verification.requestBinding], ["Issuer trust", report.verification.issuerTrust.status],
      ["Issuer trust reason", report.verification.issuerTrust.reasonCode], ["Decision", action.decision],
      ["Reason code", action.reasonCode], ["Evidence linkage", "No execution-result evidence supplied"],
    ];
    for (const [label, value] of verificationRows) row(verification, label, value);

    const timeline = byId("timeline");
    timeline.replaceChildren();
    const events = isAdmission ? [
      ["Bundle loaded", "Artifact parsed locally; no persistent copy created."],
      ["Admission checked", report.verification.admissionVerification.reasonCode],
      ["Authority / delegation", `${report.verification.authority} / ${report.verification.delegation}`],
      ["Exact request and policy", `${report.verification.requestBinding} / ${report.verification.policyBinding}`],
      ["Current execution gate", report.verification.currentAdmission.authorized ? "Would admit at verification time" : report.verification.currentAdmission.reasonCode],
      ["Execution", "Not established by an admission receipt."],
    ] : [
      ["Bundle loaded", "Artifact bytes parsed locally; no persistent copy created."],
      ["Manifest checked", report.verification.manifestSignature.reasonCode],
      ["Receipt checked", report.verification.receiptSignature.reasonCode],
      ["Request binding", report.verification.requestBinding],
      ["Issuer trust", `${report.verification.issuerTrust.status}: ${report.verification.issuerTrust.reasonCode}`],
      ["Execution", "Not established by an admission receipt."],
    ];
    events.forEach(([title, detailText]) => {
      const item = element("li");
      const time = element("span", "timeline-time", "Artifact time not supplied");
      const copy = element("div");
      copy.append(element("strong", "", title), element("p", "", detailText));
      item.append(time, copy);
      timeline.append(item);
    });
    byId("decision-status").textContent = action.decision ? action.decision.toUpperCase() : "No decision";
    byId("decision-status").className = `status ${action.decision === "allow" ? "valid" : action.decision === "deny" ? "invalid" : "neutral"}`;
    byId("disclaimer").textContent = report.disclaimer;
    byId("result-summary").hidden = false;
    byId("overall-status").textContent = report.overall;
    byId("overall-status").className = `status ${report.overall === "VERIFIED" ? "valid" : report.overall === "INVALID" ? "invalid" : "partial"}`;
    renderChecks(report);
  }

  async function verify() {
    const raw = input.value;
    if (new TextEncoder().encode(raw).byteLength > MAX_BYTES) {
      state.loaded += 1; state.rejected += 1; updateCounts();
      setMessage("Bundle exceeds the 256 KiB limit.", true);
      return;
    }
    if (!raw.trim()) {
      setMessage("Load a signed bundle first.", true);
      input.focus();
      return;
    }
    byId("verify-bundle").disabled = true;
    setMessage("Verifying locally…");
    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: raw,
        cache: "no-store",
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Verification request failed");
      state.bundle = raw;
      state.report = body;
      state.loaded += 1;
      if (body.overall === "VERIFIED") state.valid += 1;
      else state.rejected += 1;
      updateCounts();
      renderDetails(body);
      setMessage(`${body.overall}: verification result is based on the loaded bundle and supplied trust store.`);
    } catch (error) {
      state.loaded += 1; state.rejected += 1; updateCounts();
      setMessage(error instanceof Error ? error.message : "Verification failed.", true);
    } finally {
      byId("verify-bundle").disabled = false;
    }
  }

  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.view));
  });
  byId("verify-bundle").addEventListener("click", verify);
  byId("load-sample").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/sample", { cache: "no-store" });
      if (!response.ok) throw new Error("Sample fixture is unavailable.");
      input.value = JSON.stringify(await response.json(), null, 2);
      setMessage("Signed public test fixture loaded. Its included trust anchor is demo configuration, not an external trust endorsement.");
      input.focus();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Sample load failed.", true); }
  });
  byId("load-admission-sample").addEventListener("click", async () => {
    try {
      const response = await fetch("/api/sample-admission", { cache: "no-store" });
      if (!response.ok) throw new Error("Admission fixture could not be generated.");
      input.value = JSON.stringify(await response.json(), null, 2);
      setMessage("Fresh signed local admission sample loaded. Its ephemeral included trust anchors are test configuration only.");
      input.focus();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Admission sample failed.", true); }
  });
  byId("clear-bundle").addEventListener("click", () => {
    input.value = "";
    byId("result-summary").hidden = true;
    state.bundle = null; state.report = null;
    setMessage("Current bundle cleared from the page.");
  });
  byId("bundle-file").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_BYTES) { setMessage("Selected file exceeds the 256 KiB limit.", true); return; }
    input.value = await file.text();
    setMessage(`${file.name} loaded into this page. It has not been verified yet.`);
  });
  byId("export-json").addEventListener("click", () => {
    if (!state.report) return;
    const safeReport = {
      overall: state.report.overall,
      verification: state.report.verification,
      action: {
        ...state.report.action,
        parameters: state.report.action.parameters === undefined ? undefined : "OMITTED_FROM_EXPORT",
        context: state.report.action.context === undefined ? undefined : "OMITTED_FROM_EXPORT",
        request: state.report.action.request === undefined ? undefined : "OMITTED_FROM_EXPORT",
      },
      disclaimer: state.report.disclaimer,
      exportNote: "Request parameters are omitted to reduce accidental disclosure.",
    };
    download("besa-verification-report.json", JSON.stringify(safeReport, null, 2), "application/json");
  });
  byId("export-text").addEventListener("click", () => {
    if (!state.report) return;
    const r = state.report;
    const lines = r.format === "PRE_EXECUTION_ADMISSION_V1" ? [
      `BESA pre-execution admission: ${r.overall}`,
      `Decision: ${r.action.decision ?? "unknown"} (${r.action.reasonCode ?? "no reason code"})`,
      `Tool / operation / resource: ${r.action.toolName ?? "unknown"} / ${r.action.operation ?? "unknown"} / ${r.action.resource ?? "unknown"}`,
      `Admission verification: ${r.verification.admissionVerification.reasonCode}`,
      `Request / action / policy binding: ${r.verification.requestBinding} / ${r.verification.actionBinding} / ${r.verification.policyBinding}`,
      `Issuer trust: ${r.verification.issuerTrust.status} (${r.verification.issuerTrust.reasonCode})`,
      `Current execution authorization: ${r.verification.currentAdmission.authorized}`,
      `Execution evidence: ${r.verification.executionEvidence.status}`,
      "Request parameters omitted.",
      r.disclaimer,
    ] : [
      `BESA verification: ${r.overall}`,
      `Decision: ${r.action.decision ?? "unknown"} (${r.action.reasonCode ?? "no reason code"})`,
      `Tool: ${r.action.toolName ?? "unknown"}`,
      `Manifest signature: ${r.verification.manifestSignature.reasonCode}`,
      `Receipt signature: ${r.verification.receiptSignature.reasonCode}`,
      `Request binding: ${r.verification.requestBinding}`,
      `Issuer trust: ${r.verification.issuerTrust.status} (${r.verification.issuerTrust.reasonCode})`,
      "Request parameters omitted.",
      r.disclaimer,
    ];
    download("besa-verification-report.txt", lines.join("\n"), "text/plain;charset=utf-8");
  });
  byId("export-bundle").addEventListener("click", () => {
    if (!state.bundle) return;
    if (!window.confirm("The original bundle may contain sensitive parameters. Export it only to a secure location. Continue?")) return;
    download("besa-signed-bundle.json", state.bundle, "application/json");
  });
  byId("run-simulator").addEventListener("click", async () => {
    const button = byId("run-simulator");
    button.disabled = true;
    const results = byId("simulator-results");
    results.replaceChildren(element("p", "empty-state", "Running in-memory SDK scenarios…"));
    try {
      const response = await fetch("/api/simulate", { method: "POST", cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Simulation failed");
      results.replaceChildren();
      for (const scenario of body.scenarios) {
        const item = element("section", "simulation-row");
        item.append(element("h2", "", `${scenario.operation} · ${scenario.resource}`));
        item.append(element("p", "", `Decision: ${scenario.decision} (${scenario.reasonCode})`));
        item.append(element("p", "", `Mock executor called: ${scenario.executorCalled ? "yes" : "no"}`));
        item.append(element("p", "", `Evidence verification: ${scenario.evidenceVerified ? "valid" : "not produced/invalid"}`));
        results.append(item);
      }
      results.append(element("p", "warning-note", body.limitation));
      setMessage("Local scenarios completed. No external side effect was attempted.");
    } catch (error) {
      results.replaceChildren(element("p", "error", error instanceof Error ? error.message : "Simulation failed."));
      setMessage("Local simulation failed.", true);
    } finally { button.disabled = false; }
  });

  fetch("/api/health", { cache: "no-store" }).then((response) => response.json()).then((health) => {
    byId("service-state").textContent = health.status === "ok" ? "Connected" : "Unavailable";
  }).catch(() => { byId("service-state").textContent = "Unavailable"; });
})();
