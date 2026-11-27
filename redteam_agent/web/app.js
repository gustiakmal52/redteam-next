/**
 * CYBER RECON & DEEP EXPLOIT COMMAND CENTER - Client Logic
 * Real-time SSE streaming, multi-stage pipeline state, asset explorer,
 * BaaS RLS auditor, interactive sandbox, and HackerOne report builder.
 */

let currentTaskId = null;
let eventSource = null;
let currentResults = null;
let loadedAuthContext = null;
let loadedEngagement = null;
let loadedRequestCorpus = null;
let loadedRequestCorpusName = "dashboard_capture";

let pendingAnalyzeFile = null;
let lastAnalyzeReport = null;

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initPresets();
  initTheme();
  initScanLauncher();
  initAuthContext();
  initEngagement();
  initRequestCorpus();
  initTerminalActions();
  initDirectBaas();
  initSandbox();
  initReportActions();
  initExportAnalyzer();
  initSurfaceFilter();
  initWebAuth().then(authenticated => {
    if (authenticated) loadRecentScans();
  });
});

async function initWebAuth() {
  const overlay = document.getElementById("web-auth-overlay");
  const form = document.getElementById("web-auth-form");
  const tokenInput = document.getElementById("web-auth-token");
  const error = document.getElementById("web-auth-error");
  try {
    const statusResponse = await fetch("/api/auth/status", { credentials: "same-origin" });
    const status = await statusResponse.json();
    if (!status.required || status.authenticated) return true;
    if (!overlay || !form) return false;
    overlay.hidden = false;
    form.addEventListener("submit", async event => {
      event.preventDefault();
      error.textContent = "";
      try {
        const response = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ token: tokenInput.value })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Authentication failed");
        overlay.hidden = true;
        loadRecentScans();
      } catch (err) {
        error.textContent = err.message;
      }
    });
    tokenInput.focus();
    return false;
  } catch (err) {
    if (error) error.textContent = `Dashboard auth check failed: ${err.message}`;
    return false;
  }
}

/* ========================================================================= */
/* THEME TOGGLE (localStorage-persisted, tactical dark by default) */
/* ========================================================================= */
function initTheme() {
  const btn = document.getElementById("btn-theme");
  const stored = localStorage.getItem("rt_theme") || "dark";
  applyTheme(stored);
  btn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    localStorage.setItem("rt_theme", next);
    applyTheme(next);
  });
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const btn = document.getElementById("btn-theme");
  if (btn) btn.textContent = theme === "dark" ? "Light" : "Dark";
}

/* ========================================================================= */
/* TOAST NOTIFICATIONS (replaces alert) */
/* ========================================================================= */
function toast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) { alert(message); return; }
  const el = document.createElement("div");
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => { el.classList.add("toast-out"); setTimeout(() => el.remove(), 300); }, 3400);
}

/* ========================================================================= */
/* TAB NAVIGATION */
/* ========================================================================= */
function initTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      
      tabButtons.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      
      btn.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

function switchTab(tabId) {
  const btn = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  if (btn) btn.click();
}

/* ========================================================================= */
/* PRESET SELECTION */
/* ========================================================================= */
function initPresets() {
  const presetLabels = document.querySelectorAll(".preset-card");
  presetLabels.forEach(label => {
    label.addEventListener("click", () => {
      presetLabels.forEach(l => l.classList.remove("selected"));
      label.classList.add("selected");
    });
  });
}

/* ========================================================================= */
/* ATTACK SURFACE FILTER */
/* ========================================================================= */
function initSurfaceFilter() {
  const input = document.getElementById("surface-filter");
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    document.querySelectorAll("#hosts-tbody tr, #endpoints-tbody tr").forEach(row => {
      const hay = (row.textContent || "").toLowerCase();
      row.style.display = (!q || hay.includes(q)) ? "" : "none";
    });
  });
}

/* Researcher-owned auth context. Values are sent only to the in-memory task
 * when the operator explicitly selects a JSON file; they are never rendered. */
function initAuthContext() {
  const input = document.getElementById("auth-context-file");
  const status = document.getElementById("auth-context-status");
  if (!input) return;
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("root must be an object");
      loadedAuthContext = parsed;
      const identities = parsed.identities && typeof parsed.identities === "object" ? Object.keys(parsed.identities) : [];
      status.textContent = `Loaded in memory: ${identities.length} identity label(s); credential values remain redacted.`;
      status.className = "text-dim";
    } catch (err) {
      loadedAuthContext = null;
      status.textContent = `Auth context rejected: ${err.message}`;
      status.className = "text-dim";
    }
  });
}

/* Program policy or audit scope metadata; retain only its reference here. */
function initEngagement() {
  const input = document.getElementById("engagement-file");
  const status = document.getElementById("engagement-status");
  if (!input) return;
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("root must be an object");
      loadedEngagement = parsed;
      status.textContent = `Loaded: ${parsed.engagement_id || "missing ID"}; policy ${parsed.authorization_reference || parsed.authorization_ref || "missing reference"}; expires ${parsed.expires_at || "ongoing"}.`;
      status.className = "text-dim";
    } catch (err) {
      loadedEngagement = null;
      status.textContent = `Engagement rejected: ${err.message}`;
      status.className = "text-dim";
    }
  });
}

function initRequestCorpus() {
  const input = document.getElementById("request-corpus-file");
  const status = document.getElementById("request-corpus-status");
  if (!input) return;
  input.addEventListener("change", async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed || typeof parsed !== "object") throw new Error("root must be a HAR object, request object, or list");
      loadedRequestCorpus = parsed;
      loadedRequestCorpusName = file.name || "dashboard_capture";
      const entries = Array.isArray(parsed) ? parsed.length :
        (parsed.log?.entries?.length ?? parsed.requests?.length ?? 0);
      status.textContent = `Loaded in memory: ${entries} captured request(s) from ${loadedRequestCorpusName}.`;
      status.className = "text-dim";
    } catch (err) {
      loadedRequestCorpus = null;
      status.textContent = `Request corpus rejected: ${err.message}`;
      status.className = "text-dim";
    }
  });
}

/* ========================================================================= */
/* SCAN LAUNCHER & REAL-TIME SSE */
/* ========================================================================= */
function initScanLauncher() {
  const btnStart = document.getElementById("btn-start-scan");
  const inputTarget = document.getElementById("input-target");    btnStart.addEventListener("click", async () => {
    const target = inputTarget.value.trim();
    if (!target) {
      toast("Enter a target domain or URL to start.", "warn");
      return;
    }

    const selectedPresetInput = document.querySelector('input[name="scan-preset"]:checked');
    const preset = selectedPresetInput ? selectedPresetInput.value : "full";
    const trafficPreset = document.getElementById("traffic-preset").value;
    const budgetRaw = document.getElementById("max-requests").value;
    const bypassBudget = Number(document.getElementById("bypass-budget").value || 40);
    const maxDepth = Number(document.getElementById("max-depth").value || 3);
    // The dashboard exposes one explicit offensive switch. The legacy CLI/API
    // alias remains accepted for compatibility but is not a second scan mode.
    const aggressive = false;
    // The exploit presets are offensive by definition; the checkbox enables
    // the same planner for the other presets without changing scope rules.
    const offensive = document.getElementById("offensive-mode")?.checked ||
      preset === "active_exploit" || preset === "deep_bypass";
    const deepAssets = document.getElementById("deep-assets-mode")?.checked || false;
    const secretDiscovery = document.getElementById("secret-discovery-mode")?.checked || false;
    const authFlow = document.getElementById("auth-flow-mode")?.checked || false;
    const sourceMaps = document.getElementById("source-maps-mode")?.checked || false;
    const browserVerify = document.getElementById("browser-verify-mode")?.checked || false;
    const splitRules = id => document.getElementById(id).value.split(",").map(v => v.trim()).filter(Boolean);
    const scopeInclude = splitRules("scope-include");
    const scopeExclude = splitRules("scope-exclude");
    const objective = document.getElementById("hunt-objective").value.trim();
    const vulnerabilityClasses = document.getElementById("vulnerability-classes").value
      .split(",").map(value => value.trim()).filter(Boolean);

    btnStart.disabled = true;
    btnStart.textContent = "INITIALIZING...";

    try {
      const resp = await fetch("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target, preset, traffic_preset: trafficPreset,
          max_requests: budgetRaw ? Number(budgetRaw) : null,
          bypass_budget: bypassBudget,
          max_depth: maxDepth,
          aggressive,
          offensive,
          deep_assets: deepAssets,
          secret_discovery: secretDiscovery,
          auth_flow: authFlow,
          source_maps: sourceMaps,
          browser_verify: browserVerify,
          auth_context: loadedAuthContext,
          engagement: loadedEngagement,
          objective,
          vulnerability_classes: vulnerabilityClasses,
          request_corpus: loadedRequestCorpus,
          request_corpus_source: loadedRequestCorpusName,
          scope_include: scopeInclude.length ? scopeInclude : null,
          scope_exclude: scopeExclude.length ? scopeExclude : null
        })
      });

      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Failed to start scan");

      currentTaskId = data.task_id;
      setGlobalStatus("SCANNING");
      
      // Clear terminal and switch to live terminal tab
      clearTerminal();
      switchTab("tab-terminal");
      document.getElementById("terminal-target-title").textContent = `SSE Console: ${target} [${preset}]`;
      
      // Reset pipeline stepper & progress
      updateProgress(5, "Pipeline Initialized");
      
      // Connect live SSE stream
      connectSSE(currentTaskId);
      
      // Refresh recent scans table
      loadRecentScans();
    } catch (err) {
      toast("Scan launch error: " + err.message, "error");
    } finally {
      btnStart.disabled = false;
      btnStart.textContent = "Start scan";
    }
  });
}

function setGlobalStatus(status) {
  const ind = document.getElementById("global-status-indicator");
  const txt = document.getElementById("global-status-text");

  ind.className = "status-indicator " + status.toLowerCase();
  txt.textContent = status.toUpperCase();
}

function connectSSE(taskId) {
  if (eventSource) {
    eventSource.close();
  }

  eventSource = new EventSource(`/api/stream/${taskId}`);

  eventSource.onmessage = (event) => {
    try {
      const log = JSON.parse(event.data);
      if (log.message === "[STREAM_END]") {
        eventSource.close();
        setGlobalStatus("COMPLETED");
        loadScanResults(taskId);
        loadRecentScans();
        return;
      }

      appendTerminalLine(log);

      if (log.progress !== undefined) {
        updateProgress(log.progress, log.step || "");
      }
    } catch (e) {
      console.error("SSE parse error", e);
    }
  };

  eventSource.onerror = () => {
    console.warn("SSE connection closed or re-connecting");
  };
}

function appendTerminalLine(log) {
  const term = document.getElementById("terminal-output");
  const div = document.createElement("div");
  const levelClass = (log.level || "info").toLowerCase();
  
  div.className = `term-line ${levelClass}`;
  div.textContent = `[${log.time || ""}] [${log.level || "INFO"}] ${log.message}`;
  
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;

  // Update tab badge count
  const badge = document.getElementById("badge-terminal");
  badge.textContent = parseInt(badge.textContent || 0) + 1;
}

function updateProgress(percent, stepName) {
  const fill = document.getElementById("pipeline-progress-fill");
  const txt = document.getElementById("pipeline-progress-text");
  
  fill.style.width = `${percent}%`;
  txt.textContent = `${percent}% - ${stepName}`;

  // Update visual stepper
  const steps = document.querySelectorAll(".pipeline-stepper .step");
  let activeStepIdx = 1;
  if (percent >= 90) activeStepIdx = 8;
  else if (percent >= 80) activeStepIdx = 7;
  else if (percent >= 70) activeStepIdx = 6;
  else if (percent >= 65) activeStepIdx = 5;
  else if (percent >= 50) activeStepIdx = 4;
  else if (percent >= 35) activeStepIdx = 3;
  else if (percent >= 20) activeStepIdx = 2;
  else activeStepIdx = 1;

  steps.forEach(s => {
    const sIdx = parseInt(s.getAttribute("data-step"));
    s.classList.remove("active", "done");
    if (sIdx < activeStepIdx) s.classList.add("done");
    else if (sIdx === activeStepIdx) s.classList.add("active");
  });
}

function clearTerminal() {
  const term = document.getElementById("terminal-output");
  term.replaceChildren();
  document.getElementById("badge-terminal").textContent = "0";
}

/* ------------------------------------------------------------------------- */
/* Safe DOM rendering                                                        */
/* ------------------------------------------------------------------------- */
function cell(value, className = "", kind = "text") {
  return { value: value == null ? "" : String(value), className, kind };
}

function buttonCell(label, handler) {
  return { label: String(label), handler };
}

function renderTable(tbody, rows, emptyText, colSpan) {
  if (!tbody) return;
  tbody.replaceChildren();
  if (!rows || !rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colSpan || 1;
    td.className = "empty-cell";
    td.textContent = emptyText;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach(specs => {
    const tr = document.createElement("tr");
    specs.forEach(spec => {
      const td = document.createElement("td");
      if (spec && spec.handler) {
        const button = document.createElement("button");
        button.className = "btn-sm";
        button.type = "button";
        button.textContent = spec.label;
        button.addEventListener("click", spec.handler);
        td.appendChild(button);
      } else {
        const item = spec || cell("");
        const child = document.createElement(item.kind === "code" ? "code" : item.kind === "strong" ? "strong" : item.kind === "badge" ? "span" : "span");
        if (item.kind === "badge") child.className = "badge-pill";
        child.textContent = item.value == null ? "" : String(item.value);
        td.appendChild(child);
      }
      if (spec && spec.className) td.className = spec.className;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}

function addText(parent, tag, text, className = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text == null ? "" : String(text);
  parent.appendChild(node);
  return node;
}

function addLabelValue(parent, label, value, className = "") {
  const p = document.createElement("p");
  const strong = document.createElement("strong");
  strong.textContent = `${label}: `;
  p.appendChild(strong);
  const span = document.createElement("span");
  if (className) span.className = className;
  span.textContent = value == null || value === "" ? "—" : String(value);
  p.appendChild(span);
  parent.appendChild(p);
  return p;
}

function addSafeCard(parent, title, fields = [], className = "vuln-card") {
  const card = document.createElement("div");
  card.className = className;
  card.style.marginBottom = "8px";
  const header = document.createElement("div");
  header.className = "vuln-card-header";
  addText(header, "h4", title);
  card.appendChild(header);
  fields.forEach(field => addLabelValue(card, field[0], field[1], field[2] || ""));
  parent.appendChild(card);
  return card;
}

function appendBadgeList(parent, values, className = "badge-pill") {
  (values || []).forEach(value => addText(parent, "span", value, className));
}

function initTerminalActions() {
  document.getElementById("btn-clear-term").addEventListener("click", clearTerminal);
  document.getElementById("btn-copy-term").addEventListener("click", () => {
    const term = document.getElementById("terminal-output");
    navigator.clipboard.writeText(term.innerText).then(() => {
      toast("Terminal logs copied to clipboard.");
    });
  });
}

/* ========================================================================= */
/* LOAD & POPULATE SCAN RESULTS */
/* ========================================================================= */
async function loadScanResults(taskId) {
  try {
    const resp = await fetch(`/api/scan/results/${taskId}`);
    if (!resp.ok) return;
    const res = await resp.json();
    currentResults = res;

    // Update Top Strip Metrics
    document.getElementById("stat-subdomains").textContent = res.stats.subdomains || 0;
    document.getElementById("stat-hosts").textContent = res.stats.live_hosts || 0;
    document.getElementById("stat-endpoints").textContent = res.stats.endpoints || 0;
    document.getElementById("stat-secrets").textContent = res.stats.secrets_found || 0;
    document.getElementById("stat-baas").textContent = res.stats.cloud_misconfigs || 0;
    document.getElementById("stat-vulns").textContent = res.stats.vulnerabilities || 0;

    // Update Tab Badges
    document.getElementById("badge-surface").textContent = (res.subdomains.length + res.endpoints.length);
    document.getElementById("badge-js").textContent = (res.js_assets.length);
    const web3 = res.web3_recon || {};
    document.getElementById("badge-web3").textContent =
      ((web3.rpc_endpoints || []).length + (web3.contracts || []).length + (web3.solana_accounts || []).length);
    const cloud = res.cloud_baas || {supabase: [], harvested_tokens: []};
    document.getElementById("badge-cloud").textContent =
      ((cloud.supabase || []).length + (cloud.firebase || []).length + (cloud.vercel || []).length + (cloud.harvested_tokens || []).length + (((res.hidden_assets || {}).baas_projects || []).length));
    document.getElementById("badge-vulns").textContent = (res.findings || res.vulnerabilities || []).length;
    const hidden = res.hidden_assets || {};
    const hiddenStats = hidden.stats || {};
    document.getElementById("badge-hidden-assets").textContent = hiddenStats.assets || (hidden.assets || []).length || 0;
    document.getElementById("badge-hidden-endpoints").textContent = hiddenStats.endpoints || (hidden.endpoints || []).length || 0;
    document.getElementById("badge-hidden-credentials").textContent = hiddenStats.credentials || (hidden.credentials || []).length || 0;
    document.getElementById("badge-hidden-auth").textContent = hiddenStats.auth_flows || (hidden.auth_flows || []).length || 0;
    document.getElementById("badge-hidden-maps").textContent = hiddenStats.source_maps || (hidden.source_maps || []).length || 0;
    const deepExploit = res.deep_exploit || {};
    document.getElementById("badge-deep-exploit").textContent =
      (deepExploit.primitives || []).length || (deepExploit.plan || []).length || 0;
    const recon = res.recon_depth || {};
    document.getElementById("badge-recon").textContent =
      ((recon.waf && recon.waf.detected && recon.waf.detected.length) || 0) +
      ((recon.tls && recon.tls.observed ? 1 : 0)) +
      ((recon.ports || []).length);

    // Populate Tab 3: Attack Surface
    populateAttackSurface(res);

    // Populate Tab 4: JS & API Vault
    populateJSVault(res);
    populateWeb3(res);

    // First-class hidden discovery views use the same redacted engine output
    // returned to CLI/export; no browser-side secret reconstruction occurs.
    populateHiddenDiscovery(res);
    populateDeepExploit(res);

    // Populate Tab 5: Cloud BaaS Center
    populateCloudBaaS(res);
    populateDatabase(res);

    // Populate Tab 6: Verified Vulnerabilities
    populateVulnerabilities(res);
    populatePolicy(res);

    // Populate Recon Depth tab
    populateReconDepth(res);

    // Populate Tab 8: HackerOne Markdown Report
    loadMarkdownReport(taskId);

  } catch (err) {
    console.error("Error fetching results", err);
  }
}

function populateHiddenDiscovery(res) {
  const hidden = res.hidden_assets || {};
  const assets = hidden.assets || [];
  const endpoints = hidden.endpoints || [];
  const credentials = hidden.credentials || [];
  const maps = hidden.source_maps || [];
  const flows = hidden.auth_flows || [];
  const stats = hidden.stats || {};

  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  setText("hidden-assets-count", stats.assets ?? assets.length);
  setText("hidden-js-count", stats.javascript_assets ?? assets.filter(a => (a.asset_type || "").includes("javascript") || ["module", "dynamic_chunk", "web_worker", "service_worker", "worker_asset"].includes(a.asset_type)).length);
  setText("hidden-runtime-count", (hidden.runtime_configs || []).length);
  setText("hidden-framework-count", (hidden.frameworks || []).length);

  renderTable(document.getElementById("hidden-assets-tbody"), assets.slice(0, 300).map(asset => [
    cell(asset.url, "", "code"), cell(asset.asset_type || "unknown", "", "badge"),
    cell(asset.parent || "—", "text-dim"), cell(asset.depth ?? "—"), cell(asset.framework || "—"),
    cell(asset.status || "UNKNOWN"), cell(asset.source_map_url ? "FOUND" : "—")
  ]), "No hidden assets analyzed yet.", 7);
  const frameworksBox = document.getElementById("hidden-frameworks-box");
  if (frameworksBox) frameworksBox.textContent = JSON.stringify({frameworks: hidden.frameworks || [], next: (hidden.integrations || {}).next || {}, coverage: hidden.coverage || {}}, null, 2);

  renderTable(document.getElementById("hidden-endpoints-tbody"), endpoints.slice(0, 300).map(endpoint => {
    const headerNames = Object.keys(endpoint.headers || {});
    const fields = (endpoint.body_shape || {}).fields || [];
    return [cell(endpoint.method || "GET", "", "badge"), cell(endpoint.url, "", "code"),
      cell(endpoint.request_type || "REST"), cell(endpoint.auth_required ? "AUTH" : "—"),
      cell(headerNames.join(", ") || "—"), cell(fields.join(", ") || "—"),
      cell(`${endpoint.source_file || "unknown"} : ${endpoint.source_line ?? "—"}`, "text-dim"),
      cell(Number(endpoint.confidence || 0).toFixed(2))];
  }), "No hidden endpoints extracted yet.", 8);

  renderTable(document.getElementById("hidden-credentials-tbody"), credentials.map(credential => [
    cell(credential.credential_type || "UNKNOWN_TOKEN", "", "strong"), 
    cell(credential.provider || "unknown"),
    cell(credential._raw_value || credential.masked_value || "—", "", "code"), 
    cell(`${credential.status || "CANDIDATE"}${credential.public ? " · PUBLIC" : ""}`),
    cell(`${credential.source_file || credential.source_url || "unknown"} : ${credential.source_line ?? "—"}`, "text-dim"),
    cell((credential.linked_endpoints || []).join(", ") || "—"),
    cell((credential.verification || {}).status || (credential.reason || "Not validated"))
  ]), "No credential references analyzed yet.", 7);

  const authBox = document.getElementById("hidden-auth-flows");
  if (authBox) {
    authBox.replaceChildren();
    if (!flows.length) addText(authBox, "p", "No auth flow analyzed yet.", "empty-cell");
    flows.forEach(flow => {
      const card = addSafeCard(authBox, flow.flow_id || "auth-flow", [
        ["Runtime observed", flow.runtime_observed ? "yes (researcher-owned context)" : "no — static graph"],
        ["Confidence", Number(flow.confidence || 0).toFixed(2)],
        ["Edges", (flow.edges || []).map(edge => `${edge.from} → ${edge.to} (${edge.relationship})`).join("; ") || "—"]
      ]);
      addLabelValue(card, "Nodes", (flow.nodes || []).map(node => `${node.node_type}: ${node.label}`).join(" · ") || "—");
    });
  }

  renderTable(document.getElementById("hidden-maps-tbody"), maps.map(map => [
    cell(map.map_url, "", "code"), cell(map.parent_asset || "—", "text-dim"), cell(map.status || "UNKNOWN"),
    cell((map.sources || []).length), cell(map.sources_content_count ?? 0), cell(`${(map.evidence || []).length} source trace(s)`)
  ]), "No source maps parsed yet.", 6);
}

function populateDeepExploit(res) {
  const report = res.deep_exploit || {};
  const plan = report.plan || [];
  const attempts = report.reports || [];
  const primitives = report.primitives || [];
  const chains = report.chains || [];
  const focus = report.focus || {};
  
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  setText("deep-exploit-hypotheses", plan.length);
  setText("deep-exploit-requests", report.requests_used || 0);
  setText("deep-exploit-primitives", primitives.length);
  setText("deep-exploit-chains", chains.length);
  
  // Intelligence enrichment stats
  const intelEnriched = focus.intelligence_enriched_hypotheses || 0;
  setText("deep-exploit-intel-enriched", intelEnriched);
  
  // Update intelligence status panel
  setText("intel-auto-enrich", intelEnriched > 0
    ? `Applied (${intelEnriched} target-matched)` : "Observed fields only");

  renderTable(document.getElementById("deep-exploit-plan-tbody"), plan.slice(0, 300).map(item => [
    cell(item.technique || "unknown", "", "strong"), cell(item.method || "GET", "", "badge"),
    cell(item.endpoint || "unknown", "", "code"), cell(item.field || "route-level"),
    cell(`${item.source_file || "unknown"} : ${item.source_line ?? "—"}`, "text-dim"), cell(item.identity || "anonymous")
  ]), "No offensive plan executed yet.", 6);

  const reportsBox = document.getElementById("deep-exploit-reports");
  if (reportsBox) {
    reportsBox.replaceChildren();
    if (!attempts.length) addText(reportsBox, "p", "No active attempts recorded yet.", "empty-cell");
    attempts.slice(0, 300).forEach(item => {
      const hypothesis = item.hypothesis || {};
      const finding = item.finding || {};
      const auth = item.authorization || {};
      const bypass = item.bypass || {};
      const status = item.status || bypass.status || auth.status || "unknown";
      const detail = finding.type
        ? `${finding.type} / ${finding.status || "unknown"}`
        : (auth.strategy ? `${auth.strategy} / ${auth.verified_primitives?.length || 0} verified primitive(s)`
          : (bypass.protection?.detected || []).join(", ") || "response ledger recorded");
      addSafeCard(reportsBox, `${hypothesis.technique || "attempt"} — ${hypothesis.endpoint || "unknown"}`,
        [["Status", status], ["Request", `${hypothesis.method || "GET"} · field ${hypothesis.field || "route-level"} · identity ${hypothesis.identity || "anonymous"}`],
         ["Evidence", detail], ["Requests used", item.requests_used || 0]]);
    });
  }

  const primitivesBox = document.getElementById("deep-exploit-primitives-box");
  if (primitivesBox) {
    primitivesBox.textContent = JSON.stringify({
      mode: report.mode || "unknown",
      primitives,
      chains,
    }, null, 2);
  }
}

function populateAttackSurface(res) {
  const hostsTbody = document.getElementById("hosts-tbody");
  const endpointsTbody = document.getElementById("endpoints-tbody");
  const filterInput = document.getElementById("surface-filter");

  // Hosts
  renderTable(hostsTbody, (res.live_hosts || []).map(h => [
    cell(h.host || h.url, "", "strong"), cell(h.status_code || "UNKNOWN"), cell(h.title || "-"),
    cell((h.tech || []).join(" · ") || "-"),
    buttonCell("Test in Sandbox", () => sendToSandbox(h.url))
  ]), "No live hosts detected.", 5);

  // Endpoints
  renderTable(endpointsTbody, (res.endpoints || []).map(u => [
    cell(u, "", "code"), buttonCell("Audit", () => sendToSandbox(u))
  ]), "No endpoints harvested.", 2);

  document.getElementById("surface-count").textContent = `${res.live_hosts.length} hosts / ${res.endpoints.length} endpoints`;
}

function populateJSVault(res) {
  const bundlesTbody = document.getElementById("js-bundles-tbody");
  const apiTbody = document.getElementById("api-routes-tbody");
  const paramsBox = document.getElementById("hidden-params-badges");

  document.getElementById("js-count-files").textContent = res.js_assets.length;
  document.getElementById("js-count-maps").textContent = res.js_assets.filter(j => j.has_sourcemap).length;
  document.getElementById("js-count-routes").textContent = res.stats.endpoints || 0;
  document.getElementById("js-count-params").textContent = (res.hidden_params || []).length;

  renderTable(bundlesTbody, (res.js_assets || []).map(j => [
    cell(j.filename, "", "code"), cell(`${j.size_kb} KB`), cell(j.has_sourcemap ? ".map FOUND" : "No map"),
    cell(j.routes_found), cell(j.secrets_found)
  ]), "No JS bundles found.", 5);

  // Hidden Params
  paramsBox.replaceChildren();
  if (res.hidden_params && res.hidden_params.length > 0) {
    res.hidden_params.forEach(p => {
      const badge = addText(paramsBox, "button", p, "badge-pill");
      badge.type = "button";
      badge.addEventListener("click", () => setSandboxParam(p));
    });
  } else addText(paramsBox, "span", "No hidden parameters discovered in JS AST.", "empty-cell");

  // API call trace (fetch / axios / XHR / WebSocket)
  const apiTraceTbody = document.getElementById("api-trace-tbody");
  const apiCalls = res.js_api_trace || [];
  document.getElementById("api-trace-count").textContent = `${apiCalls.length} calls`;
  renderTable(apiTraceTbody, apiCalls.slice(0, 100).map(c => [
    cell(c.call_type, "", "badge"), cell(c.method, "", "badge"), cell(c.url, "", "code"),
    cell(c.source, "text-dim"), buttonCell("Audit", () => sendToSandbox(c.url))
  ]), "No API calls traced yet.", 5);

  // JS regex grep matches
  const grepTbody = document.getElementById("js-grep-tbody");
  const grepMatches = res.js_grep || [];
  document.getElementById("js-grep-count").textContent = `${grepMatches.length} matches`;
  renderTable(grepTbody, grepMatches.slice(0, 100).map(g => [
    cell(g.pattern, "", "badge"), cell(g.value, "", "code"), cell(g.source, "text-dim"), cell(g.context, "text-dim")
  ]), "No grep matches yet.", 4);
}

function populateWeb3(res) {
  const web3 = res.web3_recon || {};
  const stats = web3.stats || {};
  const contracts = web3.contracts || [];
  const solana = web3.solana_accounts || [];
  const abi = web3.abi_functions || [];
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
  setText("web3-rpc-count", stats.rpc_verified || 0);
  setText("web3-contract-count", stats.contracts_verified || 0);
  setText("web3-proxy-count", stats.proxies_verified || 0);
  setText("web3-program-count", stats.solana_programs_verified || 0);
  setText("web3-abi-count", `${abi.length} functions`);

  renderTable(document.getElementById("web3-rpc-tbody"), (web3.rpc_endpoints || []).map(rpc => [
    cell(rpc.protocol || "unknown", "", "badge"), cell(rpc.chain_id ?? rpc.node_version ?? "—"),
    cell(rpc.url || "—", "", "code"), cell(rpc.status || "CANDIDATE"),
    cell((rpc.sources || [rpc.source]).filter(Boolean).join(", ") || "—", "text-dim")
  ]), "No Web3 RPC evidence yet.", 5);

  const contractRows = contracts.map(contract => [
    cell("EVM", "", "badge"), cell(contract.address, "", "code"), cell(contract.chain_id ?? "—"),
    cell(contract.status || "CANDIDATE"), cell((contract.proxy || {}).implementation || "—", "", "code"),
    cell((contract.sources || [contract.source]).filter(Boolean).join(", ") || "—", "text-dim")
  ]).concat(solana.map(account => [
    cell(account.executable ? "SOLANA PROGRAM" : "SOLANA ACCOUNT", "", "badge"), cell(account.address, "", "code"),
    cell(account.owner || "—", "", "code"), cell(account.status || "CANDIDATE"), cell("—"),
    cell((account.sources || [account.source]).filter(Boolean).join(", ") || "—", "text-dim")
  ]));
  renderTable(document.getElementById("web3-contract-tbody"), contractRows,
    "No contract or program evidence yet.", 6);
  renderTable(document.getElementById("web3-abi-tbody"), abi.map(item => [
    cell(item.signature || item.name, "", "code"), cell((item.surface_tags || []).join(", ") || "—"),
    cell((item.sources || [item.source]).filter(Boolean).join(", ") || "—", "text-dim")
  ]), "No ABI functions extracted yet.", 3);
}

function populateReconDepth(res) {
  const recon = res.recon_depth || {};

  // WAF
  const wafBox = document.getElementById("waf-result");
  const waf = recon.waf || {};
  const wafDetected = waf.detected || [];
  document.getElementById("recon-waf-card").textContent = wafDetected.length ? wafDetected.length : "—";
  wafBox.replaceChildren();
  if (wafDetected.length > 0) {
    appendBadgeList(wafBox, wafDetected);
    addText(wafBox, "p", `Evidence: ${JSON.stringify(waf.evidence || {})}`, "mt-4 text-dim");
  } else addText(wafBox, "p", `No known WAF signatures observed. ${waf.observed ? "" : "(no detection run)"}`, "empty-cell");

  // TLS
  const tlsBox = document.getElementById("tls-result");
  const tls = recon.tls || {};
  document.getElementById("recon-tls-card").textContent = tls.observed ? (tls.not_after || "cert") : "—";
  tlsBox.replaceChildren();
  if (tls.observed) {
    addLabelValue(tlsBox, "Host", tls.host || "");
    addLabelValue(tlsBox, "Issuer", JSON.stringify(tls.issuer || ""));
    addLabelValue(tlsBox, "Expires", `${tls.not_after || "unknown"}${tls.expiring_soon ? " · EXPIRING SOON" : ""}`);
    addLabelValue(tlsBox, `SANs (${(tls.san || []).length})`, (tls.san || []).join(" · "));
  } else addText(tlsBox, "p", `No TLS certificate data observed (${tls.note || "not inspected"}).`, "empty-cell");

  // Ports
  const portsTbody = document.getElementById("ports-tbody");
  const ports = recon.ports || [];
  document.getElementById("recon-ports-card").textContent = ports.length;
  renderTable(portsTbody, ports.map(p => [cell(p.host, "", "code"), cell(p.port, "", "strong"), cell(p.state || "open", "", "badge"), cell(p.source || "naabu", "text-dim")]),
    "No open ports observed (install naabu to enable scanning).", 4);

  // Tech stack counter
  const techCount = new Set((res.live_hosts || []).flatMap(h => h.tech || [])).size;
  document.getElementById("recon-tech-card").textContent = techCount;
}

function populateDatabase(res) {
  const db = res.db_hunter || {};
  const strings = db.connection_strings || [];
  const ports = db.exposed_ports || [];
  const adminPanels = db.admin_panels || [];
  const backupFiles = db.backup_files || [];
  const hiddenStrings = db.hidden_db_strings || [];

  document.getElementById("db-strings-count").textContent = `${strings.length} found`;
  const stringsTbody = document.getElementById("db-strings-tbody");
  renderTable(stringsTbody, strings.map(s => [cell(s.scheme, "", "badge"), cell(s.masked, "", "code"), cell(s.source, "text-dim"), cell(s.has_credentials ? "YES" : "no"), cell(`${s.host || ""}${s.port ? ":" + s.port : ""}`, "text-dim")]),
    "No database connection strings detected.", 5);

  document.getElementById("db-ports-count").textContent = `${ports.length} open`;
  const portsTbody = document.getElementById("db-ports-tbody");
  renderTable(portsTbody, ports.map(p => [cell(p.host, "", "code"), cell(p.port, "", "strong"), cell(p.service, "", "badge"), cell(p.state || "open", "", "badge"), cell(p.fingerprinted ? "HIDDEN" : "standard")]),
    "No database ports observed.", 5);

  document.getElementById("db-admin-count").textContent = `${adminPanels.length} found`;
  const adminTbody = document.getElementById("db-admin-tbody");
  renderTable(adminTbody, adminPanels.map(a => [cell(a.url, "", "code"), cell(a.panel, "", "badge")]), "No web DB admin panels found.", 2);

  document.getElementById("db-backup-count").textContent = `${backupFiles.length} found`;
  const backupTbody = document.getElementById("db-backup-tbody");
  renderTable(backupTbody, backupFiles.map(b => [cell(b.url, "", "code"), cell((b.markers || []).join(", "), "text-dim")]), "No downloadable SQL dump/backup files found.", 2);

  document.getElementById("db-hidden-count").textContent = `${hiddenStrings.length} found`;
  const hiddenTbody = document.getElementById("db-hidden-tbody");
  renderTable(hiddenTbody, hiddenStrings.map(s => [cell(s.scheme, "", "badge"), cell(s.masked, "", "code"), cell(s.source, "text-dim")]),
    "No hidden DB connection strings detected in page HTML.", 3);
}

function populateCloudBaaS(res) {
  const baasBox = document.getElementById("baas-deployments-container");
  const vercelBox = document.getElementById("vercel-deployments-container");
  const secretsTbody = document.getElementById("secrets-tbody");
  const cloud = res.cloud_baas || {};
  const hiddenProjects = ((res.hidden_assets || {}).baas_projects || []);

  // Vercel deployments
  const vercel = cloud.vercel || [];
  document.getElementById("vercel-count").textContent = `${vercel.length} audited`;
  vercelBox.replaceChildren();
  if (!vercel.length) addText(vercelBox, "p", "No Vercel deployments discovered.", "empty-cell");
  vercel.forEach(v => addSafeCard(vercelBox, `Vercel: ${v.target_url || "unknown"}`, [
    ["Status", v.dangling ? "DANGLING · TAKEOVER CANDIDATE" : "HOSTED"],
    ["Markers", (v.markers || []).join(" · ") || "—"],
    ["Notes", (v.notes || []).join("; ") || "Vercel-hosted asset."]
  ], v.dangling ? "vuln-card critical" : "vuln-card"));

  // Supabase & Firebase Deployments
  baasBox.replaceChildren();
  hiddenProjects.forEach(project => {
    const publicIds = project.public_identifiers || (project.auth && project.auth.public_identifiers) || {};
    const identifierText = Object.entries(publicIds).map(([key, value]) => `${key}=${value}`).join(" · ");
    addSafeCard(baasBox, `${project.provider || "BaaS"}: ${project.url || project.project_ref || "unknown"}`,
      [["Project", project.project_ref || "unknown"], ["Key source", project.key_source || "not paired"],
       ["Public identifiers", identifierText || "—"], ["Services", (project.services || []).join(", ") || "not observed"],
       ["Verification", (project.verification || {}).note || "Correlation is not impact proof; public client configuration is not a secret by itself."]]);
  });
  (cloud.supabase || []).forEach(sup => addSafeCard(baasBox, `Supabase: ${sup.target_url || "unknown"}`,
    [["Key classification", sup.auth_used === false ? "AUTO · NO KEY" : (sup.is_service_role ? "SERVICE ROLE" : "ANON KEY")],
     ["Source", sup.source ? `auto: ${sup.source.replaceAll("_", " ")}` : "—"],
     ["Tables", (sup.discovered_tables || []).join(" · ") || "—"],
     ["RLS candidates", (sup.vulnerable_tables_rls_bypass || []).map(v => `${v.table} (${v.status || "DISCOVERED"})`).join(", ") || "none observed"]],
    sup.is_service_role ? "vuln-card critical" : "vuln-card"));
  if (!hiddenProjects.length && !(cloud.supabase || []).length) addText(baasBox, "p", "No Supabase or Firebase configurations detected in this target.", "empty-cell");

  // Harvested Secrets - full token display for offensive research
  renderTable(secretsTbody, (cloud.harvested_tokens || []).map(s => [
    cell(s.secret_type, "", "strong"), 
    cell(s._raw_value || s.value || s.display_value, "", "code"), 
    cell(s.source),
    cell(s.classification || "PATTERN_MATCH", "", "badge"), 
    cell(s.severity || "Info")
  ]), "No credentials or secret tokens discovered.", 5);
}

function populateVulnerabilities(res) {
  const container = document.getElementById("verified-vulns-list");
  const vulns = res.findings || res.vulnerabilities || [];

  container.replaceChildren();
  if (vulns.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-vuln-card";
    addText(empty, "h3", "🛡️ No Findings Recorded");
    addText(empty, "p", "No candidate or verified finding was produced. This is not proof that the target is vulnerability-free.");
    container.appendChild(empty);
    return;
  }

  vulns.forEach((v, idx) => {
    const severity = String(v.severity || "info").toLowerCase();
    const card = document.createElement("div");
    card.className = `vuln-card ${["critical", "high", "medium", "low", "info"].includes(severity) ? severity : "info"}`;
    const header = document.createElement("div");
    header.className = "vuln-card-header";
    const title = document.createElement("div");
    addText(title, "h3", `#${idx + 1} - ${v.type || v.vuln_type || "finding"}`);
    addText(title, "span", v.vrt_category || "", "panel-tag");
    header.appendChild(title);
    const badges = document.createElement("div");
    badges.className = "vuln-badges";
    addText(badges, "span", v.status || "SUSPECTED", "finding-status");
    addText(badges, "span", v.severity || "Info", "sev-badge");
    addText(badges, "span", `Confidence ${Number(v.confidence || 0).toFixed(2)}`, "cvss-badge");
    header.appendChild(badges);
    card.appendChild(header);
    addLabelValue(card, "Disposition", v.disposition || "UNTRIAGED");
    addLabelValue(card, "Observed", v.observed_impact || v.verification_note || "Unknown");
    addLabelValue(card, "Checks", (v.verification_checks || []).map(c => `${c.name || c.payload}: ${c.passed ?? c.exact_token}`).join("; ") || "No checks recorded");
    addLabelValue(card, "False-positive indicators", (v.false_positive_reasons || []).join("; ") || "None recorded");
    addLabelValue(card, "Reviews", `AI: ${v.ai_review ? v.ai_review.verdict : "Not run"} · Human: ${v.human_review ? v.human_review.action : "Pending"}`);
    addLabelValue(card, "PoC validation", v.poc_validation ? `${v.poc_validation.passed ? "PASSED" : "FAILED"} · ${v.poc_validation.reason || v.poc_validation.validated_at || ""}` : "Not run");
    addLabelValue(card, "FP gate", v.fp_kill ? `${v.fp_kill.status} · ${(v.fp_kill.reasons || []).join(" / ")}` : "NOT SCORED");
    const repro = document.createElement("div");
    repro.className = "repro-curl-box";
    addText(repro, "code", v.reproduction_curl || "");
    const copy = document.createElement("button");
    copy.className = "btn-sm btn-copy-curl";
    copy.type = "button";
    copy.textContent = "Copy curl";
    copy.addEventListener("click", () => copyToClipboard(v.reproduction_curl || ""));
    repro.appendChild(copy);
    card.appendChild(repro);
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex; gap:10px; margin-top:10px; flex-wrap:wrap;";
    const addAction = (label, handler) => {
      const button = document.createElement("button");
      button.className = "btn-sm";
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", handler);
      actions.appendChild(button);
    };
    addAction("Validate PoC", () => validatePoc(v.id || ""));
    addAction("Test in Sandbox", () => sendToSandbox(v.target_url || "", v.param || ""));
    addAction("View Report", () => switchTab("tab-report"));
    addAction("Mark Verified", () => reviewFinding(v.id || "", "MARK_VERIFIED"));
    addAction("Reject", () => reviewFinding(v.id || "", "REJECT"));
    addAction("Needs Validation", () => reviewFinding(v.id || "", "NEEDS_MORE_VALIDATION"));
    card.appendChild(actions);
    container.appendChild(card);
  });
}

function populatePolicy(res) {
  const traffic = res.traffic || {};
  document.getElementById("policy-preset").textContent = traffic.preset || "—";
  document.getElementById("policy-global-rps").textContent = traffic.global_rps ?? "—";
  document.getElementById("policy-host-rps").textContent = traffic.per_host_rps ?? "—";
  document.getElementById("policy-concurrency").textContent = traffic.global_concurrency ?? "—";
  document.getElementById("policy-host-concurrency").textContent = traffic.per_host_concurrency ?? "—";
  document.getElementById("policy-budget").textContent = traffic.max_requests ?? "Unlimited";
  document.getElementById("policy-sent").textContent = traffic.requests_sent ?? 0;
  document.getElementById("policy-pressure").textContent = `${traffic["429_count"] || 0} / ${traffic["503_count"] || 0}`;
  document.getElementById("policy-throttle").textContent = JSON.stringify(traffic.current_throttle_state || {});
  const scope = res.scope || {};
  const engagement = res.engagement || {};
  const focus = res.hunt_focus || {};
  const engagementLabel = engagement.engagement_id ?
    `${engagement.engagement_id} / ${engagement.authorization_reference}` : "exact target";
  const classLabel = (focus.vulnerability_classes || []).join(", ") || "no active class";
  document.getElementById("policy-scope-summary").textContent =
    `${engagementLabel} · focus: ${classLabel} · Include: ${(scope.include || []).join(", ") || "none"}; Exclude: ${(scope.exclude || []).join(", ") || "none"}`;
}

window.reviewFinding = async function(findingId, action) {
  if (!currentTaskId || !findingId) { toast("No scan/finding selected — load a scan first.", "warn"); return; }
  let reason = "";
  if (action === "MARK_VERIFIED") {
    reason = window.prompt("Reason for marking VERIFIED (required by FP kill gate to override):", "Manual A/B verification by operator") || "";
    if (!reason.trim()) { toast("Mark Verified requires a reason.", "warn"); return; }
  }
  try {
    const response = await fetch(`/api/findings/${currentTaskId}/${findingId}/human-review`, {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({action, reason})
    });
    const data = await response.json();
    if (!response.ok) { toast(data.detail || "Review failed", "error"); return; }
    toast(`Finding ${action.replace(/_/g, " ").toLowerCase()}.`, "success");
    await loadScanResults(currentTaskId);
  } catch (err) {
    toast("Review error: " + err.message, "error");
  }
};

window.validatePoc = async function(findingId) {
  if (!currentTaskId || !findingId) { toast("No scan/finding selected — load a scan first.", "warn"); return; }
  try {
    const response = await fetch(`/api/findings/${currentTaskId}/${findingId}/validate-poc`, { method: "POST" });
    const data = await response.json();
    if (!response.ok) { toast(data.detail || "PoC validation failed", "error"); return; }
    const v = data.validation || {};
    if (data.disposition === "INFO_ONLY") {
      toast("PoC observed the GraphQL schema; this remains INFO_ONLY until impact is proven.", "info");
    } else if (data.submission_ready) {
      toast("PoC VERIFIED live — finding passed the FP disposition gate.", "success");
    } else if (v.passed) {
      toast(`PoC observed live behavior; disposition is ${data.disposition || data.status}.`, "info");
    } else {
      toast("PoC not reproducible: " + (v.reason || "reason unknown"), "warn");
    }
    await loadScanResults(currentTaskId);
  } catch (err) {
    toast("PoC validation error: " + err.message, "error");
  }
};

/* ========================================================================= */
/* DIRECT BAAS AUDITOR */
/* ========================================================================= */
function initDirectBaas() {
  const btn = document.getElementById("btn-direct-baas");
  btn.addEventListener("click", async () => {
    const platform = document.getElementById("direct-baas-platform").value;
    const url = document.getElementById("direct-baas-url").value.trim();
    const key = document.getElementById("direct-baas-key").value.trim();

    if (!url) {
      toast("Enter the Supabase or Firebase project URL.", "warn");
      return;
    }

    btn.disabled = true;
    btn.textContent = "AUDITING RLS...";

    try {
      const resp = await fetch("/api/cloud/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ platform, url, anon_key: key, engagement: loadedEngagement })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Audit failed");

      toast("Direct audit complete — results shown below.");
      console.log("Direct BaaS Audit Results:", data);
      
      // Render in BaaS tab
      const container = document.getElementById("baas-deployments-container");
      container.replaceChildren();
      const pre = document.createElement("pre");
      addText(pre, "code", JSON.stringify(data, null, 2));
      container.appendChild(pre);
    } catch (err) {
      toast("BaaS audit error: " + err.message, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "TEST RLS NOW";
    }
  });
}

/* ========================================================================= */
/* INTERACTIVE EXPLOIT SANDBOX */
/* ========================================================================= */
function initSandbox() {
  const btnRun = document.getElementById("btn-run-sandbox");

  btnRun.addEventListener("click", async () => {
    const url = document.getElementById("sandbox-url").value.trim();
    const param = document.getElementById("sandbox-param").value.trim();
    const method = document.getElementById("sandbox-method").value;
    const payload = document.getElementById("sandbox-payload").value;
    const technique = document.getElementById("sandbox-technique").value.trim();
    if (!technique) {
      toast("Name the exact target-specific technique before sending.", "warn");
      return;
    }

    btnRun.disabled = true;
    btnRun.textContent = "SENDING REQUEST...";

    try {
      const resp = await fetch("/api/exploit/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url, param, method, payload, technique,
          task_id: currentTaskId, engagement: loadedEngagement
        })
      });
      const data = await resp.json();

      document.getElementById("sandbox-results-box").style.display = "block";
      document.getElementById("sandbox-res-status").textContent = `${data.status_code || 0} ${data.success ? 'OK' : 'ERROR'}`;
      document.getElementById("sandbox-res-time").textContent = `${(data.response_time_sec || 0).toFixed(3)}s`;
      document.getElementById("sandbox-raw-req").textContent = data.raw_request || "";
      document.getElementById("sandbox-raw-resp").textContent = data.raw_response || "";
      document.getElementById("sandbox-res-scope").textContent = data.in_scope ? "IN SCOPE" : "OUT OF SCOPE";
      document.getElementById("sandbox-res-policy").textContent = data.traffic_profile || data.traffic?.preset || "NORMAL";
      document.getElementById("sandbox-res-request").textContent = `Request #${data.request_number || "—"}`;
      document.getElementById("sandbox-res-verification").textContent = data.verification_state || "UNKNOWN";
    } catch (err) {
      toast("Sandbox execution error: " + err.message, "error");
    } finally {
      btnRun.disabled = false;
      btnRun.textContent = "⚡ FIRE PAYLOAD";
    }
  });
}

window.sendToSandbox = function(url, param = "q") {
  document.getElementById("sandbox-url").value = url;
  document.getElementById("sandbox-param").value = param;
  switchTab("tab-sandbox");
};

window.setSandboxParam = function(param) {
  document.getElementById("sandbox-param").value = param;
  switchTab("tab-sandbox");
};

/* ========================================================================= */
/* REPORT ACTIONS */
/* ========================================================================= */
async function loadMarkdownReport(taskId) {
  try {
    const resp = await fetch(`/api/report/markdown/${taskId}`);
    if (resp.ok) {
      const md = await resp.text();
      document.getElementById("report-markdown-view").textContent = md;
    }
  } catch (err) {
    console.error("Report fetch error", err);
  }
}

function initReportActions() {
  document.getElementById("btn-export-json").addEventListener("click", () => {
    if (!currentResults) { toast("No scan results to export yet.", "warn"); return; }
    const blob = new Blob([JSON.stringify(currentResults, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `results_${currentTaskId || "scan"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast("JSON results exported.");
  });

  document.getElementById("btn-copy-report").addEventListener("click", () => {
    const text = document.getElementById("report-markdown-view").textContent;
    navigator.clipboard.writeText(text).then(() => toast("Report markdown copied to clipboard."));
  });

  document.getElementById("btn-download-report").addEventListener("click", () => {
    const text = document.getElementById("report-markdown-view").textContent;
    const blob = new Blob([text], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bugbounty_report_${currentTaskId || 'audit'}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });
  document.getElementById("btn-download-bundle").addEventListener("click", () => {
    if (!currentTaskId) {
      toast("No scan selected — load a completed scan first.", "warn");
      return;
    }
    window.location.href = `/api/report/bundle/${currentTaskId}`;
  });
}

function initExportAnalyzer() {
  const fileInput = document.getElementById("analyze-upload-file");
  const status = document.getElementById("analyze-upload-status");
  const btnCurrent = document.getElementById("btn-analyze-current");
  const btnUpload = document.getElementById("btn-analyze-upload");
  const btnCopy = document.getElementById("btn-analyze-copy");
  const btnDownload = document.getElementById("btn-analyze-download");

  if (fileInput) {
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        pendingAnalyzeFile = parsed;
        if (status) status.textContent = `Loaded: ${file.name} (${(text.length/1024).toFixed(1)} KB) — siap dianalisis.`;
        toast(`Export loaded: ${file.name}`, "success");
      } catch (err) {
        pendingAnalyzeFile = null;
        if (status) status.textContent = `Gagal parse: ${err.message}`;
        toast("File bukan JSON valid: " + err.message, "error");
      }
    });
  }

  if (btnCurrent) {
    btnCurrent.addEventListener("click", async () => {
      if (!currentTaskId) { toast("Belum ada scan aktif — jalanin scan dulu atau upload file export.", "warn"); return; }
      btnCurrent.disabled = true; btnCurrent.textContent = "Menganalisis...";
      try {
        const resp = await fetch(`/api/report/analyze/${currentTaskId}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || "Analyze failed");
        renderAnalyzeReport(data);
        toast("Analisis scan aktif selesai.", "success");
      } catch (err) { toast("Analisis gagal: " + err.message, "error"); }
      finally { btnCurrent.disabled = false; btnCurrent.textContent = "Analisis Scan Aktif"; }
    });
  }

  if (btnUpload) {
    btnUpload.addEventListener("click", async () => {
      if (!pendingAnalyzeFile) { toast("Upload dulu file results.json / export JSON.", "warn"); return; }
      btnUpload.disabled = true; btnUpload.textContent = "Menganalisis...";
      try {
        const resp = await fetch("/api/report/analyze", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(pendingAnalyzeFile) });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || "Analyze failed");
        renderAnalyzeReport(data);
        toast("Analisis file export selesai.", "success");
      } catch (err) { toast("Analisis gagal: " + err.message, "error"); }
      finally { btnUpload.disabled = false; btnUpload.textContent = "Analisis File Upload"; }
    });
  }

  if (btnCopy) {
    btnCopy.addEventListener("click", () => {
      const text = document.getElementById("analyze-markdown-view")?.textContent || "";
      if (!text || text === "Belum ada analisis.") { toast("Belum ada analisis untuk di-copy.", "warn"); return; }
      navigator.clipboard.writeText(text).then(() => toast("Analisis markdown di-copy."));
    });
  }

  if (btnDownload) {
    btnDownload.addEventListener("click", () => {
      const text = document.getElementById("analyze-markdown-view")?.textContent || "";
      if (!text || text === "Belum ada analisis.") { toast("Belum ada analisis untuk di-download.", "warn"); return; }
      const blob = new Blob([text], {type:"text/markdown"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `exploit_analysis_${currentTaskId||'export'}.md`; a.click(); URL.revokeObjectURL(url);
      toast("Analisis .md di-download.");
    });
  }
}

function renderAnalyzeReport(report) {
  lastAnalyzeReport = report;
  const summary = report.summary || {};
  const prioritized = report.prioritized || [];
  const recs = report.recommendations || [];
  const md = report.markdown || "";
  const summaryBox = document.getElementById("analyze-summary");
  const recBox = document.getElementById("analyze-recommendations");
  const mdView = document.getElementById("analyze-markdown-view");
  const jsonView = document.getElementById("analyze-json-view");
  const countTag = document.getElementById("analyze-count");
  const tbody = document.getElementById("analyze-tbody");

  if (summaryBox) {
    summaryBox.style.display = "flex";
    summaryBox.replaceChildren();
    const mk = (label,val,color) => { const s=document.createElement("span"); s.append(label+" "); const t=document.createElement("strong"); if (color) t.style.color=color; t.textContent=String(val); s.appendChild(t); return s; };
    summaryBox.appendChild(mk("Target", summary.target||"—"));
    summaryBox.appendChild(mk("Total", summary.total_findings??0));
    summaryBox.appendChild(mk("VERIFIED", summary.verified??0));
    summaryBox.appendChild(mk("Ready", summary.submission_ready??0, "#16a34a"));
    summaryBox.appendChild(mk("Quarantined", summary.quarantined??0, "#dc2626"));
    summaryBox.appendChild(mk("Max CVSS", summary.max_cvss??0));
    summaryBox.appendChild(mk("Avg Conf", summary.avg_confidence??0));
    summaryBox.appendChild(mk("Preset", summary.preset||"—"));
  }
  if (recBox) {
    recBox.style.display = "block";
    recBox.replaceChildren();
    const h = document.createElement("h4"); h.textContent = "Rekomendasi — kalian analisis hasil export yang sudah di-exploit"; recBox.appendChild(h);
    if (!recs.length) { const p=document.createElement("p"); p.className="text-dim"; p.textContent="Tidak ada rekomendasi."; recBox.appendChild(p); }
    else recs.forEach(r => { const p=document.createElement("p"); p.className="text-dim"; p.textContent="• " + r; recBox.appendChild(p); });
    const kill = report.kill_report?.summary; if (kill) { const pre=document.createElement("pre"); pre.className="code-block"; pre.style.marginTop="8px"; pre.textContent="FP Kill: " + JSON.stringify(kill,null,2); recBox.appendChild(pre); }
  }
  if (countTag) countTag.textContent = `${prioritized.length} findings`;
  if (tbody) {
    const rows = prioritized.slice(0,100).map((f,idx) => [
      cell(String(idx+1)), cell(f.type||"unknown","", "strong"), cell((f.endpoint||"—").slice(0,80),"","code"), cell(`${f.status}/${f.disposition}`), cell(f.severity||"Info","", "badge"), cell(String(f.cvss_score??0)), cell(String(f.risk_score??0)), cell(f.submission_ready ? "READY" : (f.quarantined?"QUAR":"—"), f.submission_ready?"":"text-dim"), cell((f.remediation||"—").slice(0,120), "text-dim")
    ]);
    renderTable(tbody, rows, "Tidak ada finding untuk dianalisis.", 9);
  }
  if (mdView) mdView.textContent = md || "Tidak ada markdown.";
  if (jsonView) jsonView.textContent = JSON.stringify(report, null, 2);
}

/* ========================================================================= */
/* RECENT SCANS */
/* ========================================================================= */
async function loadRecentScans() {
  try {
    const resp = await fetch("/api/scan/list");
    if (!resp.ok) return;
    const data = await resp.json();
    const tbody = document.getElementById("recent-scans-tbody");

    renderTable(tbody, (data.scans || []).map(s => [
      cell(s.task_id, "", "code"), cell(s.target, "", "strong"), cell(s.preset, "", "badge"),
      cell(String(s.status || "unknown").toUpperCase()), cell(`${s.progress || 0}%`), cell(s.vulns_count || 0, "", "strong"),
      buttonCell("Load", () => selectScan(s.task_id))
    ]), "No scans recorded yet.", 7);
  } catch (err) {
    console.error("Recent scans error", err);
  }
}

window.selectScan = function(taskId) {
  currentTaskId = taskId;
  loadScanResults(taskId);
  switchTab("tab-surface");
};

window.copyToClipboard = function(text) {
  navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard."));
};
