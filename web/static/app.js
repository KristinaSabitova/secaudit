"use strict";

// Everything rendered here comes from audited third-party repositories, so the
// DOM is built with textContent only — never innerHTML.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);
const POLL_MS = 3000;

const el = (id) => document.getElementById(id);

let selectedId = null;
let pollTimer = null;

function node(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

async function api(path, options) {
  const response = await fetch(path, options);
  let body = null;
  try {
    body = await response.json();
  } catch (_) {
    // no body, or not JSON
  }
  if (response.status === 401 && path !== "/api/me") {
    location.reload();          // the session expired; show the sign-in screen
  }
  if (!response.ok) {
    throw new Error((body && body.detail) || `request failed (${response.status})`);
  }
  return body;
}

function repoLabel(url) {
  return String(url || "")
    .replace(/^https:\/\/github\.com\//, "")
    .replace(/\.git$/, "");
}

function shortSha(sha) {
  return sha ? String(sha).slice(0, 7) : "";
}

function relativeTime(iso) {
  const then = new Date(iso);
  if (!iso || Number.isNaN(then.getTime())) return "";
  const seconds = (Date.now() - then.getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return then.toLocaleDateString();
}

function countsNode(summary) {
  const counts = node("div", "counts");
  let total = 0;
  for (const severity of SEVERITIES) {
    const n = (summary && summary[severity]) || 0;
    total += n;
    if (n > 0) counts.append(node("span", `count count-${severity}`, `${severity} ${n}`));
  }
  if (total === 0) counts.append(node("span", "muted", "no findings"));
  return counts;
}

// ---------------------------------------------------------------------------
// audit list
// ---------------------------------------------------------------------------

function auditNode(audit) {
  const item = document.createElement("li");
  const button = node("button", "audit");
  button.type = "button";
  button.setAttribute("aria-current", String(audit.id === selectedId));
  button.addEventListener("click", () => select(audit.id));

  button.append(node("span", "audit-repo", repoLabel(audit.repo_url)));

  const meta = node("div", "audit-meta");
  meta.append(node("span", `status status-${audit.status}`, audit.status));
  if (audit.branch) meta.append(node("span", null, audit.branch));
  if (audit.commit_sha) meta.append(node("span", null, shortSha(audit.commit_sha)));
  meta.append(node("span", null, audit.trigger));
  const when = relativeTime(audit.created_at);
  if (when) meta.append(node("span", null, when));
  button.append(meta);

  if (audit.status === "done") button.append(countsNode(audit.summary));
  item.append(button);
  return item;
}

function renderList(audits) {
  const list = el("audit-list");
  list.replaceChildren(...audits.map(auditNode));
  el("audits-empty").hidden = audits.length > 0;
  el("audit-count").textContent = audits.length ? `(${audits.length})` : "";
}

// ---------------------------------------------------------------------------
// detail pane
// ---------------------------------------------------------------------------

function findingNode(finding) {
  const item = node("article", "finding");

  const head = node("div", "finding-head");
  head.append(node("span", `severity severity-${finding.severity}`, finding.severity));
  head.append(node("span", "finding-title", finding.title));
  item.append(head);

  const where = [finding.file, finding.anchor, finding.category].filter(Boolean);
  if (where.length) item.append(node("div", "finding-where", where.join("  ·  ")));
  if (finding.description) item.append(node("p", "finding-desc", finding.description));
  return item;
}

function detailHead(audit) {
  const head = node("div", "detail-head");
  head.append(node("div", "finding-title", repoLabel(audit.repo_url)));

  const dl = document.createElement("dl");
  const rows = [
    ["status", audit.status],
    ["branch", audit.branch || "default"],
    ["commit", shortSha(audit.commit_sha) || "—"],
    ["trigger", audit.trigger],
    ["started", audit.created_at ? new Date(audit.created_at).toLocaleString() : "—"],
  ];
  if (audit.error) rows.push(["error", audit.error]);
  for (const [term, value] of rows) {
    dl.append(node("dt", null, term));
    dl.append(node("dd", term === "status" ? `status status-${audit.status}` : null, value));
  }
  head.append(dl);
  head.append(countsNode(audit.summary));
  return head;
}

function renderDetail(audit) {
  const detail = el("detail");
  detail.replaceChildren(detailHead(audit));

  const findings = audit.findings || [];
  if (findings.length === 0) {
    const message = ACTIVE_STATUSES.has(audit.status)
      ? "audit in progress…"
      : audit.status === "error" ? "audit failed" : "no findings reported";
    detail.append(node("p", "muted", message));
  } else {
    const order = new Map(SEVERITIES.map((s, i) => [s, i]));
    const sorted = [...findings].sort(
      (a, b) => (order.get(a.severity) ?? 99) - (order.get(b.severity) ?? 99)
    );
    detail.append(...sorted.map(findingNode));
  }

  detail.hidden = false;
  el("detail-empty").hidden = true;
}

async function loadDetail(id) {
  try {
    renderDetail(await api(`/api/audits/${encodeURIComponent(id)}`));
  } catch (_) {
    // a failed detail fetch leaves the previous render in place
  }
}

function select(id) {
  selectedId = id;
  for (const button of document.querySelectorAll(".audit")) {
    button.setAttribute("aria-current", "false");
  }
  loadDetail(id);
  refresh();
}

// ---------------------------------------------------------------------------
// polling
// ---------------------------------------------------------------------------

async function refresh() {
  clearTimeout(pollTimer);
  let audits = [];
  try {
    audits = await api("/api/audits");
  } catch (_) {
    pollTimer = setTimeout(refresh, POLL_MS * 2);
    return;
  }

  renderList(audits);
  const selected = audits.find((a) => a.id === selectedId);
  if (selected) await loadDetail(selectedId);

  if (audits.some((a) => ACTIVE_STATUSES.has(a.status))) {
    pollTimer = setTimeout(refresh, POLL_MS);
  }
}

// ---------------------------------------------------------------------------
// backend settings
// ---------------------------------------------------------------------------

function renderSettings(settings) {
  el("backend").value = settings.backend || "";
  el("model").value = settings.model || "";
  el("ollama-url").value = settings.ollama_url || "";
  el("ollama-field").hidden = el("backend").value !== "ollama";

  const key = el("api-key");
  key.value = "";
  key.placeholder = settings.api_key_set
    ? "a key is stored — type a new one to replace it"
    : "sk-ant-… or sk-…";
  el("clear-key").disabled = !settings.api_key_set;

  const status = settings.backend_status || {};
  const state = el("settings-state");
  state.replaceChildren(
    node("span", `status status-${status.ready ? "done" : "error"}`,
         status.ready ? "ready" : "not ready"),
    node("span", null, `  ${status.name || "no backend"}`),
  );
  if (status.model) state.append(node("span", null, `  ·  ${status.model}`));
  if (status.detail) state.append(node("div", "muted", status.detail));
}

async function loadSettings() {
  try {
    renderSettings(await api("/api/settings"));
  } catch (e) {
    el("settings-error").textContent = e.message;
    el("settings-error").hidden = false;
  }
}

async function saveSettings(body) {
  const error = el("settings-error");
  error.hidden = true;
  try {
    renderSettings(await api("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }));
    await loadHealth();
  } catch (e) {
    error.textContent = e.message;
    error.hidden = false;
  }
}

el("settings-toggle").addEventListener("click", () => {
  const panel = el("settings");
  panel.hidden = !panel.hidden;
  el("settings-toggle").setAttribute("aria-expanded", String(!panel.hidden));
  if (!panel.hidden) loadSettings();
});

el("backend").addEventListener("change", () => {
  el("ollama-field").hidden = el("backend").value !== "ollama";
});

el("settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const body = {
    backend: el("backend").value,
    model: el("model").value.trim(),
    ollama_url: el("ollama-url").value.trim(),
  };
  const key = el("api-key").value.trim();
  if (key) body.api_key = key;
  saveSettings(body);
});

el("clear-key").addEventListener("click", () => saveSettings({ clear_api_key: true }));

async function loadHealth() {
  const health = el("health");
  try {
    const body = await api("/api/health");
    const backend = (body.backend && body.backend.name) || "unknown backend";
    health.dataset.state = body.status;
    health.textContent = `${body.status} · ${backend}`;
  } catch (_) {
    health.dataset.state = "down";
    health.textContent = "unreachable";
  }
}

// ---------------------------------------------------------------------------
// new audit
// ---------------------------------------------------------------------------

el("audit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = el("repo-url");
  const button = event.target.querySelector("button");
  const error = el("form-error");

  error.hidden = true;
  button.disabled = true;
  try {
    const audit = await api("/api/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: input.value.trim() }),
    });
    input.value = "";
    selectedId = audit.id;
    await refresh();
  } catch (e) {
    error.textContent = e.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

function showSignedOut(signInEnabled) {
  el("app").hidden = true;
  el("signin").hidden = false;
  el("signin-link").hidden = !signInEnabled;
  el("signin-disabled").hidden = signInEnabled;
  for (const id of ["whoami", "settings-toggle", "logout"]) el(id).hidden = true;
}

function showSignedIn(user, singleUser) {
  el("signin").hidden = true;
  el("app").hidden = false;
  el("whoami").textContent = user.login + (user.is_admin ? " · admin" : "");
  el("whoami").hidden = false;
  el("settings-toggle").hidden = false;
  // A personal instance has no session to end.
  el("logout").hidden = singleUser;
}

el("logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  location.reload();
});

async function start() {
  loadHealth();
  let me;
  try {
    me = await api("/api/me");
  } catch (_) {
    showSignedOut(false);
    return;
  }
  if (!me.user) {
    showSignedOut(me.sign_in_enabled);
    return;
  }
  showSignedIn(me.user, me.single_user);
  refresh();
}

start();
