"use strict";

// Everything rendered here comes from audited third-party repositories, so the
// DOM is built with textContent only — never innerHTML.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);
const POLL_MS = 3000;

// ---------------------------------------------------------------------------
// i18n
//
// Two kinds of text meet on this page. The interface is translated here, from
// this table; the findings themselves are written in the chosen language by
// the audit backend, because it is asked for that language up front — nothing
// is translated after the fact.
// ---------------------------------------------------------------------------

const LANGUAGES = ["en", "es"];
const LANG_KEY = "secaudit.language";

const TEXT = {
  en: {
    "lang.label": "language",
    "nav.backend": "backend",
    "nav.signout": "sign out",
    "signin.title": "sign in",
    "signin.lead": "secaudit audits GitHub repositories with the model of your " +
      "choice. Sign in to bring your own API key — your key and your audits " +
      "stay yours, and nobody else on this instance can see either.",
    "signin.button": "sign in with GitHub",
    "signin.disabled": "Sign-in is not configured on this instance yet.",
    "settings.title": "audit backend",
    "settings.intro": "Paste an API key and secaudit works with it. The key is " +
      "encrypted before it is stored and is never sent back to this page.",
    "settings.apikey": "api key",
    "settings.backend": "backend",
    "settings.detect": "detect from the key",
    "settings.ollama": "ollama (free, local)",
    "settings.claudecode": "claude-code (local binary)",
    "settings.model": "model",
    "settings.optional": "(optional)",
    "settings.modelph": "backend default",
    "settings.ollamaurl": "ollama url",
    "settings.save": "save",
    "settings.removekey": "remove key",
    "settings.keystored": "a key is stored — type a new one to replace it",
    "settings.ready": "ready",
    "settings.notready": "not ready",
    "settings.nobackend": "no backend",
    "runner.title": "run audits on your own machine",
    "runner.intro": "The claude-code backend runs a program signed in on a " +
      "machine, which this server is not. Audits you queue are left waiting " +
      "for a runner on your computer to pick them up — see " +
      "secaudit-runner.py. Nothing but the findings leaves your machine.",
    "runner.create": "create runner token",
    "runner.revoke": "revoke",
    "runner.copy": "Copy this now — it is not shown again:",
    "runner.revoked": "runner token revoked",
    "audit.repo": "repository",
    "audit.run": "run audit",
    "audits.title": "audits",
    "audits.empty": "no audits yet",
    "findings.title": "findings",
    "findings.select": "select an audit",
    "findings.verifiedonly": "only findings backed by code",
    "findings.none": "no findings reported",
    "findings.nonverified": "no findings backed by code in this audit",
    "findings.inprogress": "audit in progress…",
    "findings.failed": "audit failed",
    "findings.nofindings": "no findings",
    "findings.unverified": "unverified",
    "findings.counted": (n, v) => `${n} findings · ${v} backed by code`,
    "detail.status": "status",
    "detail.branch": "branch",
    "detail.commit": "commit",
    "detail.trigger": "trigger",
    "detail.started": "started",
    "detail.error": "error",
    "detail.language": "language",
    "detail.default": "default",
    "detail.delete": "delete",
    "detail.deleteconfirm": "click again to delete",
    "time.now": "just now",
    "time.minutes": (n) => `${n}m ago`,
    "time.hours": (n) => `${n}h ago`,
    "health.unreachable": "unreachable",
    "status.pending": "pending",
    "status.running": "running",
    "status.done": "done",
    "status.error": "error",
    "trigger.manual": "manual",
    "trigger.webhook": "webhook",
    "severity.critical": "critical",
    "severity.high": "high",
    "severity.medium": "medium",
    "severity.low": "low",
    "severity.info": "info",
  },
  es: {
    "lang.label": "idioma",
    "nav.backend": "motor",
    "nav.signout": "cerrar sesión",
    "signin.title": "iniciar sesión",
    "signin.lead": "secaudit audita repositorios de GitHub con el modelo que " +
      "elijas. Inicia sesión para usar tu propia clave de API: tu clave y tus " +
      "auditorías son tuyas, y nadie más en esta instancia puede verlas.",
    "signin.button": "iniciar sesión con GitHub",
    "signin.disabled": "El inicio de sesión aún no está configurado en esta instancia.",
    "settings.title": "motor de auditoría",
    "settings.intro": "Pega una clave de API y secaudit funciona con ella. La " +
      "clave se cifra antes de guardarse y nunca se devuelve a esta página.",
    "settings.apikey": "clave de api",
    "settings.backend": "motor",
    "settings.detect": "deducir de la clave",
    "settings.ollama": "ollama (gratis, local)",
    "settings.claudecode": "claude-code (binario local)",
    "settings.model": "modelo",
    "settings.optional": "(opcional)",
    "settings.modelph": "el del motor por defecto",
    "settings.ollamaurl": "url de ollama",
    "settings.save": "guardar",
    "settings.removekey": "quitar clave",
    "settings.keystored": "hay una clave guardada — escribe otra para reemplazarla",
    "settings.ready": "listo",
    "settings.notready": "no disponible",
    "settings.nobackend": "sin motor",
    "runner.title": "ejecutar auditorías en tu propia máquina",
    "runner.intro": "El motor claude-code ejecuta un programa con la sesión " +
      "iniciada en una máquina, cosa que este servidor no es. Las auditorías " +
      "que encoles quedan esperando a que las recoja un runner en tu " +
      "ordenador — mira secaudit-runner.py. De tu máquina no sale nada más " +
      "que los hallazgos.",
    "runner.create": "crear token de runner",
    "runner.revoke": "revocar",
    "runner.copy": "Cópialo ahora — no se vuelve a mostrar:",
    "runner.revoked": "token de runner revocado",
    "audit.repo": "repositorio",
    "audit.run": "auditar",
    "audits.title": "auditorías",
    "audits.empty": "todavía no hay auditorías",
    "findings.title": "hallazgos",
    "findings.select": "selecciona una auditoría",
    "findings.verifiedonly": "solo hallazgos con código que los respalde",
    "findings.none": "no se han reportado hallazgos",
    "findings.nonverified": "ningún hallazgo de esta auditoría tiene código que lo respalde",
    "findings.inprogress": "auditoría en curso…",
    "findings.failed": "la auditoría falló",
    "findings.nofindings": "sin hallazgos",
    "findings.unverified": "sin verificar",
    "findings.counted": (n, v) => `${n} hallazgos · ${v} con código que los respalda`,
    "detail.status": "estado",
    "detail.branch": "rama",
    "detail.commit": "commit",
    "detail.trigger": "origen",
    "detail.started": "iniciada",
    "detail.error": "error",
    "detail.language": "idioma",
    "detail.default": "por defecto",
    "detail.delete": "borrar",
    "detail.deleteconfirm": "pulsa otra vez para borrar",
    "time.now": "ahora mismo",
    "time.minutes": (n) => `hace ${n} min`,
    "time.hours": (n) => `hace ${n} h`,
    "health.unreachable": "no responde",
    "status.pending": "pendiente",
    "status.running": "en curso",
    "status.done": "terminada",
    "status.error": "error",
    "trigger.manual": "manual",
    "trigger.webhook": "webhook",
    "severity.critical": "crítica",
    "severity.high": "alta",
    "severity.medium": "media",
    "severity.low": "baja",
    "severity.info": "informativa",
  },
};

// Category names come back from the API as their English identifiers; they are
// the shared vocabulary of the tool, so only their display form is translated.
const CATEGORIES = {
  es: {
    injection: "inyección",
    authz: "autorización",
    sessions: "sesiones",
    rate_limiting: "limitación de peticiones",
    error_handling: "manejo de errores",
    dependencies: "dependencias",
    file_handling: "manejo de ficheros",
    secrets: "secretos",
    cors: "cors",
    xss: "xss",
    csp: "csp",
    csrf: "csrf",
    client_security: "seguridad en cliente",
    other: "otros",
  },
};

function initialLanguage() {
  const stored = localStorage.getItem(LANG_KEY);
  if (LANGUAGES.includes(stored)) return stored;
  return String(navigator.language || "en").toLowerCase().startsWith("es")
    ? "es" : "en";
}

let lang = initialLanguage();

function t(key, ...args) {
  const value = (TEXT[lang] || {})[key] ?? TEXT.en[key];
  if (typeof value === "function") return value(...args);
  return value ?? key;
}

function categoryLabel(category) {
  return (CATEGORIES[lang] || {})[category] || category;
}

function applyStaticText() {
  document.documentElement.lang = lang;
  for (const target of document.querySelectorAll("[data-i18n]")) {
    target.textContent = t(target.dataset.i18n);
  }
  for (const target of document.querySelectorAll("[data-i18n-placeholder]")) {
    target.placeholder = t(target.dataset.i18nPlaceholder);
  }
}

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
  if (seconds < 60) return t("time.now");
  if (seconds < 3600) return t("time.minutes", Math.floor(seconds / 60));
  if (seconds < 86400) return t("time.hours", Math.floor(seconds / 3600));
  return then.toLocaleDateString(lang);
}

function countsNode(summary) {
  const counts = node("div", "counts");
  let total = 0;
  for (const severity of SEVERITIES) {
    const n = (summary && summary[severity]) || 0;
    total += n;
    if (n > 0) {
      counts.append(node("span", `count count-${severity}`,
                         `${t(`severity.${severity}`)} ${n}`));
    }
  }
  if (total === 0) counts.append(node("span", "muted", t("findings.nofindings")));
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
  meta.append(node("span", `status status-${audit.status}`,
                   t(`status.${audit.status}`)));
  if (audit.branch) meta.append(node("span", null, audit.branch));
  if (audit.commit_sha) meta.append(node("span", null, shortSha(audit.commit_sha)));
  meta.append(node("span", null, t(`trigger.${audit.trigger}`)));
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
  const verified = finding.verification_status === "verified";
  const item = node("article", `finding${verified ? "" : " finding-unverified"}`);

  const head = node("div", "finding-head");
  head.append(node("span", `severity severity-${finding.severity}`,
                   t(`severity.${finding.severity}`)));
  head.append(node("span", "finding-title", finding.title));
  // An unverified finding is reported, not hidden — but it never looks like a
  // confirmed one.
  if (!verified) head.append(node("span", "badge-unverified", t("findings.unverified")));
  item.append(head);

  const at = finding.line ? `${finding.file}:${finding.line}` : finding.file;
  const where = [at, finding.anchor, categoryLabel(finding.category)]
    .filter(Boolean);
  if (where.length) item.append(node("div", "finding-where", where.join("  ·  ")));
  // The snippet is code from an audited third-party repo: textContent only.
  if (verified && finding.code_snippet) {
    item.append(node("pre", "finding-snippet", finding.code_snippet));
  }
  if (!verified && finding.verification_note) {
    item.append(node("div", "finding-note muted", finding.verification_note));
  }
  if (finding.description) item.append(node("p", "finding-desc", finding.description));
  return item;
}

function deleteButton(audit) {
  // Two clicks rather than a modal: the second one is the confirmation.
  const button = node("button", "ghost danger", t("detail.delete"));
  button.type = "button";
  let armed = false;
  button.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      button.textContent = t("detail.deleteconfirm");
      setTimeout(() => {
        armed = false;
        button.textContent = t("detail.delete");
      }, 4000);
      return;
    }
    button.disabled = true;
    try {
      await api(`/api/audits/${encodeURIComponent(audit.id)}`,
                { method: "DELETE" });
      selectedId = null;
      el("detail").hidden = true;
      el("detail-empty").hidden = false;
      await refresh();
    } catch (e) {
      button.disabled = false;
      button.textContent = e.message;
    }
  });
  return button;
}

function detailHead(audit) {
  const head = node("div", "detail-head");
  const title = node("div", "detail-title");
  title.append(node("span", "finding-title", repoLabel(audit.repo_url)),
               deleteButton(audit));
  head.append(title);

  const dl = document.createElement("dl");
  const rows = [
    ["status", t("detail.status"), t(`status.${audit.status}`)],
    ["branch", t("detail.branch"), audit.branch || t("detail.default")],
    ["commit", t("detail.commit"), shortSha(audit.commit_sha) || "—"],
    ["trigger", t("detail.trigger"), t(`trigger.${audit.trigger}`)],
    ["language", t("detail.language"), audit.language || "en"],
    ["started", t("detail.started"),
     audit.created_at ? new Date(audit.created_at).toLocaleString(lang) : "—"],
  ];
  if (audit.error) rows.push(["error", t("detail.error"), audit.error]);
  for (const [key, term, value] of rows) {
    dl.append(node("dt", null, term));
    dl.append(node("dd", key === "status" ? `status status-${audit.status}` : null, value));
  }
  head.append(dl);
  head.append(countsNode(audit.summary));
  return head;
}

function renderDetail(audit) {
  const detail = el("detail");
  detail.replaceChildren(detailHead(audit));

  const findings = audit.findings || [];
  const total = Object.values(audit.summary || {}).reduce((a, b) => a + b, 0);
  if (audit.status === "done" && total > 0) {
    detail.append(node("p", "muted verified-count",
                       t("findings.counted", total, audit.verified_count || 0)));
  }
  if (findings.length === 0) {
    const message = ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress")
      : audit.status === "error" ? t("findings.failed")
      : el("verified-only").checked && total > 0 ? t("findings.nonverified")
      : t("findings.none");
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
  const query = el("verified-only").checked ? "?verified_only=true" : "";
  try {
    renderDetail(await api(`/api/audits/${encodeURIComponent(id)}${query}`));
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
    ? t("settings.keystored")
    : "sk-ant-… or sk-…";
  el("clear-key").disabled = !settings.api_key_set;

  // The runner only matters for the backend the server cannot run itself.
  el("runner").hidden = (settings.backend_status || {}).name !== "claude-code";
  el("runner-shown").hidden = true;

  const status = settings.backend_status || {};
  const state = el("settings-state");
  state.replaceChildren(
    node("span", `status status-${status.ready ? "done" : "error"}`,
         status.ready ? t("settings.ready") : t("settings.notready")),
    node("span", null, `  ${status.name || t("settings.nobackend")}`),
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

el("runner-token").addEventListener("click", async () => {
  const shown = el("runner-shown");
  try {
    const { token } = await api("/api/runner/token", { method: "POST" });
    // Shown once: the server keeps only a hash of it.
    shown.replaceChildren(
      node("div", null, t("runner.copy")),
      node("code", "runner-token-value", token),
      node("div", null, `SECAUDIT_RUNNER_TOKEN=… ./secaudit-runner.py ${location.origin}`),
    );
    shown.hidden = false;
  } catch (e) {
    shown.replaceChildren(node("div", null, e.message));
    shown.hidden = false;
  }
});

el("runner-revoke").addEventListener("click", async () => {
  await fetch("/api/runner/token", { method: "DELETE" });
  el("runner-shown").replaceChildren(node("div", null, t("runner.revoked")));
  el("runner-shown").hidden = false;
});

async function loadHealth() {
  const health = el("health");
  try {
    const body = await api("/api/health");
    const backend = (body.backend && body.backend.name) || t("settings.nobackend");
    health.dataset.state = body.status;
    health.textContent = `${body.status} · ${backend}`;
  } catch (_) {
    health.dataset.state = "down";
    health.textContent = t("health.unreachable");
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
      // The findings come back written in the language of the interface: the
      // backend is asked for it, so nothing is translated afterwards.
      body: JSON.stringify({ repo_url: input.value.trim(), language: lang }),
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

// ---------------------------------------------------------------------------
// language and evidence filter
// ---------------------------------------------------------------------------

el("lang").addEventListener("change", () => {
  lang = LANGUAGES.includes(el("lang").value) ? el("lang").value : "en";
  localStorage.setItem(LANG_KEY, lang);
  applyStaticText();
  // Only the interface changes: findings keep the language they were audited
  // in, which is why each audit records its own.
  loadHealth();
  if (!el("settings").hidden) loadSettings();
  refresh();
  if (selectedId) loadDetail(selectedId);
});

el("verified-only").addEventListener("change", () => {
  if (selectedId) loadDetail(selectedId);
});

async function start() {
  el("lang").value = lang;
  applyStaticText();
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
