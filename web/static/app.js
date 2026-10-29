"use strict";

// Everything rendered here comes from audited third-party repositories, so the
// DOM is built with textContent only — never innerHTML.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);
const POLL_MS = 3000;

const SECTIONS = ["summary", "findings", "parallax", "falsifiability", "memory",
                  "leverage", "attacker", "history", "settings"];
// The sections that need an audit to show anything; the rest stand alone.
const AUDIT_SECTIONS = new Set(SECTIONS.slice(0, 7));
// Each module section, the module_runs name it reads, and the phase it lands in.
const MODULES = {
  parallax: { run: "parallax", phase: 5 },
  falsifiability: { run: "falsifiability", phase: 4 },
  memory: { run: "immune", phase: 6 },
  leverage: { run: "leverage", phase: 7 },
  attacker: { run: "attacker", phase: 8 },
};
const RISK_TIERS = { 1: "tier.1", 2: "tier.2", 3: "tier.3", 4: "tier.4",
                     5: "tier.5", 6: "tier.6" };

// Browser storage may be blocked; nothing here depends on it working.
function stored(key) {
  try {
    return localStorage.getItem(key);
  } catch (_) {
    return null;
  }
}

function store(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch (_) {
    // the choice holds for this visit only
  }
}

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
    "nav.skip": "skip to content",
    "nav.toggle": "show or hide the sections",
    "nav.sections": "sections",
    "nav.summary": "Summary",
    "nav.findings": "Findings",
    "nav.parallax": "Parallax",
    "nav.falsifiability": "Falsifiability",
    "nav.memory": "Memory",
    "nav.leverage": "Leverage",
    "nav.attacker": "Attacker",
    "nav.history": "History",
    "nav.settings": "Settings",
    "nav.signout": "sign out",
    "nav.notrun": "not run",
    "nav.phase": (n) => `phase ${n}`,
    "top.project": "project",
    "top.audit": "audit",
    "top.search": "search findings",
    "top.searchph": "search findings  /",
    "theme.label": "theme",
    "theme.system": "as the system",
    "theme.dark": "dark",
    "theme.light": "light",
    "theme.todark": "Switch to dark mode",
    "theme.tolight": "Switch to light mode",
    "drawer.close": "close the detail panel",
    "signin.title": "sign in",
    "signin.lead": "secaudit audits GitHub repositories with the model of your " +
      "choice. Sign in to bring your own API key — your key and your audits " +
      "stay yours, and nobody else on this instance can see either.",
    "signin.button": "sign in with GitHub",
    "signin.disabled": "Sign-in is not configured on this instance yet.",
    "settings.title": "Audit backend",
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
    "settings.display": "Display",
    "jewels.title": "Crown jewels",
    "jewels.phase": "What an attacker would want most from each project — " +
      "secrets, user data, deployment, administration. Declared here from " +
      "phase 8, together with the Attacker section.",
    "runner.title": "Run audits on your own machine",
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
    "audits.title": "Audits",
    "audits.empty": "no audits yet",
    "history.metrics": "How each metric moves from one commit to the next is " +
      "drawn here once the modules record them.",
    "history.repo": "repository",
    "history.commit": "commit",
    "history.when": "when",
    "history.status": "status",
    "history.findings": "findings",
    "history.coverage": "coverage",
    "summary.noaudits": "Nothing has been audited yet.",
    "summary.start": "start an audit",
    "summary.loading": "loading…",
    "summary.integrity": "Integrity of the audit",
    "summary.integritynone": "Not measured: see Parallax for why.",
    "summary.divergences": (n) => `${n} place(s) where the views of the ` +
      `repository disagree.`,
    "summary.seeparallax": "see the divergences",
    "summary.unreliable": "No findings, but the auditor missed decoys planted " +
      "where it was looking: do not take this clean result as reliable.",
    "summary.coverage": "Coverage",
    "summary.nocoverage": "This audit predates coverage: what the auditor saw " +
      "was not recorded.",
    "summary.files": "Files left out or audited in part",
    "summary.allaudited": "Every file was audited in full.",
    "summary.findings": "Findings",
    "summary.seefindings": "see the findings",
    "summary.paths": "Critical paths and the fix that cuts most",
    "summary.pathsphase": "The cheapest way in for each attacker profile and " +
      "the single fix that closes most of them. Arrives in phase 8.",
    "summary.modules": "What ran",
    "summary.nomodules": "No module runs were recorded for this audit.",
    "module.name": "module",
    "module.status": "status",
    "module.model": "model",
    "module.tokens": "tokens in / out",
    "module.duration": "duration",
    "module.audit": "audit",
    "module.evidence": "evidence check",
    "module.falsifiability": "falsifiability",
    "module.parallax": "parallax",
    "coverage.file": "file",
    "coverage.reason": "reason",
    "coverage.tier": "risk",
    "tier.1": "runs on its own",
    "tier.2": "agent configuration",
    "tier.3": "entry point",
    "tier.4": "auth and secrets",
    "tier.5": "code",
    "tier.6": "tests, docs, data",
    "findings.verifiedonly": "only findings backed by code",
    "findings.none": "no findings reported",
    "findings.nonverified": "no findings backed by code in this audit",
    "findings.nomatch": "no finding matches these filters",
    "findings.inprogress": "audit in progress…",
    "findings.failed": "audit failed",
    "findings.nofindings": "no findings",
    "findings.unverified": "unverified",
    "findings.verified": "backed by code",
    "findings.counted": (n, v) => `${n} findings · ${v} backed by code`,
    "findings.showing": (n) => ` · ${n} shown`,
    "findings.expand": (title) => `show more of: ${title}`,
    "findings.severity": "severity",
    "findings.finding": "finding",
    "findings.location": "location",
    "findings.evidence": "evidence",
    "findings.epistemic": "status",
    "findings.category": "category",
    "findings.anchor": "anchor",
    "findings.note": "why it is unverified",
    "findings.snippet": "the code it quotes",
    "findings.description": "description",
    "filter.severity": "severity",
    "filter.evidence": "evidence",
    "filter.epistemic": "epistemic status",
    "filter.all": "all",
    "filter.unverifiedonly": "only unverified",
    "epistemic.exists": "exists",
    "epistemic.reachable": "reachable",
    "epistemic.corroborated": "corroborated",
    "epistemic.refuted": "refuted",
    "epistemic.inconclusive": "inconclusive",
    "epistemic.none": "not established",
    "parallax.question": "Does the model read the repository the way a person does?",
    "parallax.what": "Each file seen several ways — as a person reads it, as " +
      "bytes, as the machine runs it, as the model was shown it, as it was " +
      "published — and every place where those views disagree, annotated over " +
      "the code.",
    "parallax.integrity": "Integrity of the auditor",
    "parallax.integrityline": (found, planted) => `The auditor found ${found} ` +
      `of the ${planted} decoys planted in a copy of one of its own requests.`,
    "parallax.integritynote": "A signal, not a guarantee: a context that degrades " +
      "the model shows up as missed decoys, but someone who knew about them could " +
      "let them through and still hide the real thing. Decoys are never findings.",
    "parallax.integritynone": "Not measured for this audit.",
    "parallax.runner": "Counted by your runner, on your machine.",
    "parallax.decoy": "decoy",
    "parallax.found": "found",
    "parallax.missed": "missed",
    "decoy.sql_injection": "SQL injection",
    "decoy.command_injection": "command injection",
    "decoy.code_eval": "evaluated input",
    "decoy.insecure_deserialization": "insecure deserialisation",
    "decoy.path_traversal": "path traversal",
    "kind.hidden_content": "Hidden content",
    "kind.unexpected_execution": "Unexpected execution",
    "kind.audit_blind_spot": "Blind spots of the audit",
    "kind.release_mismatch": "Release that is not the source",
    "kinddesc.hidden_content": "What a person sees is not what the bytes say: " +
      "invisible characters, comments the rendered page drops.",
    "kinddesc.unexpected_execution": "Something runs — on install, on opening " +
      "the folder, when an agent starts — that does not look like it would.",
    "kinddesc.audit_blind_spot": "What the auditor was not sent, saw only in " +
      "part, or saw drowned in filler.",
    "kinddesc.release_mismatch": "The package on the registry is not the " +
      "source at its git tag.",
    "parallax.nokind": "Nothing of this kind.",
    "parallax.notrun": "Parallax did not run for this audit: it predates the module.",
    "parallax.failed": "Parallax failed for this audit; the findings stand without it.",
    "parallax.published": "Published package",
    "parallax.nopackage": "The repository declares no Python or npm package at its root.",
    "parallax.publishedoff": "The published view is not checked on this instance.",
    "parallax.compared": (name, tag, n) => `${name}: compared with tag ${tag} — ` +
      `${n} difference(s).`,
    "parallax.notcompared": (name) => `${name}: not compared.`,
    "parallax.notes": "The descriptions are written by the analysis, in English.",
    "parallax.file": "file",
    "parallax.divergence": "divergence",
    "parallax.views": "views",
    "parallax.whole": "the repository",
    "parallax.sidebyside": "side by side",
    "parallax.overlay": "overlaid",
    "parallax.notshown": "(not shown)",
    "parallax.absent": "(absent)",
    "parallax.trigger": "runs on",
    "parallax.command": "what runs",
    "parallax.decoded": "what the hidden characters say",
    "parallax.files": "files",
    "parallax.more": (n) => `… and ${n} more`,
    "parallax.truncated": "Only the first lines that differ are shown.",
    "parallax.nocheckout": "Not checked: the server could not check out the " +
      "audited commit.",
    "parallax.expand": (what) => `show the views of: ${what}`,
    "view.human": "what a person sees",
    "view.bytes": "the bytes",
    "view.machine": "what runs",
    "view.llm": "what the auditor was sent",
    "view.published": "the published package",
    "falsifiability.question": "Does each finding survive a serious attempt to refute it?",
    "falsifiability.what": "Each finding backed by code is stated as a flow — " +
      "where the input enters, the dangerous use it reaches, the functions " +
      "between — and secaudit tries to refute it: by the call graph, by what " +
      "actually reaches the sink, by whether anything outside can reach it, " +
      "and by asking the model to argue it false, quoting code. Only what " +
      "survives all four is corroborated.",
    "falsify.statuses": "Where the findings stand",
    "falsify.table": "Hypotheses and the attempts to refute them",
    "falsify.none": "No finding in this audit was stated as a hypothesis. Audits " +
      "from before this module have none.",
    "falsify.flow": "source → sink",
    "falsify.rate": "Refutation rate by model",
    "falsify.rateintro": "Of the findings each model stated as a testable " +
      "hypothesis, across all your audits, the share that fell: a measured " +
      "false-positive rate.",
    "falsify.ratenone": "Nothing has been tested yet.",
    "falsify.model": "backend · model",
    "falsify.tested": "tested",
    "falsify.refuted": "refuted",
    "falsify.ratecol": "rate",
    "falsify.pythononly": "The flow analysis reads Python only: a finding in " +
      "another language can be refuted, but goes no further than exists.",
    "falsify.incomplete": "No complete hypothesis — a source and a sink — was " +
      "given, so there was nothing to refute: it stays at exists.",
    "falsify.notes": "The notes on each attempt are written by the analysis, in English.",
    "falsify.deadcode": "No complete hypothesis was given, but this refutation " +
      "needs none: nothing can run this code, or nothing dangerous reaches it.",
    "method.callgraph": "call graph",
    "method.sanitizer": "what reaches the sink",
    "method.reachability": "reachability",
    "method.devil_advocate": "devil's advocate",
    "result.survived": "survived",
    "result.refuted": "refuted",
    "result.inconclusive": "inconclusive",
    "result.none": "not tried",
    "hyp.title": "Hypothesis",
    "hyp.source": "source",
    "hyp.sink": "sink",
    "hyp.path": "path",
    "hyp.preconditions": "preconditions",
    "hyp.attempts": "Attempts to refute it",
    "hyp.notfound": "not in the repository: this quote does not count",
    "value.constant": "only literals reach it",
    "value.sanitized": "it is sanitised on the way",
    "value.tainted": "an unsanitised value reaches it",
    "value.parameterised": "the values travel as query parameters",
    "verdict.false_positive": "argued it is false",
    "verdict.holds": "could not argue it false",
    "verdict.unsure": "could not tell",
    "memory.question": "Has a flaw that was already fixed come back?",
    "memory.what": "Rules learnt from the project's own fixes, checked against " +
      "the commit that was vulnerable and the one that fixed it; the zombies " +
      "they catch; and their export to Semgrep.",
    "memory.notrun": "Immune memory did not run for this audit: it predates the module.",
    "memory.failed": "Immune memory failed for this audit; the findings stand without it.",
    "memory.zombies": "zombies",
    "memory.zombiesintro": "Findings of this audit that a fix had already removed " +
      "once: reported again by the model, or caught by a validated rule.",
    "memory.nozombies": "No fixed finding has come back.",
    "memory.fixedin": "fixed in",
    "memory.rules": "rules learnt from fixes",
    "memory.rulesintro": "One per finding shown to hold that a later commit removed. " +
      "A rule is validated only if it matches the code just before the fix and " +
      "not the fix itself.",
    "memory.norules": "No rule yet: none of this project's findings shown to hold " +
      "has been fixed between two audits.",
    "memory.rule": "rule",
    "memory.validation": "validation",
    "memory.validated": "validated",
    "memory.notvalidated": "not validated",
    "memory.counts": (a, b) => `before ${a} · after ${b}`,
    "memory.matches": "caught",
    "memory.export": "download the validated rules (Semgrep YAML)",
    "memory.noexport": "Nothing to export until a rule is validated.",
    "memory.provenance": "provenance",
    "memory.provenanceintro": "For each located finding, the oldest commit that " +
      "touched its lines (git blame). AI participation is what the commit " +
      "declares in its trailers: declared, not established.",
    "memory.located": "with provenance",
    "memory.aideclared": "AI participation declared",
    "memory.fixedcount": "fixed since the previous audit",
    "memory.nosemgrep": "Semgrep is not installed on this server: rules cannot " +
      "be validated or run.",
    "memory.proposalerror": (e) => `The rule request failed: ${e}`,
    "provenance.origin": "introduced in",
    "provenance.confidence": "confidence",
    "provenance.ai": "AI participation declared",
    "provenance.aiyes": "yes, in the commit's trailers",
    "provenance.aino": "none declared",
    "confidence.high": "high: one commit",
    "confidence.medium": "medium: several commits",
    "confidence.low": "low: history cut short",
    "zombie.badge": "zombie",
    "zombie.note": (title, sha) => `A fix had removed this finding before (\u201c${title}\u201d, fixed in ${sha}).`,
    "filter.origin": "origin",
    "filter.zombie": "zombies (fixed before)",
    "filter.ai": "AI participation declared",
    "leverage.question": "Which files give the most power over the system with the least oversight?",
    "leverage.what": "A map of every file by leverage against oversight, and " +
      "what each agent configuration lets an agent do.",
    "leverage.notrun": "The leverage map did not run for this audit: it predates the module.",
    "leverage.failed": "The leverage map failed for this audit; the findings stand without it.",
    "leverage.map": "leverage against oversight",
    "leverage.mapintro": "Each dot is a file. Further right, more damage a malicious " +
      "change there could do; lower, less review it gets. The shaded corner is " +
      "what to look at first.",
    "leverage.zone": "much leverage, little oversight",
    "leverage.axisx": "leverage",
    "leverage.axisy": "oversight",
    "leverage.files": "files, most exposed first",
    "leverage.filesintro": "Ordered by leverage × (1 − oversight).",
    "leverage.file": "file",
    "leverage.leverage": "leverage",
    "leverage.oversight": "oversight",
    "leverage.priority": "exposure",
    "leverage.why": "why",
    "leverage.showall": (n) => `show all ${n}`,
    "leverage.leftout": (n) => `${n} more files of little leverage are not listed.`,
    "leverage.nogithub": "Without SECAUDIT_GITHUB_TOKEN on this server, approvals and " +
      "branch protection are not known: oversight counts only CODEOWNERS and history.",
    "leverage.githuberror": (e) => `GitHub could not be asked: ${e}. What only it knows is reported as unknown.`,
    "leverage.githubok": (n) => `Asked GitHub (read-only, ${n} requests).`,
    "leverage.shallow": (n) => `Read from the last ${n} commits: changes before them are not seen.`,
    "leverage.codeowners": (f) => `CODEOWNERS: ${f}`,
    "leverage.nocodeowners": "The repository has no CODEOWNERS.",
    "leverage.leverageside": "leverage",
    "leverage.oversightside": "oversight",
    "leverage.lastcommit": "last change",
    "agent.title": "agent surface",
    "agent.intro": "What an AI agent opening this repository would inherit. A " +
      "combination that makes a complete path is shown as that path.",
    "agent.none": "No agent configuration: an agent opening it inherits nothing from it.",
    "agent.nocombo": "No combination makes a complete path.",
    "agent.source": "from",
    "agent.capability": "capability",
    "agent.detail": "what",
    "agent.unattended": "without anyone asking",
    "combo.exfiltration": "read files and send them out",
    "combo.steered_tools": "instructions that steer the agent's tools",
    "cap.reads_files": "reads files",
    "cap.network": "reaches the network",
    "cap.executes": "runs commands",
    "cap.runs_on_start": "runs on its own",
    "cap.mcp_server": "MCP server",
    "cap.instructions": "instructions",
    "reason.codeowners_file": "decides who must review everything else",
    "reason.ci_workflow": "a CI workflow: runs with the repository's permissions",
    "reason.ci_deploy": "deploys, releases or publishes",
    "reason.ci_secrets": "uses repository secrets",
    "reason.ci_pr_target": "runs on pull_request_target: other people's pull requests get the secrets",
    "reason.ci_write_perms": "can write to the repository or its packages",
    "reason.install_script": "runs on install or commit, on every developer's machine",
    "reason.container": "builds or runs the containers",
    "reason.lockfile": "decides which dependency code is installed",
    "reason.env_file": "an environment file: configuration and secrets",
    "reason.auto_execution": "runs on install, build, checkout or CI",
    "reason.agent_config": "read by AI agents as instructions or configuration",
    "reason.entry_point": "where outside input arrives",
    "reason.auth": "authentication, authorization or secrets",
    "reason.code": "application code",
    "reason.tests_docs": "tests, documentation or data",
    "reason.finding": (a) => `${a.count} finding(s) shown to hold`,
    "reason.divergence": (a) => `a divergence: ${t(`kind.${a.kind}`)}`,
    "reason.attack_path": "on an attack path",
    "reason.run_by": (a) => `run by ${a.by}, which runs on its own`,
    "reason.owner": (a) => `owned by ${(a.owners || []).join(", ")} in CODEOWNERS`,
    "reason.owners_removed": (a) => `CODEOWNERS removes its owners (${a.pattern})`,
    "reason.no_owner": "no owner in CODEOWNERS",
    "reason.no_codeowners": "no CODEOWNERS in the repository",
    "reason.approved": (a) => `${a.of === 1 ? "its last change" : `${a.count} of its last ${a.of} changes`} came through an approved pull request`,
    "reason.pr_unapproved": (a) => `${a.of === 1 ? "its last change" : `${a.count} of its last ${a.of} changes`} came through a pull request nobody else approved`,
    "reason.pr_approval_unknown": (a) => `${a.of === 1 ? "its last change" : `${a.count} of its last ${a.of} changes`} came through a pull request; whether it was approved is not known`,
    "reason.direct": (a) => `${a.of === 1 ? "its last change" : `${a.count} of its last ${a.of} changes`} went in without a pull request`,
    "reason.ai_unreviewed": "its last change declares AI participation and was not reviewed",
    "reason.old": "not changed in the history that was read",
    "reason.protected_reviews": (a) => `${a.branch} requires ${a.count} approving review(s)`,
    "reason.protected": (a) => `${a.branch} is protected, without required reviews`,
    "reason.unprotected": (a) => `${a.branch} is not protected`,
    "reason.protection_unknown": "branch protection not known",
    "attacker.question": "How far does each kind of attacker get, and which fix stops them first?",
    "attacker.what": "Choose a profile and a crown jewel to see the path " +
      "between them, step by step, with the evidence for each step.",
    "attacker.phase": "Arrives in phase 8.",
    "coverage.line": (c) => `${c.audited} of ${c.files} files audited in ` +
      `${c.requests} request${c.requests === 1 ? "" : "s"}` +
      (c.partial ? ` (${c.partial} in part)` : "") +
      (c.not_audited ? ` · ${c.not_audited} not audited` : ""),
    "coverage.highrisk": (n) => `${n} high-risk file${n === 1 ? " was" : "s were"} not audited`,
    "coverage.padding": "the repository looks padded: many near-identical or oversized files",
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
    "status.ok": "ok",
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
    "nav.skip": "saltar al contenido",
    "nav.toggle": "mostrar u ocultar las secciones",
    "nav.sections": "secciones",
    "nav.summary": "Resumen",
    "nav.findings": "Hallazgos",
    "nav.parallax": "Paralaje",
    "nav.falsifiability": "Falsabilidad",
    "nav.memory": "Memoria",
    "nav.leverage": "Palanca",
    "nav.attacker": "Atacante",
    "nav.history": "Historial",
    "nav.settings": "Ajustes",
    "nav.signout": "cerrar sesión",
    "nav.notrun": "sin ejecutar",
    "nav.phase": (n) => `fase ${n}`,
    "top.project": "proyecto",
    "top.audit": "auditoría",
    "top.search": "buscar hallazgos",
    "top.searchph": "buscar hallazgos  /",
    "theme.label": "tema",
    "theme.system": "como el sistema",
    "theme.dark": "oscuro",
    "theme.light": "claro",
    "theme.todark": "Cambiar a modo oscuro",
    "theme.tolight": "Cambiar a modo claro",
    "drawer.close": "cerrar el panel de detalle",
    "signin.title": "iniciar sesión",
    "signin.lead": "secaudit audita repositorios de GitHub con el modelo que " +
      "elijas. Inicia sesión para usar tu propia clave de API: tu clave y tus " +
      "auditorías son tuyas, y nadie más en esta instancia puede verlas.",
    "signin.button": "iniciar sesión con GitHub",
    "signin.disabled": "El inicio de sesión aún no está configurado en esta instancia.",
    "settings.title": "Motor de auditoría",
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
    "settings.display": "Visualización",
    "jewels.title": "Joyas de la corona",
    "jewels.phase": "Lo que un atacante querría por encima de todo en cada " +
      "proyecto: secretos, datos de usuarios, despliegue, administración. Se " +
      "declaran aquí a partir de la fase 8, junto con la sección Atacante.",
    "runner.title": "Ejecutar auditorías en tu propia máquina",
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
    "audits.title": "Auditorías",
    "audits.empty": "todavía no hay auditorías",
    "history.metrics": "Cómo evoluciona cada métrica de un commit al siguiente " +
      "se dibujará aquí cuando los módulos las registren.",
    "history.repo": "repositorio",
    "history.commit": "commit",
    "history.when": "cuándo",
    "history.status": "estado",
    "history.findings": "hallazgos",
    "history.coverage": "cobertura",
    "summary.noaudits": "Todavía no se ha auditado nada.",
    "summary.start": "empezar una auditoría",
    "summary.loading": "cargando…",
    "summary.integrity": "Integridad de la auditoría",
    "summary.integritynone": "Sin medir: en Paralaje se explica por qué.",
    "summary.divergences": (n) => `${n} punto(s) donde las vistas del ` +
      `repositorio no coinciden.`,
    "summary.seeparallax": "ver las divergencias",
    "summary.unreliable": "Sin hallazgos, pero el auditor no vio señuelos " +
      "plantados donde estaba mirando: este resultado limpio no es fiable.",
    "summary.coverage": "Cobertura",
    "summary.nocoverage": "Esta auditoría es anterior a la cobertura: no se " +
      "registró qué vio el auditor.",
    "summary.files": "Ficheros sin auditar o auditados en parte",
    "summary.allaudited": "Se auditaron todos los ficheros completos.",
    "summary.findings": "Hallazgos",
    "summary.seefindings": "ver los hallazgos",
    "summary.paths": "Caminos críticos y el arreglo que más corta",
    "summary.pathsphase": "La entrada más barata para cada perfil de atacante " +
      "y el arreglo único que cierra más caminos. Llega en la fase 8.",
    "summary.modules": "Qué se ejecutó",
    "summary.nomodules": "No hay ejecuciones de módulos registradas para esta auditoría.",
    "module.name": "módulo",
    "module.status": "estado",
    "module.model": "modelo",
    "module.tokens": "tokens entrada / salida",
    "module.duration": "duración",
    "module.audit": "auditoría",
    "module.evidence": "comprobación de evidencia",
    "module.falsifiability": "falsabilidad",
    "module.parallax": "paralaje",
    "coverage.file": "fichero",
    "coverage.reason": "motivo",
    "coverage.tier": "riesgo",
    "tier.1": "se ejecuta solo",
    "tier.2": "configuración de agentes",
    "tier.3": "punto de entrada",
    "tier.4": "autenticación y secretos",
    "tier.5": "código",
    "tier.6": "tests, documentación, datos",
    "findings.verifiedonly": "solo hallazgos con código que los respalde",
    "findings.none": "no se han reportado hallazgos",
    "findings.nonverified": "ningún hallazgo de esta auditoría tiene código que lo respalde",
    "findings.nomatch": "ningún hallazgo coincide con estos filtros",
    "findings.inprogress": "auditoría en curso…",
    "findings.failed": "la auditoría falló",
    "findings.nofindings": "sin hallazgos",
    "findings.unverified": "sin verificar",
    "findings.verified": "con código que lo respalda",
    "findings.counted": (n, v) => `${n} hallazgos · ${v} con código que los respalda`,
    "findings.showing": (n) => ` · ${n} mostrados`,
    "findings.expand": (title) => `ver más de: ${title}`,
    "findings.severity": "severidad",
    "findings.finding": "hallazgo",
    "findings.location": "ubicación",
    "findings.evidence": "evidencia",
    "findings.epistemic": "estado",
    "findings.category": "categoría",
    "findings.anchor": "ancla",
    "findings.note": "por qué no está verificado",
    "findings.snippet": "el código que cita",
    "findings.description": "descripción",
    "filter.severity": "severidad",
    "filter.evidence": "evidencia",
    "filter.epistemic": "estado epistémico",
    "filter.all": "todos",
    "filter.unverifiedonly": "solo sin verificar",
    "epistemic.exists": "existe",
    "epistemic.reachable": "alcanzable",
    "epistemic.corroborated": "corroborado",
    "epistemic.refuted": "refutado",
    "epistemic.inconclusive": "no concluyente",
    "epistemic.none": "sin establecer",
    "parallax.question": "¿Lee el modelo el repositorio como lo lee una persona?",
    "parallax.what": "Cada fichero visto de varias maneras —como lo lee una " +
      "persona, como bytes, como lo ejecuta la máquina, como se le mostró al " +
      "modelo, como se publicó— y cada punto donde esas vistas no coinciden, " +
      "anotado sobre el código.",
    "parallax.integrity": "Integridad del auditor",
    "parallax.integrityline": (found, planted) => `El auditor encontró ${found} ` +
      `de los ${planted} señuelos plantados en una copia de una de sus propias peticiones.`,
    "parallax.integritynote": "Es una señal, no una garantía: un contexto que " +
      "degrada al modelo se nota en señuelos que no ve, pero quien supiera de " +
      "ellos podría dejarlos pasar y ocultar lo real. Los señuelos nunca son hallazgos.",
    "parallax.integritynone": "No se midió en esta auditoría.",
    "parallax.runner": "Contado por tu runner, en tu máquina.",
    "parallax.decoy": "señuelo",
    "parallax.found": "encontrado",
    "parallax.missed": "no visto",
    "decoy.sql_injection": "inyección SQL",
    "decoy.command_injection": "inyección de comandos",
    "decoy.code_eval": "evaluación de la entrada",
    "decoy.insecure_deserialization": "deserialización insegura",
    "decoy.path_traversal": "recorrido de rutas",
    "kind.hidden_content": "Contenido oculto",
    "kind.unexpected_execution": "Ejecución inesperada",
    "kind.audit_blind_spot": "Puntos ciegos de la auditoría",
    "kind.release_mismatch": "Publicación que no es el código",
    "kinddesc.hidden_content": "Lo que ve una persona no es lo que dicen los " +
      "bytes: caracteres invisibles, comentarios que la página renderizada no muestra.",
    "kinddesc.unexpected_execution": "Algo se ejecuta —al instalar, al abrir la " +
      "carpeta, al arrancar un agente— sin que lo parezca.",
    "kinddesc.audit_blind_spot": "Lo que no se envió al auditor, lo que vio solo " +
      "en parte o ahogado en relleno.",
    "kinddesc.release_mismatch": "El paquete del registro no es el código de su " +
      "tag de git.",
    "parallax.nokind": "Nada de este tipo.",
    "parallax.notrun": "Paralaje no se ejecutó en esta auditoría: es anterior al módulo.",
    "parallax.failed": "Paralaje falló en esta auditoría; los hallazgos siguen en pie sin él.",
    "parallax.published": "Paquete publicado",
    "parallax.nopackage": "El repositorio no declara ningún paquete de Python ni de npm en su raíz.",
    "parallax.publishedoff": "Esta instancia no comprueba la vista publicada.",
    "parallax.compared": (name, tag, n) => `${name}: comparado con el tag ${tag} — ` +
      `${n} diferencia(s).`,
    "parallax.notcompared": (name) => `${name}: sin comparar.`,
    "parallax.notes": "Las descripciones las escribe el análisis, en inglés.",
    "parallax.file": "fichero",
    "parallax.divergence": "divergencia",
    "parallax.views": "vistas",
    "parallax.whole": "el repositorio",
    "parallax.sidebyside": "lado a lado",
    "parallax.overlay": "superpuestas",
    "parallax.notshown": "(no se ve)",
    "parallax.absent": "(no está)",
    "parallax.trigger": "se ejecuta al",
    "parallax.command": "qué se ejecuta",
    "parallax.decoded": "lo que dicen los caracteres ocultos",
    "parallax.files": "ficheros",
    "parallax.more": (n) => `… y ${n} más`,
    "parallax.truncated": "Solo se muestran las primeras líneas que difieren.",
    "parallax.nocheckout": "Sin comprobar: el servidor no pudo obtener el " +
      "commit auditado.",
    "parallax.expand": (what) => `ver las vistas de: ${what}`,
    "view.human": "lo que ve una persona",
    "view.bytes": "los bytes",
    "view.machine": "lo que se ejecuta",
    "view.llm": "lo que se envió al auditor",
    "view.published": "el paquete publicado",
    "falsifiability.question": "¿Sobrevive cada hallazgo a un intento serio de refutarlo?",
    "falsifiability.what": "Cada hallazgo respaldado por código se enuncia " +
      "como un flujo —dónde entra la entrada, el uso peligroso al que llega y " +
      "las funciones de en medio— y secaudit intenta refutarlo: por el grafo " +
      "de llamadas, por lo que de verdad llega al destino, por si algo de " +
      "fuera puede alcanzarlo y pidiendo al modelo que demuestre que es falso " +
      "citando código. Solo lo que sobrevive a los cuatro queda corroborado.",
    "falsify.statuses": "En qué estado quedan los hallazgos",
    "falsify.table": "Hipótesis e intentos de refutarlas",
    "falsify.none": "Ningún hallazgo de esta auditoría se enunció como " +
      "hipótesis. Las auditorías anteriores a este módulo no tienen.",
    "falsify.flow": "origen → destino",
    "falsify.rate": "Tasa de refutación por modelo",
    "falsify.rateintro": "De los hallazgos que cada modelo enunció como " +
      "hipótesis comprobable, en todas tus auditorías, la parte que cayó: una " +
      "tasa de falsos positivos medida.",
    "falsify.ratenone": "Todavía no se ha comprobado nada.",
    "falsify.model": "motor · modelo",
    "falsify.tested": "comprobados",
    "falsify.refuted": "refutados",
    "falsify.ratecol": "tasa",
    "falsify.pythononly": "El análisis de flujo solo lee Python: un hallazgo " +
      "en otro lenguaje puede refutarse, pero no pasa de «existe».",
    "falsify.incomplete": "No se dio una hipótesis completa —origen y " +
      "destino—, así que no había nada que refutar: se queda en «existe».",
    "falsify.notes": "Las notas de cada intento las escribe el análisis, en inglés.",
    "falsify.deadcode": "No se dio una hipótesis completa, pero esta refutación " +
      "no la necesita: nada puede ejecutar este código, o nada peligroso le llega.",
    "method.callgraph": "grafo de llamadas",
    "method.sanitizer": "qué llega al destino",
    "method.reachability": "alcanzabilidad",
    "method.devil_advocate": "abogado del diablo",
    "result.survived": "sobrevive",
    "result.refuted": "refutado",
    "result.inconclusive": "no concluyente",
    "result.none": "sin intentar",
    "hyp.title": "Hipótesis",
    "hyp.source": "origen",
    "hyp.sink": "destino",
    "hyp.path": "camino",
    "hyp.preconditions": "condiciones previas",
    "hyp.attempts": "Intentos de refutarla",
    "hyp.notfound": "no está en el repositorio: esta cita no cuenta",
    "value.constant": "solo le llegan literales",
    "value.sanitized": "se sanea por el camino",
    "value.tainted": "le llega un valor sin sanear",
    "value.parameterised": "los valores viajan como parámetros de la consulta",
    "verdict.false_positive": "argumenta que es falso",
    "verdict.holds": "no ha podido demostrar que sea falso",
    "verdict.unsure": "no ha sabido decirlo",
    "memory.question": "¿Ha vuelto algún fallo que ya se había arreglado?",
    "memory.what": "Reglas aprendidas de los propios arreglos del proyecto, " +
      "comprobadas contra el commit vulnerable y el que lo arregló; los " +
      "zombis que detectan; y su exportación a Semgrep.",
    "memory.notrun": "La memoria inmunológica no se ejecutó en esta auditoría: es anterior al módulo.",
    "memory.failed": "La memoria inmunológica falló en esta auditoría; los hallazgos siguen en pie sin ella.",
    "memory.zombies": "zombis",
    "memory.zombiesintro": "Hallazgos de esta auditoría que un arreglo ya había " +
      "quitado una vez: vueltos a informar por el modelo o atrapados por una regla validada.",
    "memory.nozombies": "No ha vuelto ningún hallazgo arreglado.",
    "memory.fixedin": "arreglado en",
    "memory.rules": "reglas aprendidas de los arreglos",
    "memory.rulesintro": "Una por cada hallazgo demostrado que un commit posterior " +
      "quitó. Una regla solo se valida si encaja con el código justo antes del " +
      "arreglo y no con el arreglo.",
    "memory.norules": "Aún no hay reglas: ningún hallazgo demostrado de este " +
      "proyecto se ha arreglado entre dos auditorías.",
    "memory.rule": "regla",
    "memory.validation": "validación",
    "memory.validated": "validada",
    "memory.notvalidated": "no validada",
    "memory.counts": (a, b) => `antes ${a} · después ${b}`,
    "memory.matches": "atrapados",
    "memory.export": "descargar las reglas validadas (YAML de Semgrep)",
    "memory.noexport": "No hay nada que exportar hasta que se valide una regla.",
    "memory.provenance": "procedencia",
    "memory.provenanceintro": "Para cada hallazgo localizado, el commit más " +
      "antiguo que tocó sus líneas (git blame). La participación de IA es la que " +
      "el commit declara en sus trailers: declarada, no demostrada.",
    "memory.located": "con procedencia",
    "memory.aideclared": "participación de IA declarada",
    "memory.fixedcount": "arreglados desde la auditoría anterior",
    "memory.nosemgrep": "Semgrep no está instalado en este servidor: las reglas " +
      "no se pueden validar ni ejecutar.",
    "memory.proposalerror": (e) => `La petición de reglas falló: ${e}`,
    "provenance.origin": "introducido en",
    "provenance.confidence": "confianza",
    "provenance.ai": "participación de IA declarada",
    "provenance.aiyes": "sí, en los trailers del commit",
    "provenance.aino": "ninguna declarada",
    "confidence.high": "alta: un commit",
    "confidence.medium": "media: varios commits",
    "confidence.low": "baja: historia cortada",
    "zombie.badge": "zombi",
    "zombie.note": (title, sha) => `Un arreglo ya había quitado este hallazgo («${title}», arreglado en ${sha}).`,
    "filter.origin": "origen",
    "filter.zombie": "zombis (arreglados antes)",
    "filter.ai": "participación de IA declarada",
    "leverage.question": "¿Qué ficheros dan más poder sobre el sistema con menos vigilancia?",
    "leverage.what": "Un mapa de todos los ficheros según su palanca frente a " +
      "su vigilancia, y lo que cada configuración de agente le permite hacer.",
    "leverage.notrun": "El mapa de palanca no se ejecutó en esta auditoría: es anterior al módulo.",
    "leverage.failed": "El mapa de palanca falló en esta auditoría; los hallazgos siguen en pie sin él.",
    "leverage.map": "palanca frente a vigilancia",
    "leverage.mapintro": "Cada punto es un fichero. Más a la derecha, más daño haría " +
      "un cambio malicioso ahí; más abajo, menos revisión recibe. La esquina " +
      "sombreada es lo primero que mirar.",
    "leverage.zone": "mucha palanca, poca vigilancia",
    "leverage.axisx": "palanca",
    "leverage.axisy": "vigilancia",
    "leverage.files": "ficheros, los más expuestos primero",
    "leverage.filesintro": "Ordenados por palanca × (1 − vigilancia).",
    "leverage.file": "fichero",
    "leverage.leverage": "palanca",
    "leverage.oversight": "vigilancia",
    "leverage.priority": "exposición",
    "leverage.why": "por qué",
    "leverage.showall": (n) => `ver los ${n}`,
    "leverage.leftout": (n) => `No se listan ${n} ficheros más de poca palanca.`,
    "leverage.nogithub": "Sin SECAUDIT_GITHUB_TOKEN en este servidor no se sabe de " +
      "aprobaciones ni de protección de rama: la vigilancia solo cuenta CODEOWNERS y la historia.",
    "leverage.githuberror": (e) => `No se pudo preguntar a GitHub: ${e}. Lo que solo sabe GitHub figura como desconocido.`,
    "leverage.githubok": (n) => `Consultado GitHub (solo lectura, ${n} peticiones).`,
    "leverage.shallow": (n) => `Leído de los últimos ${n} commits: los cambios anteriores no se ven.`,
    "leverage.codeowners": (f) => `CODEOWNERS: ${f}`,
    "leverage.nocodeowners": "El repositorio no tiene CODEOWNERS.",
    "leverage.leverageside": "palanca",
    "leverage.oversightside": "vigilancia",
    "leverage.lastcommit": "último cambio",
    "agent.title": "superficie de agentes",
    "agent.intro": "Lo que heredaría un agente de IA al abrir este repositorio. Una " +
      "combinación que forma un camino completo se muestra como ese camino.",
    "agent.none": "No hay configuración de agentes: un agente que lo abra no hereda nada de él.",
    "agent.nocombo": "Ninguna combinación forma un camino completo.",
    "agent.source": "de",
    "agent.capability": "capacidad",
    "agent.detail": "qué",
    "agent.unattended": "sin que nadie lo pida",
    "combo.exfiltration": "leer ficheros y sacarlos fuera",
    "combo.steered_tools": "instrucciones que dirigen las herramientas del agente",
    "cap.reads_files": "lee ficheros",
    "cap.network": "llega a la red",
    "cap.executes": "ejecuta órdenes",
    "cap.runs_on_start": "se ejecuta solo",
    "cap.mcp_server": "servidor MCP",
    "cap.instructions": "instrucciones",
    "reason.codeowners_file": "decide quién debe revisar todo lo demás",
    "reason.ci_workflow": "un workflow de CI: se ejecuta con los permisos del repositorio",
    "reason.ci_deploy": "despliega, publica o saca versiones",
    "reason.ci_secrets": "usa secretos del repositorio",
    "reason.ci_pr_target": "corre con pull_request_target: los PR de otros reciben los secretos",
    "reason.ci_write_perms": "puede escribir en el repositorio o en sus paquetes",
    "reason.install_script": "se ejecuta al instalar o al hacer commit, en la máquina de cada desarrollador",
    "reason.container": "construye o arranca los contenedores",
    "reason.lockfile": "decide qué código de dependencias se instala",
    "reason.env_file": "un fichero de entorno: configuración y secretos",
    "reason.auto_execution": "se ejecuta al instalar, compilar, hacer checkout o en CI",
    "reason.agent_config": "lo leen los agentes de IA como instrucciones o configuración",
    "reason.entry_point": "por donde llega la entrada de fuera",
    "reason.auth": "autenticación, autorización o secretos",
    "reason.code": "código de la aplicación",
    "reason.tests_docs": "tests, documentación o datos",
    "reason.finding": (a) => `${a.count} hallazgo(s) demostrado(s)`,
    "reason.divergence": (a) => `una divergencia: ${t(`kind.${a.kind}`)}`,
    "reason.attack_path": "en un camino de ataque",
    "reason.run_by": (a) => `lo ejecuta ${a.by}, que se ejecuta solo`,
    "reason.owner": (a) => `responsable en CODEOWNERS: ${(a.owners || []).join(", ")}`,
    "reason.owners_removed": (a) => `CODEOWNERS le quita los responsables (${a.pattern})`,
    "reason.no_owner": "sin responsable en CODEOWNERS",
    "reason.no_codeowners": "el repositorio no tiene CODEOWNERS",
    "reason.approved": (a) => a.of === 1 ? "su último cambio entró por un PR aprobado" : `${a.count} de sus ${a.of} últimos cambios entraron por un PR aprobado`,
    "reason.pr_unapproved": (a) => a.of === 1 ? "su último cambio entró por un PR que nadie más aprobó" : `${a.count} de sus ${a.of} últimos cambios entraron por un PR que nadie más aprobó`,
    "reason.pr_approval_unknown": (a) => a.of === 1 ? "su último cambio entró por un PR; no se sabe si se aprobó" : `${a.count} de sus ${a.of} últimos cambios entraron por un PR; no se sabe si se aprobó`,
    "reason.direct": (a) => a.of === 1 ? "su último cambio entró sin PR" : `${a.count} de sus ${a.of} últimos cambios entraron sin PR`,
    "reason.ai_unreviewed": "su último cambio declara participación de IA y no se revisó",
    "reason.old": "no ha cambiado en la historia leída",
    "reason.protected_reviews": (a) => `${a.branch} exige ${a.count} revisión(es) aprobada(s)`,
    "reason.protected": (a) => `${a.branch} está protegida, sin revisiones obligatorias`,
    "reason.unprotected": (a) => `${a.branch} no está protegida`,
    "reason.protection_unknown": "protección de rama desconocida",
    "attacker.question": "¿Hasta dónde llega cada tipo de atacante y qué arreglo lo frena antes?",
    "attacker.what": "Elige un perfil y una joya de la corona para ver el " +
      "camino entre ellos, paso a paso, con la evidencia de cada paso.",
    "attacker.phase": "Llega en la fase 8.",
    "coverage.line": (c) => `${c.audited} de ${c.files} ficheros auditados en ` +
      `${c.requests} petici${c.requests === 1 ? "ón" : "ones"}` +
      (c.partial ? ` (${c.partial} en parte)` : "") +
      (c.not_audited ? ` · ${c.not_audited} sin auditar` : ""),
    "coverage.highrisk": (n) => `${n} fichero${n === 1 ? "" : "s"} de alto riesgo sin auditar`,
    "coverage.padding": "el repositorio parece rellenado: muchos ficheros casi idénticos o enormes",
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
    "status.ok": "correcto",
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
  const saved = stored(LANG_KEY);
  if (LANGUAGES.includes(saved)) return saved;
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
  for (const target of document.querySelectorAll("[data-i18n-label]")) {
    target.setAttribute("aria-label", t(target.dataset.i18nLabel));
  }
  renderThemeToggle();
}

const el = (id) => document.getElementById(id);

function node(tag, className, text) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function button(text, className, onClick) {
  const b = node("button", className, text);
  b.type = "button";
  if (onClick) b.addEventListener("click", onClick);
  return b;
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

function totalOf(summary) {
  return Object.values(summary || {}).reduce((a, b) => a + b, 0);
}

// Severity is never colour alone: the word is always there, the marker's
// shape differs per level (style.css).
function severityNode(severity, count) {
  const label = t(`severity.${severity}`);
  return node("span", `severity severity-${severity}`,
              count === undefined ? label : `${label} ${count}`);
}

function statusNode(status) {
  return node("span", `status status-${status}`, t(`status.${status}`));
}

function countsNode(summary) {
  const counts = node("div", "counts");
  for (const severity of SEVERITIES) {
    const n = (summary && summary[severity]) || 0;
    if (n > 0) counts.append(severityNode(severity, n));
  }
  if (totalOf(summary) === 0) counts.append(node("span", "muted", t("findings.nofindings")));
  return counts;
}

function headerRow(headers) {
  const head = document.createElement("thead");
  const tr = document.createElement("tr");
  for (const h of headers) {
    const th = node("th", h.className, h.text);
    th.scope = "col";
    tr.append(th);
  }
  head.append(tr);
  return head;
}

// bodies: <tr>s for a single <tbody>, or <tbody>s when rows come in groups.
function table(headers, bodies) {
  const wrap = node("div", "table-wrap");
  const tbl = document.createElement("table");
  tbl.append(headerRow(headers));
  if (bodies.length && bodies[0].tagName === "TBODY") {
    tbl.append(...bodies);
  } else {
    const body = document.createElement("tbody");
    body.append(...bodies);
    tbl.append(body);
  }
  wrap.append(tbl);
  return wrap;
}

function row(cells, className) {
  const tr = document.createElement("tr");
  if (className) tr.className = className;
  for (const cell of cells) {
    const td = document.createElement("td");
    const plain = cell === null || cell === undefined || typeof cell !== "object"
      || cell instanceof Node;
    const content = plain ? cell : cell.content;
    if (!plain && cell.className) td.className = cell.className;
    if (content instanceof Node) td.append(content);
    else if (content !== null && content !== undefined) td.textContent = String(content);
    tr.append(td);
  }
  return tr;
}

function block(titleText, ...children) {
  const section = node("section", "block");
  section.append(node("h2", null, titleText), ...children);
  return section;
}

function facts(pairs) {
  const dl = node("dl", "facts");
  for (const [term, value] of pairs) {
    const item = document.createElement("div");
    const dd = document.createElement("dd");
    if (value instanceof Node) dd.append(value);
    else dd.textContent = String(value);
    item.append(node("dt", null, term), dd);
    dl.append(item);
  }
  return dl;
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

const state = {
  loaded: false,           // the list of audits has arrived at least once
  audits: [],
  current: null,           // the selected audit, with its findings
  selectedId: null,
  section: "summary",
  coverage: new Map(),     // audit id -> coverage rows, fetched when opened
  expanded: new Set(),     // finding ids whose row is open
  drawerFinding: null,     // finding id shown in the detail panel
  drawerDivergence: null,  // or the divergence id shown there instead
  drawerFile: null,        // or the path whose leverage is shown there
  leverageAll: false,
  expandedViews: new Set(), // divergence ids whose views are open in the table
  viewMode: stored("secaudit.views") === "overlay" ? "overlay" : "side",
  drawerOpener: null,      // what gets focus back when the panel closes
  query: "",
  stats: undefined,        // refutation rate per model; fetched per visit
};

let pollTimer = null;

// One project per owner and repository. Audits from before projects existed
// were given one by migration 0010, so project_id is only missing on an audit
// that has not been stored yet; the repository stands in for it.
function projectKey(audit) {
  return audit.project_id ? `p${audit.project_id}` : `r${audit.repo_url}`;
}

function projects() {
  const byKey = new Map();
  for (const audit of state.audits) {
    const key = projectKey(audit);
    if (!byKey.has(key)) byKey.set(key, { key, repo_url: audit.repo_url, audits: [] });
    byKey.get(key).audits.push(audit);
  }
  return [...byKey.values()];
}

function selectedAudit() {
  return state.audits.find((a) => a.id === state.selectedId) || null;
}

// ---------------------------------------------------------------------------
// routing: #section or #section/<audit id>
// ---------------------------------------------------------------------------

function parseHash() {
  const [section, id] = location.hash.replace(/^#/, "").split("/");
  return { section: SECTIONS.includes(section) ? section : "summary",
           id: id ? decodeURIComponent(id) : null };
}

function hashFor(section, id) {
  return AUDIT_SECTIONS.has(section) && id
    ? `#${section}/${encodeURIComponent(id)}` : `#${section}`;
}

function go(section, id = state.selectedId) {
  const target = hashFor(section, id);
  if (location.hash === target) applyRoute();
  else location.hash = target;
}

function renderNavLinks() {
  for (const link of document.querySelectorAll("[data-section]")) {
    link.href = hashFor(link.dataset.section, state.selectedId);
    if (link.dataset.section === state.section) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function applyRoute() {
  if (el("app").hidden) return;
  const { section, id } = parseHash();
  const sectionChanged = section !== state.section;
  state.section = section;
  if (id && id !== state.selectedId) selectAudit(id, { route: false });
  for (const view of document.querySelectorAll("[data-view]")) {
    view.hidden = view.dataset.view !== section;
  }
  if (narrow()) setNav(false);
  renderSection();
  if (sectionChanged) el("content").scrollTop = 0;
  if (section === "settings") loadSettings();
  if (section === "falsifiability" && sectionChanged) loadStats();
}

window.addEventListener("hashchange", applyRoute);

// ---------------------------------------------------------------------------
// top bar: project and audit
// ---------------------------------------------------------------------------

function auditLabel(audit) {
  const when = audit.created_at ? new Date(audit.created_at).toLocaleString(lang, {
    dateStyle: "short", timeStyle: "short" }) : "";
  const what = shortSha(audit.commit_sha) || t(`status.${audit.status}`);
  return [what, audit.branch, when].filter(Boolean).join(" · ");
}

function renderContext() {
  const all = projects();
  el("context").hidden = all.length === 0;
  const current = selectedAudit();
  const currentKey = current ? projectKey(current) : null;

  const projectSelect = el("project-select");
  projectSelect.replaceChildren(...all.map((p) => {
    const option = node("option", null, repoLabel(p.repo_url));
    option.value = p.key;
    return option;
  }));
  if (currentKey) projectSelect.value = currentKey;

  const project = all.find((p) => p.key === currentKey);
  const auditSelect = el("audit-select");
  auditSelect.replaceChildren(...(project ? project.audits : []).map((a) => {
    const option = node("option", null, auditLabel(a));
    option.value = a.id;
    return option;
  }));
  if (current) auditSelect.value = current.id;
}

el("project-select").addEventListener("change", () => {
  const project = projects().find((p) => p.key === el("project-select").value);
  if (project) selectAudit(project.audits[0].id);
});

el("audit-select").addEventListener("change", () => {
  selectAudit(el("audit-select").value);
});

// ---------------------------------------------------------------------------
// sidebar indicators: the state of the last run and how many items it left
// ---------------------------------------------------------------------------

function setIndicator(name, text, stateName, label) {
  const target = document.querySelector(`[data-indicator="${name}"]`);
  target.textContent = text || "";
  if (stateName) target.dataset.state = stateName;
  else delete target.dataset.state;
  if (label) target.title = label;
  else target.removeAttribute("title");
}

function renderIndicators() {
  const audit = selectedAudit();
  const current = state.current && state.current.id === state.selectedId
    ? state.current : null;
  const coverage = audit && audit.coverage;
  const auditState = !audit ? null
    : ACTIVE_STATUSES.has(audit.status) ? "running"
    : audit.status === "error" ? "error" : "ok";
  setIndicator("summary",
               coverage && coverage.files
                 ? `${Math.round((100 * coverage.audited) / coverage.files)}%` : "",
               auditState, audit ? t(`status.${audit.status}`) : null);
  setIndicator("findings", audit && audit.status === "done"
    ? String(totalOf(audit.summary)) : "");
  const runs = (current && current.modules) || [];
  for (const [section, module] of Object.entries(MODULES)) {
    const run = runs.filter((r) => r.module === module.run).pop();
    if (run) {
      const items = run.detail && Number.isFinite(run.detail.items)
        ? String(run.detail.items) : t(`status.${run.status}`);
      setIndicator(section, items, run.status === "ok" ? "ok" : "error",
                   t(`status.${run.status}`));
    } else {
      setIndicator(section, t("nav.phase", module.phase), null, t("nav.notrun"));
    }
  }
  setIndicator("history", state.audits.length ? String(state.audits.length) : "");
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

function renderSection() {
  renderNavLinks();
  renderContext();
  renderIndicators();
  if (state.section === "summary") renderSummary();
  else if (state.section === "findings") renderFindings();
  else if (state.section === "falsifiability") renderFalsifiability();
  else if (state.section === "parallax") renderParallax();
  else if (state.section === "memory") renderMemory();
  else if (state.section === "leverage") renderLeverage();
  else if (state.section === "history") renderHistory();
  renderDrawerFinding();
}

// Fills target with why there is nothing to show yet, if there is not.
function needsAudit(target) {
  if (!state.loaded || (state.selectedId && !(state.current
      && state.current.id === state.selectedId))) {
    target.replaceChildren(node("p", "muted", t("summary.loading")));
    return true;
  }
  if (!state.selectedId) {
    const empty = node("div", "empty-state");
    empty.append(node("p", null, t("summary.noaudits")),
                 button(t("summary.start"), null, () => {
                   go("history");
                   el("repo-url").focus();
                 }));
    target.replaceChildren(empty);
    return true;
  }
  return false;
}

function deleteButton(audit) {
  // Two clicks rather than a modal: the second one is the confirmation.
  const b = button(t("detail.delete"), "ghost danger");
  let armed = false;
  b.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      b.textContent = t("detail.deleteconfirm");
      setTimeout(() => {
        armed = false;
        b.textContent = t("detail.delete");
      }, 4000);
      return;
    }
    b.disabled = true;
    try {
      await api(`/api/audits/${encodeURIComponent(audit.id)}`, { method: "DELETE" });
      state.selectedId = null;
      state.current = null;
      closeDrawer();
      await refresh();
      go(state.section);
    } catch (e) {
      b.disabled = false;
      b.textContent = e.message;
    }
  });
  return b;
}

function auditHead(audit) {
  const wrap = document.createDocumentFragment();
  const head = node("div", "audit-head");
  head.append(node("span", "audit-repo-title", repoLabel(audit.repo_url)),
              deleteButton(audit));
  const pairs = [
    [t("detail.status"), statusNode(audit.status)],
    [t("detail.branch"), audit.branch || t("detail.default")],
    [t("detail.commit"), shortSha(audit.commit_sha) || "—"],
    [t("detail.trigger"), t(`trigger.${audit.trigger}`)],
    [t("detail.language"), audit.language || "en"],
    [t("detail.started"),
     audit.created_at ? new Date(audit.created_at).toLocaleString(lang) : "—"],
  ];
  if (audit.error) pairs.push([t("detail.error"), audit.error]);
  wrap.append(head, facts(pairs));
  return wrap;
}

function coverageBlock(audit) {
  const coverage = audit.coverage;
  const section = block(t("summary.coverage"));
  if (!coverage || !coverage.files) {
    section.append(node("p", "muted",
                        ACTIVE_STATUSES.has(audit.status) ? t("findings.inprogress")
                          : audit.status === "error" ? t("findings.failed")
                          : t("summary.nocoverage")));
    return section;
  }
  section.append(node("p", null, t("coverage.line", coverage)));
  if (coverage.high_risk_not_audited) {
    section.append(node("p", "coverage-warning",
                        t("coverage.highrisk", coverage.high_risk_not_audited)));
  }
  if (coverage.padding_suspected) {
    section.append(node("p", "coverage-warning", t("coverage.padding")));
  }

  // The list is long and read rarely: fetched the first time it is opened.
  const details = node("details", "block");
  details.append(node("summary", null, t("summary.files")));
  const holder = node("div");
  details.append(holder);
  const fill = () => {
    const left = state.coverage.get(audit.id)
      .filter((r) => !r.audited || String(r.reason).startsWith("audited in part"))
      .sort((a, b) => a.risk_tier - b.risk_tier || a.file.localeCompare(b.file));
    if (left.length === 0) {
      holder.replaceChildren(node("p", "muted", t("summary.allaudited")));
      return;
    }
    holder.replaceChildren(table(
      [{ text: t("coverage.file") }, { text: t("coverage.tier") },
       { text: t("coverage.reason") }],
      left.map((r) => row([{ className: "where", content: r.file },
                           t(RISK_TIERS[r.risk_tier] || "tier.5"),
                           r.reason]))));
  };
  details.addEventListener("toggle", async () => {
    if (!details.open) return;
    if (!state.coverage.has(audit.id)) {
      holder.replaceChildren(node("p", "muted", t("summary.loading")));
      try {
        const body = await api(`/api/audits/${encodeURIComponent(audit.id)}/coverage`);
        state.coverage.set(audit.id, body.files || []);
      } catch (e) {
        holder.replaceChildren(node("p", "error", e.message));
        return;
      }
    }
    fill();
  });
  section.append(details);
  return section;
}

function moduleRunsBlock(audit) {
  const details = node("details", "block");
  details.append(node("summary", null, t("summary.modules")));
  const runs = audit.modules || [];
  if (runs.length === 0) {
    details.append(node("p", "muted", t("summary.nomodules")));
    return details;
  }
  const number = (n) => Number(n || 0).toLocaleString(lang);
  details.append(table(
    [{ text: t("module.name") }, { text: t("module.status") },
     { text: t("module.model") }, { text: t("module.tokens"), className: "num" },
     { text: t("module.duration"), className: "num" }],
    runs.map((r) => row([
      TEXT.en[`module.${r.module}`] ? t(`module.${r.module}`) : r.module,
      statusNode(r.status),
      [r.backend, r.model].filter(Boolean).join(" · ") || "—",
      { className: "num", content: r.tokens_in || r.tokens_out
        ? `${number(r.tokens_in)} / ${number(r.tokens_out)}` : "—" },
      { className: "num", content: Number.isFinite(r.duration_ms)
        ? `${(r.duration_ms / 1000).toFixed(1)} s` : "—" },
    ]))));
  return details;
}

function parallaxRun(audit) {
  return (audit.modules || []).filter((r) => r.module === "parallax").pop() || null;
}

function integrityBlock(audit, total) {
  const section = block(t("summary.integrity"));
  const c = audit.canary;
  const run = parallaxRun(audit);
  if (!run) {
    section.append(node("p", "placeholder", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("parallax.notrun")));
    return section;
  }
  if (c) {
    section.append(node("p", null, t("parallax.integrityline", c.found, c.planted)));
    // "Clean" from an auditor that missed what was planted in front of it is
    // not a clean bill: said in so many words.
    if (audit.status === "done" && total === 0 && c.found < c.planted) {
      section.append(node("p", "coverage-warning", t("summary.unreliable")));
    }
  } else {
    section.append(node("p", "muted", t("summary.integritynone")));
  }
  const n = (audit.divergences || []).length;
  if (n) {
    section.append(node("p", null, t("summary.divergences", n)),
                   button(t("summary.seeparallax"), "link", () => go("parallax")));
  }
  return section;
}

function renderSummary() {
  const target = el("summary-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const total = totalOf(audit.summary);

  const findings = block(t("summary.findings"), countsNode(audit.summary));
  if (audit.status === "done" && total > 0) {
    findings.append(node("p", "muted", t("findings.counted", total, audit.verified_count || 0)),
                    button(t("summary.seefindings"), "link", () => go("findings")));
  } else if (ACTIVE_STATUSES.has(audit.status)) {
    findings.append(node("p", "muted", t("findings.inprogress")));
  }

  // Keep open whatever the reader had open across the re-render polling does.
  const open = new Set([...target.querySelectorAll("details[open] > summary")]
    .map((s) => s.textContent));
  target.replaceChildren(
    auditHead(audit),
    integrityBlock(audit, total),
    coverageBlock(audit),
    findings,
    block(t("summary.paths"), node("p", "placeholder", t("summary.pathsphase"))),
    moduleRunsBlock(audit),
  );
  for (const summary of target.querySelectorAll("details > summary")) {
    if (open.has(summary.textContent)) summary.parentElement.open = true;
  }
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

function whereText(finding) {
  // line is where the snippet was found in the file, checked by the server.
  const lines = finding.line_end && finding.line_end !== finding.line
    ? `${finding.line}-${finding.line_end}` : finding.line;
  return finding.line ? `${finding.file}:${lines}` : finding.file || "";
}

function filteredFindings() {
  const severity = el("filter-severity").value;
  const evidence = el("filter-evidence").value;
  const epistemic = el("filter-epistemic").value;
  const origin = el("filter-origin").value;
  const query = state.query.trim().toLowerCase();
  const order = new Map(SEVERITIES.map((s, i) => [s, i]));
  return (state.current.findings || [])
    .filter((f) => !severity || f.severity === severity)
    .filter((f) => evidence !== "unverified" || f.verification_status !== "verified")
    .filter((f) => !epistemic
            || (epistemic === "none" ? !f.epistemic_status : f.epistemic_status === epistemic))
    .filter((f) => origin !== "zombie" || f.zombie_of)
    .filter((f) => origin !== "ai" || (f.provenance && f.provenance.ai_declared))
    .filter((f) => !query || [f.title, f.file, f.anchor, f.description, f.category,
                              categoryLabel(f.category)]
      .some((v) => String(v || "").toLowerCase().includes(query)))
    .sort((a, b) => (order.get(a.severity) ?? 99) - (order.get(b.severity) ?? 99));
}

function epistemicNode(finding) {
  const status = finding.epistemic_status;
  return node("span", `badge${status ? ` badge-${status}` : ""}`,
              t(`epistemic.${status || "none"}`));
}

function evidenceNode(finding) {
  const verified = finding.verification_status === "verified";
  return node("span", verified ? null : "muted",
              verified ? t("findings.verified") : t("findings.unverified"));
}

// What the expanded row and the detail panel both show.
function findingBody(finding, { full }) {
  const parts = document.createDocumentFragment();
  const verified = finding.verification_status === "verified";
  if (full) {
    const pairs = [
      [t("findings.severity"), severityNode(finding.severity)],
      [t("findings.evidence"), evidenceNode(finding)],
      [t("findings.epistemic"), epistemicNode(finding)],
      [t("findings.category"), categoryLabel(finding.category) || "—"],
      [t("findings.location"), node("span", "where", whereText(finding) || "—")],
    ];
    if (finding.anchor) pairs.push([t("findings.anchor"), node("span", "where", finding.anchor)]);
    const p = finding.provenance;
    if (p) {
      pairs.push([t("provenance.origin"), commitNode(p.origin_commit)],
                 [t("provenance.confidence"), t(`confidence.${p.confidence}`)],
                 [t("provenance.ai"), t(p.ai_declared ? "provenance.aiyes" : "provenance.aino")]);
    }
    parts.append(facts(pairs));
  }
  if (finding.zombie_of) {
    const z = finding.zombie_of;
    parts.append(node("p", "note zombie-note",
                      t("zombie.note", z.title || "—", shortSha(z.fix_commit) || "—")));
  }
  // The snippet is code from an audited third-party repo: textContent only.
  // An unverified one is not shown as if it were the file's.
  if (verified && finding.code_snippet) {
    if (full) parts.append(node("h3", null, t("findings.snippet")));
    parts.append(node("pre", "snippet", finding.code_snippet));
  }
  if (!verified && finding.verification_note) {
    if (full) parts.append(node("h3", null, t("findings.note")));
    parts.append(node("p", "note", finding.verification_note));
  }
  if (finding.description) {
    if (full) parts.append(node("h3", null, t("findings.description")));
    parts.append(node("p", "prose", finding.description));
  }
  if (full) parts.append(hypothesisNodes(finding));
  return parts;
}

function findingRows(finding) {
  const body = document.createElement("tbody");
  const verified = finding.verification_status === "verified";
  const open = state.expanded.has(finding.id);
  const expandId = `finding-more-${finding.id}`;

  const toggle = button("", "toggle");
  toggle.setAttribute("aria-expanded", String(open));
  toggle.setAttribute("aria-controls", expandId);
  toggle.setAttribute("aria-label", t("findings.expand", finding.title));

  const title = button(finding.title, "link");
  title.dataset.finding = String(finding.id);
  title.addEventListener("click", () => openFinding(finding.id, title));
  const titleCell = document.createDocumentFragment();
  titleCell.append(title);
  if (finding.zombie_of) titleCell.append(" ", node("span", "badge badge-zombie", t("zombie.badge")));

  const main = row([
    toggle,
    severityNode(finding.severity),
    { className: "finding-title-cell", content: titleCell },
    { className: "where hide-narrow", content: whereText(finding) },
    { className: "hide-narrow", content: evidenceNode(finding) },
    { className: "hide-narrow", content: epistemicNode(finding) },
  ], `finding-row${verified ? "" : " unverified"}`);
  main.setAttribute("aria-selected", String(state.drawerFinding === finding.id));

  const more = document.createElement("tr");
  more.className = "finding-expand";
  more.id = expandId;
  more.hidden = !open;
  const cell = document.createElement("td");
  cell.colSpan = 6;
  if (whereText(finding)) cell.append(node("div", "where", whereText(finding)));
  cell.append(findingBody(finding, { full: false }));
  more.append(cell);

  toggle.addEventListener("click", () => {
    const now = !state.expanded.has(finding.id);
    if (now) state.expanded.add(finding.id);
    else state.expanded.delete(finding.id);
    toggle.setAttribute("aria-expanded", String(now));
    more.hidden = !now;
  });
  body.append(main, more);
  return body;
}

function renderFindings() {
  const target = el("findings-body");
  const count = el("findings-count");
  count.textContent = "";
  if (needsAudit(target)) return;
  const audit = state.current;
  const findings = audit.findings || [];
  const total = totalOf(audit.summary);

  if (findings.length === 0) {
    const message = ACTIVE_STATUSES.has(audit.status) ? t("findings.inprogress")
      : audit.status === "error" ? t("findings.failed")
      : el("filter-evidence").value === "verified" && total > 0 ? t("findings.nonverified")
      : t("findings.none");
    target.replaceChildren(node("p", "muted", message));
    return;
  }
  const shown = filteredFindings();
  count.textContent = t("findings.counted", total, audit.verified_count || 0) +
    (shown.length !== total ? t("findings.showing", shown.length) : "");
  if (shown.length === 0) {
    target.replaceChildren(node("p", "muted", t("findings.nomatch")));
    return;
  }
  // A re-render must not drop the keyboard: put focus back where it was.
  const focused = document.activeElement && target.contains(document.activeElement)
    ? document.activeElement.dataset.finding : null;
  target.replaceChildren(table([
    { text: "" },
    { text: t("findings.severity") },
    { text: t("findings.finding") },
    { text: t("findings.location"), className: "hide-narrow" },
    { text: t("findings.evidence"), className: "hide-narrow" },
    { text: t("findings.epistemic"), className: "hide-narrow" },
  ], shown.map(findingRows)));
  if (focused) {
    const again = target.querySelector(`[data-finding="${CSS.escape(focused)}"]`);
    if (again) again.focus();
  }
}

for (const id of ["filter-severity", "filter-epistemic", "filter-origin"]) {
  el(id).addEventListener("change", renderFindings);
}

// "Only backed by code" is asked of the server, as it always was; "only
// unverified" is a view over what is already here.
el("filter-evidence").addEventListener("change", () => {
  if (state.selectedId) loadDetail(state.selectedId);
});

el("filters").addEventListener("submit", (event) => event.preventDefault());

el("search").addEventListener("input", () => {
  state.query = el("search").value;
  if (state.section !== "findings") go("findings");
  else renderFindings();
});

// ---------------------------------------------------------------------------
// falsifiability (module 2)
// ---------------------------------------------------------------------------

const METHODS = ["callgraph", "sanitizer", "reachability", "devil_advocate"];
const EPISTEMIC_ORDER = ["corroborated", "reachable", "exists", "inconclusive",
                         "refuted", null];

function resultNode(result) {
  return node("span", `result result-${result || "none"}`, t(`result.${result || "none"}`));
}

function isPython(finding) {
  return String(finding.file || "").endsWith(".py");
}

function attemptNode(a) {
  const item = node("li", "attempt");
  const head = node("div", "attempt-head");
  head.append(node("span", "attempt-method", t(`method.${a.method}`)), resultNode(a.result));
  item.append(head);
  const ev = a.evidence || {};
  if (ev.verdict) item.append(node("div", null, t(`verdict.${ev.verdict}`)));
  if (Array.isArray(ev.chain)) item.append(node("div", "where", ev.chain.join("  →  ")));
  if (ev.value) {
    const how = [t(`value.${ev.value}`)];
    if (Array.isArray(ev.through) && ev.through.length) how.push(`(${ev.through.join(", ")})`);
    item.append(node("div", null, how.join(" ")));
  }
  if (ev.call) item.append(node("div", "where", `${ev.call}${ev.line ? `  ·  ${ev.line}` : ""}`));
  if (ev.why) item.append(node("div", "muted", ev.why));
  if (ev.argument) item.append(node("p", "prose", ev.argument));
  // What the second model quoted: shown as code only if it is in the repo.
  for (const c of Array.isArray(ev.citations) ? ev.citations : []) {
    const cite = node("div", c.found ? "citation" : "citation citation-missing");
    cite.append(node("div", "where", c.found
      ? `${c.file}:${c.line}${c.line_end && c.line_end !== c.line ? `-${c.line_end}` : ""}`
      : `${c.file || "—"} — ${t("hyp.notfound")}`));
    cite.append(node("pre", c.found ? "snippet" : "snippet snippet-claimed", c.code_snippet));
    item.append(cite);
  }
  if (a.note) item.append(node("p", "note", a.note));
  return item;
}

// The hypothesis of a finding and what was tried against it, for the panel.
function hypothesisNodes(finding) {
  const parts = document.createDocumentFragment();
  const h = finding.hypothesis;
  if (!h) return parts;
  parts.append(node("h3", null, t("hyp.title")));
  const pairs = [[t("hyp.source"), h.source || "—"], [t("hyp.sink"), h.sink || "—"]];
  if (h.path && h.path.length) pairs.push([t("hyp.path"), h.path.join("  →  ")]);
  if (h.preconditions && h.preconditions.length) {
    pairs.push([t("hyp.preconditions"), h.preconditions.join("; ")]);
  }
  const dl = facts(pairs);
  dl.classList.add("facts-wide");
  parts.append(dl);
  if (!h.complete) {
    parts.append(node("p", "muted", t(h.attempts && h.attempts.length
      ? "falsify.deadcode" : "falsify.incomplete")));
  } else if (!isPython(finding) && finding.verification_status === "verified") {
    parts.append(node("p", "muted", t("falsify.pythononly")));
  }
  if (h.attempts && h.attempts.length) {
    parts.append(node("h3", null, t("hyp.attempts")));
    const list = node("ol", "attempts");
    list.append(...h.attempts.map(attemptNode));
    parts.append(list, node("p", "muted small", t("falsify.notes")));
  }
  return parts;
}

async function loadStats() {
  state.stats = undefined;
  try {
    state.stats = await api("/api/stats/refutation");
  } catch (_) {
    state.stats = [];
  }
  if (state.section === "falsifiability") renderFalsifiability();
}

function ratesBlock() {
  const section = block(t("falsify.rate"), node("p", "muted", t("falsify.rateintro")));
  if (state.stats === undefined) {
    section.append(node("p", "muted", t("summary.loading")));
  } else if (!state.stats.length) {
    section.append(node("p", "muted", t("falsify.ratenone")));
  } else {
    section.append(table(
      [{ text: t("falsify.model") }, { text: t("falsify.tested"), className: "num" },
       { text: t("falsify.refuted"), className: "num" },
       { text: t("falsify.ratecol"), className: "num" }],
      state.stats.map((r) => row([
        [r.backend, r.model].filter(Boolean).join(" · ") || "—",
        { className: "num", content: r.tested },
        { className: "num", content: r.refuted },
        { className: "num", content: `${Math.round(r.rate * 100)} %` },
      ]))));
  }
  return section;
}

function renderFalsifiability() {
  const target = el("falsifiability-body");
  if (needsAudit(target)) return;
  const findings = state.current.findings || [];
  const order = new Map(SEVERITIES.map((s, i) => [s, i]));

  const counts = new Map();
  for (const f of findings) {
    const key = f.epistemic_status || null;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const statuses = node("div", "counts");
  for (const key of EPISTEMIC_ORDER) {
    if (!counts.get(key)) continue;
    const badge = epistemicNode({ epistemic_status: key });
    badge.textContent = `${badge.textContent} ${counts.get(key)}`;
    statuses.append(badge);
  }
  if (!findings.length) statuses.append(node("span", "muted", t("findings.nofindings")));

  const tested = findings.filter((f) => f.hypothesis)
    .sort((a, b) => (order.get(a.severity) ?? 99) - (order.get(b.severity) ?? 99));
  const hypotheses = block(t("falsify.table"));
  if (!tested.length) {
    hypotheses.append(node("p", "muted", t("falsify.none")));
  } else {
    hypotheses.append(table(
      [{ text: t("findings.severity") }, { text: t("findings.finding") },
       { text: t("falsify.flow"), className: "hide-narrow" },
       { text: t("findings.epistemic") },
       ...METHODS.map((m) => ({ text: t(`method.${m}`), className: "hide-narrow" }))],
      tested.map((f) => {
        const byMethod = Object.fromEntries((f.hypothesis.attempts || [])
          .map((a) => [a.method, a.result]));
        const title = button(f.title, "link");
        title.dataset.finding = String(f.id);
        title.addEventListener("click", () => openFinding(f.id, title));
        const r = row([
          severityNode(f.severity),
          title,
          { className: "where hide-narrow",
            content: `${f.hypothesis.source || "—"}  →  ${f.hypothesis.sink || "—"}` },
          epistemicNode(f),
          ...METHODS.map((m) => ({ className: "hide-narrow",
                                   content: resultNode(byMethod[m]) })),
        ], "finding-row");
        r.setAttribute("aria-selected", String(state.drawerFinding === f.id));
        return r;
      })));
    if (tested.some((f) => !isPython(f))) {
      hypotheses.append(node("p", "muted", t("falsify.pythononly")));
    }
  }
  target.replaceChildren(block(t("falsify.statuses"), statuses), hypotheses, ratesBlock());
}

// ---------------------------------------------------------------------------
// parallax (module 1)
// ---------------------------------------------------------------------------

const KINDS = ["hidden_content", "unexpected_execution", "audit_blind_spot",
               "release_mismatch"];

// The bytes view writes each invisible character as <U+XXXX>: those are the
// marks drawn over the code, in the annotation colour.
function markedText(text) {
  const out = document.createDocumentFragment();
  const parts = String(text).split(/(<U\+[0-9A-F]{4,6}>)/);
  for (const part of parts) {
    if (!part) continue;
    if (/^<U\+[0-9A-F]{4,6}>$/.test(part)) out.append(node("mark", "glyph", part));
    else out.append(document.createTextNode(part));
  }
  return out;
}

function viewLine(text, missing, marked) {
  const cell = node("span", "view-line");
  if (text === null || text === undefined) {
    cell.classList.add("view-missing");
    cell.textContent = missing;
  } else if (marked) {
    cell.append(markedText(text));
  } else {
    cell.textContent = text;
  }
  return cell;
}

function viewModeToggle(onChange) {
  const group = node("div", "segmented");
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", t("parallax.views"));
  for (const mode of ["side", "overlay"]) {
    const b = button(t(mode === "side" ? "parallax.sidebyside" : "parallax.overlay"));
    b.setAttribute("aria-pressed", String(state.viewMode === mode));
    b.addEventListener("click", () => {
      state.viewMode = mode;
      store("secaudit.views", mode === "overlay" ? "overlay" : null);
      onChange();
    });
    group.append(b);
  }
  return group;
}

// The two views of the lines that differ: side by side, or overlaid like two
// slices of the same study, with the difference annotated on the code.
function excerptNode(d, mode) {
  const ex = d.evidence && d.evidence.excerpt;
  if (!ex || !Array.isArray(ex.lines) || !ex.lines.length) return null;
  const single = d.kind === "unexpected_execution";
  const missing = t(d.kind === "release_mismatch" ? "parallax.absent" : "parallax.notshown");
  const viewer = node("div", `viewer viewer-${single ? "single" : mode}`);
  const head = node("div", "viewer-head");
  head.append(node("span", "viewer-gutter"));
  if (single) {
    head.append(node("span", null, t("view.bytes")));
  } else if (mode === "side") {
    head.append(node("span", null, t(`view.${d.view_a}`)), node("span", null, t(`view.${d.view_b}`)));
  } else {
    head.append(node("span", null, `${t(`view.${d.view_b}`)} / ${t(`view.${d.view_a}`)}`));
  }
  viewer.append(head);
  for (const line of ex.lines) {
    const r = node("div", `viewer-row${line.marked ? " viewer-marked" : ""}`);
    r.append(node("span", "viewer-gutter", line.n === null || line.n === undefined ? "" : line.n));
    if (single) {
      r.append(viewLine(line.b, missing, true));
    } else if (mode === "side") {
      r.append(viewLine(line.a, missing, false), viewLine(line.b, missing, true));
    } else {
      const stack = node("span", "viewer-stack");
      stack.append(viewLine(line.b, missing, true));
      if (line.marked && line.a !== line.b) {
        const under = viewLine(line.a, missing, false);
        under.classList.add("view-under");
        stack.append(under);
      }
      r.append(stack);
    }
    viewer.append(r);
  }
  const wrap = node("div", "viewer-wrap");
  wrap.append(viewer);
  if (ex.truncated) wrap.append(node("p", "muted small", t("parallax.truncated")));
  return wrap;
}

function fileListNode(files, more) {
  const list = node("ul", "file-list");
  for (const f of files) list.append(node("li", "where", f));
  if (more) list.append(node("li", "muted", t("parallax.more", more)));
  return list;
}

// Everything known of one divergence, for the expanded row and the panel.
function divergenceBody(d, { mode, onMode }) {
  const parts = document.createDocumentFragment();
  const ev = d.evidence || {};
  parts.append(node("p", "prose", d.detail));
  const pairs = [];
  if (ev.trigger) pairs.push([t("parallax.trigger"), ev.trigger]);
  if (ev.command) pairs.push([t("parallax.command"), node("span", "where", ev.command)]);
  if (pairs.length) {
    const dl = facts(pairs);
    dl.classList.add("facts-wide");
    parts.append(dl);
  }
  const decoded = (ev.occurrences || []).map((o) => o.decoded).filter(Boolean);
  if (decoded.length) {
    parts.append(node("h3", null, t("parallax.decoded")));
    for (const text of decoded.slice(0, 5)) parts.append(node("pre", "snippet", text));
  }
  if (ev.excerpt) {
    const viewer = excerptNode(d, mode);
    if (viewer) {
      if (onMode && d.kind !== "unexpected_execution") parts.append(viewModeToggle(onMode));
      parts.append(viewer);
    }
  }
  if (Array.isArray(ev.files) && ev.files.length) {
    parts.append(node("h3", null, t("parallax.files")), fileListNode(ev.files, ev.more));
  }
  return parts;
}

function divergenceRows(d) {
  const body = document.createElement("tbody");
  const open = state.expandedViews.has(d.id);
  const expandId = `divergence-more-${d.id}`;
  const where = d.file || t("parallax.whole");

  const toggle = button("", "toggle");
  toggle.setAttribute("aria-expanded", String(open));
  toggle.setAttribute("aria-controls", expandId);
  toggle.setAttribute("aria-label", t("parallax.expand", where));

  const title = button(where, "link where");
  title.dataset.divergence = String(d.id);
  title.addEventListener("click", () => openDivergence(d.id, title));

  const main = row([
    toggle,
    severityNode(d.severity),
    { className: "finding-title-cell divergence-file", content: title },
    { className: "hide-narrow", content: d.detail },
  ], "finding-row");
  main.setAttribute("aria-selected", String(state.drawerDivergence === d.id));

  const more = document.createElement("tr");
  more.className = "finding-expand";
  more.id = expandId;
  more.hidden = !open;
  const cell = document.createElement("td");
  cell.colSpan = 4;
  const fill = () => cell.replaceChildren(divergenceBody(d, {
    mode: state.viewMode, onMode: () => renderParallax() }));
  if (open) fill();
  more.append(cell);

  toggle.addEventListener("click", () => {
    const now = !state.expandedViews.has(d.id);
    if (now) state.expandedViews.add(d.id);
    else state.expandedViews.delete(d.id);
    toggle.setAttribute("aria-expanded", String(now));
    if (now) fill();
    more.hidden = !now;
  });
  body.append(main, more);
  return body;
}

function canaryBlock(audit, run) {
  const section = block(t("parallax.integrity"));
  const c = audit.canary;
  if (!c) {
    section.append(node("p", "muted", t("parallax.integritynone")));
    const why = run && run.detail && (run.detail.canary_error || run.detail.canary_skipped);
    if (why) section.append(node("p", "note", why));
    return section;
  }
  const score = node("p", "integrity");
  score.append(node("span", "integrity-score", `${c.found} / ${c.planted}`),
               document.createTextNode(` ${t("parallax.integrityline", c.found, c.planted)}`));
  section.append(score);
  const decoys = (c.detail && c.detail.decoys) || [];
  if (decoys.length) {
    section.append(table(
      [{ text: t("parallax.decoy") }, { text: t("parallax.file") }, { text: "" }],
      decoys.map((x) => row([
        TEXT.en[`decoy.${x.kind}`] ? t(`decoy.${x.kind}`) : x.kind,
        { className: "where", content: x.file },
        node("span", `result result-${x.found ? "survived" : "refuted"}`,
             t(x.found ? "parallax.found" : "parallax.missed")),
      ]))));
  }
  if (c.detail && c.detail.source === "runner") {
    section.append(node("p", "muted small", t("parallax.runner")));
  }
  section.append(node("p", "muted", t("parallax.integritynote")));
  return section;
}

function publishedBlock(run) {
  const section = block(t("parallax.published"));
  const published = run && run.detail && run.detail.published;
  if (!published || !published.checked) {
    section.append(node("p", "muted", t(published && published.reason
      ? "parallax.publishedoff" : "parallax.nocheckout")));
    return section;
  }
  const packages = published.packages || [];
  if (!packages.length) {
    section.append(node("p", "muted", t("parallax.nopackage")));
    return section;
  }
  for (const p of packages) {
    const name = `${p.name}${p.version ? ` ${p.version}` : ""} (${p.ecosystem})`;
    if (p.compared) {
      section.append(node("p", null, t("parallax.compared", name, p.tag, p.differences)));
    } else {
      section.append(node("p", null, t("parallax.notcompared", name)));
      if (p.reason) section.append(node("p", "note", p.reason));
    }
  }
  return section;
}

function renderParallax() {
  const target = el("parallax-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = parallaxRun(audit);
  if (!run) {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("parallax.notrun")));
    return;
  }
  const divergences = audit.divergences || [];
  const parts = [canaryBlock(audit, run)];
  if (run.status === "error") parts.push(node("p", "error", t("parallax.failed")));
  const counts = node("div", "counts");
  for (const kind of KINDS) {
    const n = divergences.filter((d) => d.kind === kind).length;
    counts.append(node("span", n ? "badge badge-reachable" : "badge", `${t(`kind.${kind}`)} ${n}`));
  }
  parts.push(counts);
  // Keep open whatever the reader had open across the re-render polling does.
  const open = new Set([...target.querySelectorAll("details[open]")]
    .map((x) => x.dataset.kind));
  for (const kind of KINDS) {
    const these = divergences.filter((d) => d.kind === kind);
    const details = node("details", "block kind-block");
    details.dataset.kind = kind;
    details.open = open.size ? open.has(kind) : these.length > 0;
    const summary = node("summary", null, `${t(`kind.${kind}`)} · ${these.length}`);
    details.append(summary, node("p", "muted", t(`kinddesc.${kind}`)));
    if (!these.length) {
      details.append(node("p", "muted", t("parallax.nokind")));
    } else {
      details.append(table(
        [{ text: "" }, { text: t("findings.severity") }, { text: t("parallax.file") },
         { text: t("parallax.divergence"), className: "hide-narrow" }],
        these.map(divergenceRows)));
    }
    parts.push(details);
  }
  parts.push(publishedBlock(run), node("p", "muted small", t("parallax.notes")));
  const focused = document.activeElement && target.contains(document.activeElement)
    ? document.activeElement.dataset.divergence : null;
  target.replaceChildren(...parts);
  if (focused) {
    const again = target.querySelector(`[data-divergence="${CSS.escape(focused)}"]`);
    if (again) again.focus();
  }
}

function openDivergence(id, opener) {
  state.drawerFinding = null;
  state.drawerFile = null;
  state.drawerDivergence = id;
  for (const r of document.querySelectorAll(".finding-row")) {
    r.setAttribute("aria-selected", "false");
  }
  if (opener) opener.closest("tr").setAttribute("aria-selected", "true");
  renderDrawerFinding(opener);
}

function renderDrawerDivergence(opener) {
  const d = state.current && (state.current.divergences || [])
    .find((x) => x.id === state.drawerDivergence);
  if (!d) {
    closeDrawer();
    return;
  }
  const content = document.createDocumentFragment();
  const pairs = [[t("findings.severity"), severityNode(d.severity)],
                 [t("parallax.views"), `${t(`view.${d.view_a}`)} ≠ ${t(`view.${d.view_b}`)}`]];
  content.append(facts(pairs));
  // The panel is narrow: the views are overlaid there.
  content.append(divergenceBody(d, { mode: "overlay" }));
  openDrawer(`${t(`kind.${d.kind}`)}: ${d.file || t("parallax.whole")}`, content, opener);
}

// ---------------------------------------------------------------------------
// detail panel
// ---------------------------------------------------------------------------

function narrow() {
  return window.matchMedia("(max-width: 899px)").matches;
}

function openDrawer(title, content, opener) {
  if (opener) state.drawerOpener = opener;
  el("drawer-title").textContent = title;
  el("drawer-body").replaceChildren(content);
  const wasOpen = !el("drawer").hidden;
  el("drawer").hidden = false;
  el("app").classList.add("drawer-open");
  if (!wasOpen) el("drawer-close").focus();
}

function closeDrawer() {
  if (el("drawer").hidden) return;
  const shown = state.drawerFinding;
  const shownDivergence = state.drawerDivergence;
  const shownFile = state.drawerFile;
  el("drawer").hidden = true;
  el("app").classList.remove("drawer-open");
  state.drawerFinding = null;
  state.drawerDivergence = null;
  state.drawerFile = null;
  for (const r of document.querySelectorAll(".finding-row")) {
    r.setAttribute("aria-selected", "false");
  }
  // Back to what opened it — or to its stand-in, if polling redrew the table.
  let opener = state.drawerOpener;
  state.drawerOpener = null;
  if ((!opener || !opener.isConnected) && shown !== null) {
    opener = visibleFinding(shown);
  }
  if ((!opener || !opener.isConnected) && shownDivergence !== null) {
    opener = document.querySelector(
      `[data-divergence="${CSS.escape(String(shownDivergence))}"]`);
  }
  if ((!opener || !opener.isConnected) && shownFile !== null) {
    opener = document.querySelector(`[data-leverage="${CSS.escape(shownFile)}"]`);
  }
  if (opener && opener.isConnected) opener.focus();
  else el("content").focus();
}

// The same finding can have a link in several sections; only one is shown.
function visibleFinding(id) {
  return document.querySelector(
    `[data-view="${state.section}"] [data-finding="${CSS.escape(String(id))}"]`);
}

function openFinding(id, opener) {
  state.drawerDivergence = null;
  state.drawerFile = null;
  state.drawerFinding = id;
  for (const r of document.querySelectorAll(".finding-row")) {
    r.setAttribute("aria-selected", "false");
  }
  if (opener) opener.closest("tr").setAttribute("aria-selected", "true");
  renderDrawerFinding(opener);
}

// Kept in step with polling: the finding shown is re-read from the latest data.
function renderDrawerFinding(opener) {
  if (state.drawerFile !== null) {
    renderDrawerFile(opener);
    return;
  }
  if (state.drawerDivergence !== null) {
    renderDrawerDivergence(opener);
    return;
  }
  if (state.drawerFinding === null) return;
  const finding = state.current && (state.current.findings || [])
    .find((f) => f.id === state.drawerFinding);
  if (!finding) {
    closeDrawer();
    return;
  }
  openDrawer(finding.title, findingBody(finding, { full: true }), opener);
}

el("drawer-close").addEventListener("click", closeDrawer);

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (!el("drawer").hidden) {
      event.preventDefault();
      closeDrawer();
    } else if (narrow() && !el("app").classList.contains("nav-collapsed")) {
      setNav(false);
      el("nav-toggle").focus();
    }
    return;
  }
  // "/" jumps to the search, unless something is being typed already.
  const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
  if (event.key === "/" && !typing && !el("app").hidden) {
    event.preventDefault();
    el("search").focus();
  }
});

// ---------------------------------------------------------------------------
// immune memory (module 3)
// ---------------------------------------------------------------------------

// A commit of the audited repository, linked to GitHub when it is there.
function commitNode(sha) {
  if (!sha) return node("span", "muted", "—");
  const url = state.current && state.current.repo_url;
  if (!/^https:\/\/github\.com\/[^/]+\/[^/]+$/.test(String(url || "").replace(/\.git$/, ""))) {
    return node("span", "where", shortSha(sha));
  }
  const a = node("a", "where", shortSha(sha));
  a.href = `${String(url).replace(/\.git$/, "")}/commit/${encodeURIComponent(sha)}`;
  a.rel = "noopener noreferrer";
  a.target = "_blank";
  a.title = sha;
  return a;
}

function zombiesBlock(findings) {
  const zombies = findings.filter((f) => f.zombie_of);
  const section = block(t("memory.zombies"), node("p", "muted", t("memory.zombiesintro")));
  if (!zombies.length) {
    section.append(node("p", "muted", t("memory.nozombies")));
    return section;
  }
  section.append(table(
    [{ text: t("findings.severity") }, { text: t("findings.finding") },
     { text: t("findings.location"), className: "hide-narrow" },
     { text: t("memory.fixedin") },
     { text: t("provenance.origin"), className: "hide-narrow" }],
    zombies.map((f) => {
      const title = button(f.title, "link");
      title.dataset.finding = String(f.id);
      title.addEventListener("click", () => openFinding(f.id, title));
      const r = row([
        severityNode(f.severity), title,
        { className: "where hide-narrow", content: whereText(f) },
        commitNode(f.zombie_of.fix_commit),
        { className: "hide-narrow",
          content: commitNode(f.provenance && f.provenance.origin_commit) },
      ], "finding-row");
      r.setAttribute("aria-selected", String(state.drawerFinding === f.id));
      return r;
    })));
  return section;
}

function rulesBlock(audit) {
  const rules = audit.immune_rules || [];
  const section = block(t("memory.rules"), node("p", "muted", t("memory.rulesintro")));
  if (!rules.length) {
    section.append(node("p", "muted", t("memory.norules")));
    return section;
  }
  section.append(table(
    [{ text: t("memory.rule") }, { text: t("parallax.file"), className: "hide-narrow" },
     { text: t("memory.validation") }, { text: t("memory.fixedin"), className: "hide-narrow" },
     { text: t("memory.matches"), className: "num" }],
    rules.map((r) => {
      const name = node("details", "rule-yaml");
      name.append(node("summary", "where", r.rule_id));
      if (r.explanation) name.append(node("p", "muted", r.explanation));
      if (r.yaml) name.append(node("pre", "snippet", r.yaml));
      const verdict = node("span", null);
      verdict.append(node("span", r.validated ? "badge badge-corroborated" : "badge badge-inconclusive",
                          t(r.validated ? "memory.validated" : "memory.notvalidated")));
      if (Number.isInteger(r.before)) {
        verdict.append(" ", node("span", "muted small",
                                 t("memory.counts", r.before, r.after ?? "—")));
      }
      if (!r.validated && r.reason) verdict.append(node("div", "muted small", r.reason));
      return row([
        name,
        { className: "where hide-narrow", content: r.file || "—" },
        verdict,
        { className: "hide-narrow", content: commitNode(r.fix_commit) },
        { className: "num", content: r.matches || 0 },
      ]);
    })));
  if (rules.some((r) => r.validated) && audit.project_id) {
    const a = node("a", null, t("memory.export"));
    a.href = `/api/projects/${encodeURIComponent(audit.project_id)}/immune-rules.yaml`;
    a.setAttribute("download", "");
    const p = node("p", null);
    p.append(a);
    section.append(p);
  } else {
    section.append(node("p", "muted small", t("memory.noexport")));
  }
  return section;
}

function provenanceBlock(run) {
  const d = run.detail || {};
  const counts = node("div", "counts");
  counts.append(node("span", "badge", `${t("memory.located")} ${d.provenance || 0}`),
                node("span", d.ai_declared ? "badge badge-reachable" : "badge",
                     `${t("memory.aideclared")} ${d.ai_declared || 0}`),
                node("span", "badge", `${t("memory.fixedcount")} ${d.fixed || 0}`));
  const section = block(t("memory.provenance"),
                        node("p", "muted", t("memory.provenanceintro")), counts);
  for (const note of d.notes || []) section.append(node("p", "muted small", note));
  return section;
}

function renderMemory() {
  const target = el("memory-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = (audit.modules || []).filter((r) => r.module === "immune").pop();
  if (!run) {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("memory.notrun")));
    return;
  }
  const parts = [];
  if (run.status === "error") parts.push(node("p", "error", t("memory.failed")));
  const d = run.detail || {};
  if (d.semgrep === false) parts.push(node("p", "note", t("memory.nosemgrep")));
  if (d.proposal_error) parts.push(node("p", "note", t("memory.proposalerror", d.proposal_error)));
  parts.push(zombiesBlock(audit.findings || []), rulesBlock(audit), provenanceBlock(run));
  // Keep open the rules the reader had open across the polling re-render.
  const open = new Set([...target.querySelectorAll("details[open] > summary")]
    .map((s) => s.textContent));
  target.replaceChildren(...parts);
  for (const s of target.querySelectorAll("details > summary")) {
    if (open.has(s.textContent)) s.parentElement.open = true;
  }
}

// ---------------------------------------------------------------------------
// leverage map (module 4)
// ---------------------------------------------------------------------------

const FRAGILE_LEVERAGE = 0.7;
const FRAGILE_OVERSIGHT = 0.3;
const SHOWN_FILES = 30;

function reasonText(r) {
  const value = t(`reason.${r.code}`, r.args || {});
  return value === `reason.${r.code}` ? r.code : value;
}

// The reasons that explain the score, the ones that hurt first.
function headline(entry) {
  const lev = entry.reasons.filter((r) => r.side === "leverage")
    .sort((a, b) => (b.delta || 0) - (a.delta || 0));
  const lacks = entry.reasons.filter((r) => r.side === "oversight" && !(r.delta > 0)
                                      && r.code !== "protection_unknown");
  return [lev[0], ...lacks].filter(Boolean).map(reasonText).join("; ");
}

function score(value) {
  return Number(value).toFixed(2);
}

function openLeverage(file, opener) {
  state.drawerFinding = null;
  state.drawerDivergence = null;
  state.drawerFile = file;
  for (const r of document.querySelectorAll(".finding-row")) {
    r.setAttribute("aria-selected", "false");
  }
  const tr = opener && opener.closest("tr");
  if (tr) tr.setAttribute("aria-selected", "true");
  renderDrawerFinding(opener);
}

function reasonList(reasons) {
  const ul = node("ul", "reasons");
  for (const r of reasons) {
    const li = node("li", r.delta < 0 ? "reason-minus" : r.delta > 0 ? "reason-plus" : "reason-none");
    li.append(node("span", "reason-delta", r.delta ? `${r.delta > 0 ? "+" : "−"}${score(Math.abs(r.delta))}` : "·"),
              " ", reasonText(r));
    ul.append(li);
  }
  return ul;
}

function renderDrawerFile(opener) {
  const entry = state.current && (state.current.leverage || [])
    .find((x) => x.file === state.drawerFile);
  if (!entry) {
    closeDrawer();
    return;
  }
  const content = document.createDocumentFragment();
  content.append(facts([
    [t("leverage.leverage"), score(entry.leverage)],
    [t("leverage.oversight"), score(entry.oversight)],
    [t("leverage.priority"), score(entry.priority)],
    [t("leverage.lastcommit"), commitNode(entry.last_commit)],
  ]));
  content.append(node("h3", null, t("leverage.leverageside")),
                 reasonList(entry.reasons.filter((r) => r.side === "leverage")),
                 node("h3", null, t("leverage.oversightside")),
                 reasonList(entry.reasons.filter((r) => r.side === "oversight")));
  openDrawer(entry.file, content, opener);
}

const SVG_NS = "http://www.w3.org/2000/svg";

function svg(tag, attrs, text) {
  const n = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
  if (text !== undefined) n.textContent = text;
  return n;
}

// Leverage on x, oversight on y, one dot per file. The table below is the
// same data as text, so nothing here is reachable only by pointer.
function leverageChart(files) {
  const W = 640, H = 360, M = { top: 16, right: 24, bottom: 44, left: 52 };
  // A little room past 0 and 1, so the dots on the edges are whole.
  const PAD = 0.04;
  const x = (v) => M.left + ((v + PAD) / (1 + 2 * PAD)) * (W - M.left - M.right);
  const y = (v) => H - M.bottom - ((v + PAD) / (1 + 2 * PAD)) * (H - M.top - M.bottom);
  const wrap = node("div", "chart");
  const chart = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img",
                             "aria-label": t("leverage.map") });
  chart.append(svg("rect", { class: "chart-zone", x: x(FRAGILE_LEVERAGE), y: y(FRAGILE_OVERSIGHT),
                             width: x(1 + PAD) - x(FRAGILE_LEVERAGE),
                             height: y(-PAD) - y(FRAGILE_OVERSIGHT) }));
  chart.append(svg("text", { class: "chart-zone-label", x: x(1 + PAD) - 4,
                             y: y(FRAGILE_OVERSIGHT) + 13, "text-anchor": "end" },
                   t("leverage.zone")));
  for (const v of [0, 0.25, 0.5, 0.75, 1]) {
    chart.append(svg("line", { class: "chart-grid", x1: x(0), x2: x(1), y1: y(v), y2: y(v) }),
                 svg("text", { class: "chart-tick", x: M.left - 8, y: y(v) + 4,
                               "text-anchor": "end" }, v.toFixed(2)),
                 svg("text", { class: "chart-tick", x: x(v), y: H - M.bottom + 18,
                               "text-anchor": "middle" }, v.toFixed(2)));
  }
  chart.append(svg("text", { class: "chart-axis", x: x(0.5), y: H - 6, "text-anchor": "middle" },
                   `${t("leverage.axisx")} →`),
               svg("text", { class: "chart-axis", x: 14, y: y(0.5), "text-anchor": "middle",
                             transform: `rotate(-90 14 ${y(0.5)})` }, `${t("leverage.axisy")} →`));
  const tip = node("div", "chart-tip");
  tip.hidden = true;
  // Files that land on the same spot are drawn once, and listed together.
  const spots = new Map();
  for (const f of files) {
    const key = `${f.leverage.toFixed(2)}|${f.oversight.toFixed(2)}`;
    if (!spots.has(key)) spots.set(key, []);
    spots.get(key).push(f);
  }
  const labelled = new Set(files.slice(0, 3).map((f) => f.file));
  const placed = [];          // label boxes already drawn, to keep them apart
  for (const group of spots.values()) {
    const f = group[0];
    const g = svg("g", { class: "chart-dot" });
    g.append(svg("circle", { class: "chart-hit", cx: x(f.leverage), cy: y(f.oversight), r: 12 }),
             svg("circle", { class: "chart-mark", cx: x(f.leverage), cy: y(f.oversight),
                             r: Math.min(9, 4 + group.length) }));
    const show = () => {
      tip.replaceChildren(
        ...group.slice(0, 6).map((e) => node("div", "where", e.file)),
        ...(group.length > 6 ? [node("div", "muted", `+${group.length - 6}`)] : []),
        node("div", "muted", `${t("leverage.leverage")} ${score(f.leverage)} · ` +
                             `${t("leverage.oversight")} ${score(f.oversight)}`));
      tip.style.left = `${(x(f.leverage) / W) * 100}%`;
      tip.style.top = `${(y(f.oversight) / H) * 100}%`;
      tip.hidden = false;
    };
    g.addEventListener("mouseenter", show);
    g.addEventListener("mouseleave", () => { tip.hidden = true; });
    g.addEventListener("click", () => {
      const row = document.querySelector(`[data-leverage="${CSS.escape(f.file)}"]`);
      openLeverage(f.file, row);
    });
    chart.append(g);
    const named = group.find((e) => labelled.has(e.file));
    if (named) {
      const text = named.file.split("/").pop() + (group.length > 1 ? ` +${group.length - 1}` : "");
      const width = text.length * 6.2;
      const right = f.leverage < 0.6;
      const left = right ? x(f.leverage) + 12 : x(f.leverage) - 12 - width;
      let top = y(f.oversight) - 22;
      while (placed.some((b) => left < b.left + b.width && b.left < left + width
                                && top < b.top + 14 && b.top < top + 14)) {
        top -= 15;
      }
      placed.push({ left, top, width });
      chart.append(svg("text", { class: "chart-label", x: left, y: top + 11 }, text));
    }
  }
  wrap.append(chart, tip);
  return wrap;
}

function leverageTable(files, run) {
  const shown = state.leverageAll ? files : files.slice(0, SHOWN_FILES);
  const section = block(t("leverage.files"), node("p", "muted", t("leverage.filesintro")));
  section.append(table(
    [{ text: t("leverage.file") }, { text: t("leverage.leverage"), className: "num" },
     { text: t("leverage.oversight"), className: "num" },
     { text: t("leverage.priority"), className: "num" },
     { text: t("leverage.why"), className: "hide-narrow" }],
    shown.map((f) => {
      // Long paths break at their slashes, not in the middle of a name.
      const name = button("", "link where");
      f.file.split("/").forEach((part, i, parts) => {
        name.append(part + (i < parts.length - 1 ? "/" : ""));
        if (i < parts.length - 1) name.append(document.createElement("wbr"));
      });
      name.dataset.leverage = f.file;
      name.addEventListener("click", () => openLeverage(f.file, name));
      const r = row([
        name,
        { className: "num", content: score(f.leverage) },
        { className: "num", content: score(f.oversight) },
        { className: "num", content: score(f.priority) },
        { className: "hide-narrow small", content: headline(f) },
      ], `finding-row${f.leverage >= FRAGILE_LEVERAGE && f.oversight < FRAGILE_OVERSIGHT
                       ? " fragile" : ""}`);
      r.setAttribute("aria-selected", String(state.drawerFile === f.file));
      return r;
    })));
  if (files.length > shown.length) {
    section.append(button(t("leverage.showall", files.length), "link", () => {
      state.leverageAll = true;
      renderLeverage();
    }));
  }
  const left = (run.detail || {}).left_out;
  if (left) section.append(node("p", "muted small", t("leverage.leftout", left)));
  return section;
}

function agentBlock(audit, run) {
  const caps = audit.agent_capabilities || [];
  const byId = new Map(caps.map((c) => [c.id, c]));
  const section = block(t("agent.title"), node("p", "muted", t("agent.intro")));
  if (!caps.length) {
    section.append(node("p", "muted", t("agent.none")));
    return section;
  }
  const combos = (run.detail || {}).combinations || [];
  if (!combos.length) section.append(node("p", "muted", t("agent.nocombo")));
  for (const combo of combos) {
    const path = node("div", "agent-path");
    const head = node("p", "agent-path-title");
    head.append(severityNode(combo.severity), " ", t(`combo.${combo.kind}`));
    if (combo.unattended) head.append(" · ", node("strong", null, t("agent.unattended")));
    const steps = node("ol", "agent-steps");
    for (const id of combo.steps) {
      const c = byId.get(id);
      if (!c) continue;
      const li = node("li");
      li.append(node("span", "badge", t(`cap.${c.capability}`)), " ",
                node("span", "where", c.source_file), node("div", "small", c.detail));
      steps.append(li);
    }
    path.append(head, steps);
    section.append(path);
  }
  section.append(table(
    [{ text: t("agent.capability") }, { text: t("agent.source") },
     { text: t("agent.detail"), className: "hide-narrow" }],
    caps.map((c) => row([
      node("span", "badge", t(`cap.${c.capability}`)),
      { className: "where", content: c.source_file },
      { className: "hide-narrow small", content: c.detail },
    ]))));
  return section;
}

function leverageNotes(run) {
  const d = run.detail || {};
  const notes = node("div", "notes");
  const gh = d.github || {};
  if (gh.error) notes.append(node("p", "note", t("leverage.githuberror", gh.error)));
  else if (!gh.token) notes.append(node("p", "muted small", t("leverage.nogithub")));
  else notes.append(node("p", "muted small", t("leverage.githubok", gh.calls || 0)));
  notes.append(node("p", "muted small", d.codeowners
    ? t("leverage.codeowners", d.codeowners) : t("leverage.nocodeowners")));
  if (d.history && d.history.shallow) {
    notes.append(node("p", "muted small", t("leverage.shallow", d.history.commits)));
  }
  return notes;
}

function renderLeverage() {
  const target = el("leverage-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = (audit.modules || []).filter((r) => r.module === "leverage").pop();
  if (!run) {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("leverage.notrun")));
    return;
  }
  const files = audit.leverage || [];
  const parts = [];
  if (run.status === "error") parts.push(node("p", "error", t("leverage.failed")));
  if (files.length) {
    parts.push(block(t("leverage.map"), node("p", "muted", t("leverage.mapintro")),
                     leverageChart(files)),
               leverageTable(files, run));
  }
  parts.push(agentBlock(audit, run), leverageNotes(run));
  const focused = document.activeElement && target.contains(document.activeElement)
    ? document.activeElement.dataset.leverage : null;
  target.replaceChildren(...parts);
  if (focused) {
    const again = target.querySelector(`[data-leverage="${CSS.escape(focused)}"]`);
    if (again) again.focus();
  }
}

// ---------------------------------------------------------------------------
// sidebar
// ---------------------------------------------------------------------------

const NAV_KEY = "secaudit.nav";

function setNav(open) {
  el("app").classList.toggle("nav-collapsed", !open);
  el("nav-toggle").setAttribute("aria-expanded", String(open));
}

el("nav-toggle").addEventListener("click", () => {
  const open = el("app").classList.contains("nav-collapsed");
  setNav(open);
  // Only the desktop choice is remembered; on a phone it always starts shut.
  if (!narrow()) store(NAV_KEY, open ? null : "collapsed");
  if (open && narrow()) el("sidebar").querySelector("a").focus();
});

el("scrim").addEventListener("click", () => setNav(false));

// ---------------------------------------------------------------------------
// history
// ---------------------------------------------------------------------------

function renderHistory() {
  const target = el("history-body");
  el("audits-empty").hidden = !state.loaded || state.audits.length > 0;
  el("audit-count").textContent = state.audits.length ? `(${state.audits.length})` : "";
  if (state.audits.length === 0) {
    target.replaceChildren();
    return;
  }
  target.replaceChildren(table(
    [{ text: t("history.repo") }, { text: t("history.commit") },
     { text: t("history.status") }, { text: t("history.findings") },
     { text: t("history.coverage"), className: "hide-narrow" },
     { text: t("history.when"), className: "hide-narrow" }],
    state.audits.map((audit) => {
      const here = audit.id === state.selectedId;
      const open = button(repoLabel(audit.repo_url), "link", () => go("summary", audit.id));
      if (here) open.setAttribute("aria-current", "true");
      const coverage = audit.coverage;
      return row([
        { className: "where", content: open },
        { className: "where", content: [shortSha(audit.commit_sha), audit.branch]
          .filter(Boolean).join(" · ") || "—" },
        statusNode(audit.status),
        audit.status === "done" ? countsNode(audit.summary) : "",
        { className: "hide-narrow", content: coverage && coverage.files
          ? `${coverage.audited} / ${coverage.files}` : "—" },
        { className: "hide-narrow", content: relativeTime(audit.created_at) },
      ], here ? "current" : null);
    })));
}

el("audit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = el("repo-url");
  const submit = event.target.querySelector("button");
  const error = el("form-error");

  error.hidden = true;
  submit.disabled = true;
  try {
    const audit = await api("/api/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // The findings come back written in the language of the interface: the
      // backend is asked for it, so nothing is translated afterwards.
      body: JSON.stringify({ repo_url: input.value.trim(), language: lang }),
    });
    input.value = "";
    await refresh();
    go("summary", audit.id);
  } catch (e) {
    error.textContent = e.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// loading and polling
// ---------------------------------------------------------------------------

async function loadDetail(id) {
  const query = el("filter-evidence").value === "verified" ? "?verified_only=true" : "";
  try {
    const audit = await api(`/api/audits/${encodeURIComponent(id)}${query}`);
    if (id !== state.selectedId) return;      // another audit was chosen meanwhile
    state.current = audit;
  } catch (_) {
    // a failed detail fetch leaves the previous render in place
    return;
  }
  renderSection();
}

function selectAudit(id, { route = true } = {}) {
  if (id !== state.selectedId) {
    state.selectedId = id;
    state.current = null;
    state.expanded.clear();
    closeDrawer();
  }
  // Routing renders it; the id is already selected, so it does not load it.
  if (route) go(AUDIT_SECTIONS.has(state.section) ? state.section : "summary", id);
  else renderSection();
  loadDetail(id);
}

async function refresh() {
  clearTimeout(pollTimer);
  let audits = [];
  try {
    audits = await api("/api/audits");
  } catch (_) {
    pollTimer = setTimeout(refresh, POLL_MS * 2);
    return;
  }
  state.audits = audits;
  state.loaded = true;

  // The audit in the address if it is still there, or else the latest one.
  if (!audits.some((a) => a.id === state.selectedId)) {
    state.selectedId = audits.length ? audits[0].id : null;
    state.current = null;
    if (AUDIT_SECTIONS.has(state.section)) {
      history.replaceState(null, "", hashFor(state.section, state.selectedId));
    }
  }
  renderSection();
  if (state.selectedId) await loadDetail(state.selectedId);

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
  const line = el("settings-state");
  line.replaceChildren(
    node("span", `status status-${status.ready ? "done" : "error"}`,
         status.ready ? t("settings.ready") : t("settings.notready")),
    node("span", null, `  ${status.name || t("settings.nobackend")}`),
  );
  if (status.model) line.append(node("span", null, `  ·  ${status.model}`));
  if (status.detail) line.append(node("div", "muted", status.detail));
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
// theme: theme.js has already set it; this keeps the button and the setting
// ---------------------------------------------------------------------------

const THEME_KEY = "secaudit.theme";
const systemDark = window.matchMedia("(prefers-color-scheme: dark)");

function currentTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function setTheme(choice) {
  // "system" forgets the choice, so the system decides again.
  store(THEME_KEY, choice === "system" ? null : choice);
  document.documentElement.dataset.theme = choice === "system"
    ? (systemDark.matches ? "dark" : "light") : choice;
  renderThemeToggle();
}

function renderThemeToggle() {
  const label = currentTheme() === "dark" ? t("theme.tolight") : t("theme.todark");
  el("theme-toggle-label").textContent = label;
  el("theme-toggle").title = label;
  const saved = stored(THEME_KEY);
  el("theme-choice").value = saved === "dark" || saved === "light" ? saved : "system";
}

el("theme-toggle").addEventListener("click", () => {
  setTheme(currentTheme() === "dark" ? "light" : "dark");
});

el("theme-choice").addEventListener("change", () => setTheme(el("theme-choice").value));

systemDark.addEventListener("change", () => {
  if (!stored(THEME_KEY)) setTheme("system");
});

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------

function showSignedOut(signInEnabled) {
  el("app").hidden = true;
  el("signin").hidden = false;
  el("signin-link").hidden = !signInEnabled;
  el("signin-disabled").hidden = signInEnabled;
  for (const id of ["whoami", "logout", "nav-toggle", "search", "context"]) {
    el(id).hidden = true;
  }
}

function showSignedIn(user, singleUser) {
  el("signin").hidden = true;
  el("app").hidden = false;
  el("nav-toggle").hidden = false;
  el("search").hidden = false;
  el("whoami").textContent = user.login + (user.is_admin ? " · admin" : "");
  el("whoami").hidden = false;
  // A personal instance has no session to end.
  el("logout").hidden = singleUser;
  setNav(!narrow() && stored(NAV_KEY) !== "collapsed");
}

el("logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST" });
  location.reload();
});

// ---------------------------------------------------------------------------
// language
// ---------------------------------------------------------------------------

function setLanguage(value) {
  lang = LANGUAGES.includes(value) ? value : "en";
  store(LANG_KEY, lang);
  el("lang").value = lang;
  el("lang-signin").value = lang;
  applyStaticText();
  // Only the interface changes: findings keep the language they were audited
  // in, which is why each audit records its own.
  loadHealth();
  if (el("app").hidden) return;
  if (state.section === "settings") loadSettings();
  renderSection();
}

el("lang").addEventListener("change", () => setLanguage(el("lang").value));
el("lang-signin").addEventListener("change", () => setLanguage(el("lang-signin").value));

async function start() {
  el("lang").value = lang;
  el("lang-signin").value = lang;
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
  state.section = null;          // so the first route counts as a change
  applyRoute();
  refresh();
}

start();
