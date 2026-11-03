"use strict";

// Everything rendered here comes from audited third-party repositories, so the
// DOM is built with textContent only — never innerHTML.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ACTIVE_STATUSES = new Set(["pending", "running"]);
const POLL_MS = 3000;

const SECTIONS = ["summary", "findings", "views", "parallax", "falsifiability", "memory",
                  "leverage", "attacker", "mcp", "supply", "surface", "changes", "twin",
                  "history", "settings"];
// The sections that need an audit to show anything; the rest stand alone.
const AUDIT_SECTIONS = new Set(SECTIONS.slice(0, 13));
// Each module section, the module_runs name it reads, and the phase it lands in.
const MODULES = {
  parallax: { run: "parallax", phase: 5 },
  falsifiability: { run: "falsifiability", phase: 4 },
  memory: { run: "immune", phase: 6 },
  leverage: { run: "leverage", phase: 7 },
  attacker: { run: "attacker", phase: 8 },
  mcp: { run: "mcp", phase: "P3" },
  supply: { run: "dependencies", phase: "P3" },
  surface: { run: "surface", phase: "P3" },
  changes: { run: "drift", phase: "P3" },
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
    "jewels.phase": "What an attacker would want most from the selected audit's " +
      "project. secaudit suggests the ones the repository points at; declared " +
      "ones replace them, and a removed suggestion is not made again. They count " +
      "from the next audit.",
    "jewels.none": "Select an audit to see its project's crown jewels.",
    "jewels.empty": "No crown jewel yet: the next audit suggests them.",
    "jewels.kind": "kind",
    "jewels.target": "what exactly",
    "jewels.add": "add",
    "jewels.remove": "remove",
    "jewels.by.user": "declared",
    "jewels.by.suggested": "suggested",
    "jewels.removelabel": (k) => `remove ${k}`,
    "jewel.secrets": "secrets",
    "jewel.user_data": "user data",
    "jewel.deployment": "deployment",
    "jewel.administration": "administration",
    "jewel.code_execution": "code execution",
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
      "the single fix that closes most of them.",
    "summary.nopaths": "No attacker profile reaches a crown jewel through what was shown to hold.",
    "summary.pathcount": (n, c) => `${n} path(s) to a crown jewel, ${c} of them critical.`,
    "summary.topfix": "The fix that cuts most:",
    "summary.seeattacker": "see the paths",
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
    "attacker.notrun": "The attacker's view did not run for this audit: it predates the module.",
    "attacker.failed": "The attacker's view failed for this audit; the findings stand without it.",
    "attacker.profile": "attacker profile",
    "attacker.jewel": "crown jewel",
    "attacker.cut": "the fix that cuts most",
    "attacker.cutintro": "Removing it leaves these profile and jewel pairs with no " +
      "path at all — not a longer one. Inconclusive steps never count.",
    "attacker.cutsome": (n) => `cuts ${n} path(s)`,
    "attacker.then": "then",
    "attacker.nocut": "No single fix cuts a path: every pair has another way in.",
    "attacker.matrix": "every profile against every jewel",
    "attacker.matrixintro": "The cost of the cheapest path; empty where there is none.",
    "attacker.nopath": "no path",
    "attacker.path": "the path",
    "attacker.nopathhere": "This profile has no path to this jewel through what was shown to hold.",
    "attacker.cost": (c) => `cost ${c}`,
    "attacker.tentative": "tentative: a step rests on an inconclusive finding",
    "attacker.sees": "what they would see",
    "attacker.works": "why it works",
    "attacker.needs": "what it needs",
    "attacker.gains": "what they gain",
    "attacker.implied": "follows from holding the previous capability",
    "attacker.costdetail": (d) => `${d.steps} step(s) · privileges: ${d.privileges}` +
      `${d.interaction ? " · needs a victim's action" : ""}${d.trace ? " · leaves a trace" : ""}`,
    "attacker.nofindings": "No finding shown to hold, no weakly watched file and no " +
      "agent path: there is nothing to chain.",
    "attacker.limits": "Paths are described, never armed: no exploit and no payload. " +
      "They use only findings shown to hold (reachable or corroborated); inconclusive " +
      "ones are dashed. Costs count steps, privileges, a victim's action and traces.",
    "fix.finding": (x) => `fix the finding \u201c${x.title || "?"}\u201d (${x.file || "—"})`,
    "fix.divergence": (x) => `remove the ${t(`kind.${x.kind}`)} in ${x.file || "—"}`,
    "fix.leverage": (x) => `put ${x.file || "?"} under review (an owner, required approvals)`,
    "fix.agent": (x) => `narrow the agent configuration in ${(x.files || []).join(", ")}`,
    "persona.anonymous": "anonymous",
    "persona.authenticated_user": "authenticated user",
    "persona.malicious_contributor": "malicious contributor",
    "persona.compromised_dependency": "compromised dependency",
    "persona.manipulated_agent": "manipulated agent",
    "personadesc.anonymous": "from the internet, without an account",
    "personadesc.authenticated_user": "with a low-privilege account",
    "personadesc.malicious_contributor": "can open pull requests",
    "personadesc.compromised_dependency": "a package's code runs inside the application",
    "personadesc.manipulated_agent": "an AI agent in the repository, with injected instructions",
    "node.sends_requests": "sends requests to the application",
    "node.user_account": "holds a user account",
    "node.gets_session": "holds another user's session",
    "node.accesses_admin": "administers the application",
    "node.executes_code": "runs code where the application runs",
    "node.reads_user_data": "reads user data",
    "node.writes_db": "writes to the database",
    "node.reads_files": "reads the server's files",
    "node.reads_secret": "reads a secret",
    "node.reaches_internal": "reaches the internal network",
    "node.reads_repository": "reads the repository",
    "node.changes_code": "gets a change into the default branch",
    "node.runs_in_ci": "runs code in CI",
    "node.executes_on_developer": "runs code on a developer's machine",
    "node.controls_agent": "steers an AI agent in the repository",
    "node.publishes_release": "publishes a release or deploys",
    "works.sql_injection": "the query is built from input instead of bound parameters",
    "works.command_injection": "input reaches a shell command",
    "works.code_injection": "input is evaluated as code",
    "works.deserialization": "untrusted data is deserialized into objects",
    "works.path_traversal": "a path from input is not confined to its directory",
    "works.ssrf": "the server fetches a URL the caller chooses",
    "works.idor": "the record is fetched by its id with no check of whose it is",
    "works.privilege": "the role is not checked before the action",
    "works.missing_auth": "the endpoint does not require authentication",
    "works.session": "sessions are not bound, rotated or protected",
    "works.xss": "input is rendered as markup without escaping",
    "works.csrf": "state-changing requests carry no anti-forgery token",
    "works.brute_force": "attempts are not limited",
    "works.hardcoded_secret": "a credential is kept in the source",
    "works.info_disclosure": "errors reveal internals",
    "works.cors": "other origins may make credentialed requests",
    "works.pr_target": "the workflow runs on pull_request_target, with the base repository's secrets, for anyone's pull request",
    "works.ci_secrets": "the workflow is handed repository secrets",
    "works.ci_deploy": "the workflow deploys or publishes what it runs",
    "works.merge": "changes to it land with little review",
    "works.hidden_instructions": "the file says one thing to a person and another to the agent that reads it",
    "works.runs_on_open": "code runs on install, checkout or opening the folder, without anyone asking",
    "works.in_repository": "what is merged is what developers clone",
    "filter.context": "contextual severity",
    "filter.onnopath": "on no path",
    "filter.persona": "attacker profile",
    "findings.context": "contextual severity",
    "findings.personas": "who can use it",
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
    "nav.mcp": "MCP",
    "nav.supply": "Supply chain",
    "nav.surface": "Attack surface",
    "nav.changes": "Changes",
    "mcp.question": "Which MCP servers, tools and configurations does this repository carry, and what do they expose?",
    "mcp.what": "Static checks against the OWASP MCP Top 10. Nothing is installed, started or connected to: what only a running server can show is marked as needing a dynamic test.",
    "supply.question": "What does it depend on, where does it come from, and which credentials has it leaked?",
    "supply.what": "Manifests and lockfiles read as text (no package manager is run), a CycloneDX SBOM, dependency confusion signals, apparently unused dependencies, and every credential in the code and in the fetched history.",
    "surface.question": "Where does outside input enter, and what can it reach?",
    "surface.what": "Endpoints, webhooks, uploads, CLIs, jobs and MCP tools, read from the code, with the trust boundaries they cross. A missing auth marker is a place to look, not a finding.",
    "changes.question": "What changed since the last audit, and did any control get weaker?",
    "changes.what": "Findings new, fixed, persisting and reintroduced by fingerprint; critical files and workflows changed; and security drift read from the diff between the two audited commits.",
    "filter.assessment": "assessment",
    "assessment.confirmed": "confirmed",
    "assessment.potential": "potential",
    "assessment.discarded": "discarded",
    "assessment.unverifiable": "not verifiable",
    "source.model": "model (checked)",
    "source.rule": "deterministic rule",
    "source.immune": "immune rule",
    "band.high": "high",
    "band.medium": "medium",
    "band.low": "low",
    "cond.verified": "verified",
    "cond.discarded": "discarded",
    "cond.unknown": "unknown",
    "p3.notrun": "this module did not run for this audit (audits from before it existed)",
    "p3.modulefailed": (a0) => `the module failed: ${a0}`,
    "p3.notmeasured": "not measured",
    "p3.trust": "Audit confidence",
    "p3.trustintro": "Three dimensions, kept apart on purpose: none of them can make up for another.",
    "p3.dimension": "dimension",
    "p3.score": "score",
    "p3.reasons": "why",
    "p3.dim.coverage": "coverage",
    "p3.dim.evidence": "evidence quality",
    "p3.dim.adversarial": "adversarial resistance",
    "p3.limits": "limits of this audit",
    "p3.exports": "Exports",
    "p3.exportswait": "available when the audit is done",
    "p3.export.html": "report (print to PDF)",
    "p3.export.replay": "replay manifest",
    "p3.exportsnote": "All built from the same stored evidence. No CVSS is computed; secrets are masked in every one.",
    "p3.assessment": "assessment",
    "p3.source": "source",
    "p3.rule": "rule",
    "p3.confidence": "confidence",
    "p3.prerequisites": "Prerequisites",
    "p3.impact": "Impact",
    "p3.mitigation": "Mitigation",
    "p3.limitsone": "Limits",
    "p3.references": "References",
    "p3.why": "why",
    "p3.snippethash": "snippet sha256",
    "p3.checks": "Checks",
    "p3.counterfactuals": "Exploitation conditions",
    "nav.views": "Views",
    "nav.twin": "Digital twin",
    "views.question": "What does this audit mean for each reader?",
    "views.what": "Three readings of the same findings and the same evidence: what is at stake, what to fix and where, and what each conclusion rests on.",
    "views.intro": "Same evidence in every view; only the reading changes.",
    "views.exec": "Executive",
    "views.dev": "Developer",
    "views.analyst": "Analyst",
    "views.stake": "What is at stake",
    "views.execline": (n, c, s) => `${n} finding(s) still standing, ${c} confirmed, ${s} critical or high.`,
    "views.execpaths": (n, c) => `${n} attack path(s), ${c} reaching something critical. Every path is argued from the code, never demonstrated.`,
    "views.top": "Most severe",
    "views.devnote": "Where, the code, and what to change. Discarded findings are left out.",
    "views.analystnote": "Every finding, discarded ones included, with how it was assessed. Open one for its evidence chain.",
    "twin.question": "What is this system made of, and where are the unknowns?",
    "twin.what": "A navigable model of the audited commit built from what the modules measured: areas of code, entry points, assets, services, dependencies, findings and attack paths. It is a map, not an executable copy.",
    "twin.note": "Built from the audit's measurements. Every attack path is hypothetical: nothing was run. A missing node is not a missing thing.",
    "twin.counts": (n, e, u) => `${n} node(s), ${e} link(s); ${u} node(s) with something unknown.`,
    "twin.type.area": "Areas",
    "twin.type.entry": "Entries",
    "twin.type.asset": "Assets",
    "twin.type.service": "Services",
    "twin.type.dependency": "Dependencies",
    "twin.type.finding": "Findings",
    "twin.type.persona": "Attackers",
    "twin.type.jewel": "Targets",
    "twin.pick": "Pick a node to see what it links to and what is unknown about it.",
    "twin.unknown": "Unknown",
    "twin.nounknown": "Nothing flagged as unknown.",
    "twin.links": "Links",
    "twin.sim.title": "Simulate: fix or confirm findings and recompute the attack paths",
    "twin.sim.intro": "Choose what happens to each finding on an attack path. Fixing removes its steps; confirming makes them solid, as a dynamic test would.",
    "twin.sim.none": "No finding is on an attack path: there is nothing to simulate.",
    "twin.sim.finding": "Finding",
    "twin.sim.keep": "keep",
    "twin.sim.fix": "fix",
    "twin.sim.confirm": "confirm",
    "twin.sim.run": "recompute paths",
    "twin.sim.nothing": "Choose at least one finding to fix or confirm.",
    "twin.sim.cost": (c) => `cost ${c}`,
    "twin.sim.summary": (b, a) => `Paths: ${b} before, ${a} after.`,
    "twin.sim.closed": "Closed",
    "twin.sim.changed": "Changed",
    "twin.sim.opened": "Opened",
    "twin.sim.remaining": "Still open",
    "twin.sim.note": "Recomputed on the attack graph the audit measured; nothing ran and the code is unchanged. A path the graph does not contain cannot be closed here.",
    "twin.rel.contains": "contains",
    "twin.rel.touches": "touches",
    "twin.rel.depends_on": "depends on",
    "twin.rel.affects": "affects",
    "twin.rel.reaches": "reaches",
    "twin.rel.crosses": "crosses into",
    "twin.rel.runs": "runs",
    "attacker.hypothetical": "hypothetical",
    "attacker.hypotheticalnote": "argued from the code; no step was executed",
    "blue.show": "detection proposal (Blue Team)",
    "blue.none": "No detection template for this category.",
    "blue.title": "Detection proposal",
    "blue.log": "log",
    "blue.detect": "detect",
    "whatif.title": "What if? Try a fix on a copy",
    "whatif.intro": "Paste a unified diff. It is applied to a temporary copy of the audited commit; the original repository is never touched. Its code is not run, except its tests when an administrator has turned on the sandbox, and then only in an isolated container.",
    "whatif.patch": "patch (unified diff)",
    "whatif.run": "try this fix",
    "whatif.running": "cloning the commit and measuring the fix…",
    "whatif.failed": "The fix could not be evaluated.",
    "whatif.verdict.promising": "Promising: the cited code is gone and nothing new appeared",
    "whatif.verdict.introduces_issues": "The fix introduces something to look at",
    "whatif.verdict.not_shown": "Not shown to fix the finding",
    "whatif.cited": "cited code still there",
    "whatif.gone": "rule findings gone",
    "whatif.new": "new rule findings",
    "whatif.drift": "controls weakened by the patch",
    "whatif.immune": "approved immune rules matching",
    "whatif.immuneoff": "not run",
    "whatif.untouched": "original untouched",
    "whatif.tests": "Tests",
    "whatif.diff": "the applied diff",
    "whatif.sandboxrunning": "Running the repository's tests in an isolated container, before and after the patch. This takes a few minutes…",
    "whatif.t.before": "audited commit",
    "whatif.t.after": "with the patch",
    "whatif.t.pass": "pass",
    "whatif.t.fail": "fail",
    "whatif.t.none": "no tests collected",
    "whatif.t.timeout": "timed out",
    "whatif.t.isolation": "where",
    "whatif.t.isolationtext": (img) => `throwaway container ${img}, no network, read-only, no capabilities, as nobody`,
    "whatif.t.installed": "dependencies installed",
    "whatif.t.broken": "Tests the patch breaks",
    "whatif.t.fixed": "Tests the patch fixes",
    "whatif.t.output": "test output (with the patch)",
    "whatif.t.candidates": "Tests that cover the changed files, by name:",
    "whatif.t.reason.off": "The repository's tests are not run: an administrator can turn on the sandbox.",
    "whatif.t.reason.no_runner": "No test runner was recognised (pytest or npm test).",
    "whatif.t.reason.error": "The sandbox could not run the tests.",
    "memory.approval": "approval",
    "memory.approved": (who) => `approved by ${who}`,
    "memory.pending": "waiting for approval: not used yet",
    "memory.approve": "approve",
    "memory.revoke": "revoke",
    "replay.title": "Replay",
    "replay.intro": "Audit the same commit again with the engine and settings in force now, and compare. A model does not answer twice the same; deterministic rules should.",
    "replay.run": "replay this audit",
    "replay.compare": "Against the original",
    "replay.agreement": (a, both, o, r) => `Agreement ${a}: ${both} finding(s) in both, ${o} only in the original, ${r} only in the replay.`,
    "replay.rulesagree": "Rule findings agree exactly.",
    "replay.rulesdiffer": "Rule findings differ: the engine or its settings changed.",
    "replay.note": "Model findings vary between runs: disagreement there is expected and measured, not hidden.",
    "replay.only_original": "Only in the original",
    "replay.only_replay": "Only in the replay",
    "mcp.check": "check the taxonomy against the official page now",
    "mcp.checkfailed": (e) => `Could not check (${e}): the pinned version is still the one in use.`,
    "mcp.checkok": (at, ed) => `Matches the official OWASP MCP Top 10 (edition ${ed}), checked ${at}.`,
    "mcp.checkdiff": (d) => `The official names differ: ${d}`,
    "surface.services": "Services",
    "surface.servicesnote": "Containers, datastores, third-party SDKs and external hosts named in the code and its configuration.",
    "surface.ports": "published ports",
    "surface.flags": "flags",
    "surface.datastores": "datastores",
    "surface.thirdparty": "third-party services",
    "surface.hosts": "external hosts",
    "surface.noservices": "No services found in the code.",
    "surface.novalidation": "no validation seen",
    "surface.validation": "validation",
    "validation.declared": "seen",
    "validation.none_seen": "not seen",
    "taint.title": "Taint: source to sink",
    "taint.line": (l, k) => `Analysed: ${l}. Flows by sink: ${k}.`,
    "taint.flow": "Flow",
    "taint.step.source": "source",
    "taint.step.assign": "through",
    "taint.step.sink": "sink",
    "claims.title": "Documentation against code",
    "claims.intro": "Security promises in README, SECURITY and docs, and whether the code shows them.",
    "claims.none": "The documentation makes no security claim this checks.",
    "claims.lowers": "The documentation promises controls the code does not show: trust the code, not the README.",
    "claims.claim": "claim",
    "claims.status": "status",
    "claims.said": "said in",
    "claims.code": "in the code",
    "claims.backed": "backed",
    "claims.unbacked": "not seen in code",
    "claims.contradicted": "contradicted",
    "dead.title": "Apparently unused code",
    "dead.note": "Functions, files and blueprints nothing in the repository mentions. Reflection, plugins and dynamic imports can still reach them.",
    "dead.none": "Nothing apparently unused.",
    "dead.function": "function",
    "dead.class": "class",
    "dead.export": "export",
    "dead.file": "file",
    "dead.blueprint": "blueprint not registered",
    "supply.maintdone": (n, s, d, days) => `Registries asked about ${n} direct dependency(ies): ${s} with no release in ${days} days, ${d} deprecated.`,
    "supply.maintoff": "Maintenance not checked: registries are only asked with SECAUDIT_ABANDONED_CHECK=1 (package names leave the server).",
    "supply.directonly": "No lockfile: only direct dependencies are known; transitive ones need a lockfile.",
    "supply.maint": "maintenance",
    "supply.deprecated": "deprecated",
    "supply.days": (d) => `${d} days since release`,
    "detail.pr": "pull request",
    "detail.base": "compared with",
    "detail.replayof": "replay of",
    "trigger.replay": "replay",
    "changes.pr": (n) => `Pull request #${n}: the head compared with its base.`,
    "changes.replay": "A replay: compared with the audit it repeats.",
    "changes.basenoaudit": (b) => `No finished audit of ${b} to compare findings with; the code changes are below.`,
    "audit.advanced": "options",
    "audit.branch": "branch",
    "audit.base": "compare with (branch or commit)",
    "audit.baseph": "main or a commit sha",
    "audit.commit": "exact commit",
    "audit.err.url": "Enter a GitHub repository: https://github.com/<owner>/<repo> or <owner>/<repo>.",
    "audit.err.name": "That repository name is not valid.",
    "audit.err.owner": (owners) => `This instance only audits repositories of: ${owners}.`,
    "audit.err.ref": "A branch or commit in the options is not valid: use a branch name (main, feature/x) or a full commit sha.",
    "audit.err.sha": "The exact commit must be a full 40-character sha.",
    "p3.discarded": "Discarded hypotheses",
    "p3.unknowns": "Unknowns",
    "p3.showchain": "show the evidence chain",
    "p3.chain": "Evidence chain",
    "p3.finding": "finding",
    "mcp.taxonomy": (a0, a1, a2) => `Taxonomy: ${a0}, checked against ${a2} on ${a1}.`,
    "mcp.inventory": "Inventory",
    "mcp.none": "No MCP server, client or configuration was found.",
    "mcp.counts": (a0, a1, a2, a3) => `${a0} server(s), ${a1} client(s), ${a2} configuration file(s), ${a3} tool(s), resource(s) or prompt(s).`,
    "mcp.config": "configuration",
    "mcp.servers": "servers",
    "mcp.tool": "name",
    "mcp.kind": "kind",
    "mcp.categories": "By OWASP MCP category",
    "mcp.count": "findings",
    "mcp.nofindings": "No MCP finding. That is not proof the MCP surface is safe.",
    "mcp.catalog": "Rules per category",
    "mcp.inspects": "inspects",
    "mcp.static": "statically detectable",
    "mcp.confirm": "confirmed when",
    "mcp.fp": "usual false positives",
    "supply.deps": "Dependencies",
    "supply.components": (a0, a1, a2) => `${a0} component(s), ${a1} direct. ${a2}`,
    "supply.manifests": (a0) => `Read from: ${a0}`,
    "supply.osvdone": (a0, a1) => `OSV.dev asked about ${a0} exact version(s): ${a1} affected.`,
    "supply.osverror": (a0) => `OSV.dev could not be asked: ${a0}`,
    "supply.osvoff": "Known vulnerabilities were not looked up: OSV.dev is only asked with SECAUDIT_OSV_CHECK=1 (package names and versions leave the server).",
    "supply.list": "every component",
    "supply.name": "package",
    "supply.version": "version",
    "supply.direct": "direct",
    "supply.scope": "scope",
    "supply.vulns": "advisories",
    "supply.yes": "yes",
    "supply.no": "no",
    "supply.ghosts": "Apparently unused",
    "supply.ghostsnote": "Declared and mentioned nowhere else. Plugins, entry points and dynamic imports can still use them.",
    "supply.noghosts": "Every direct dependency is mentioned somewhere in the code.",
    "supply.manifest": "declared in",
    "supply.signals": "Supply-chain signals",
    "supply.secrets": "Secret exposure timeline",
    "supply.secretsline": (a0, a1, a2) => `${a0} secret(s) in the checkout; ${a1} commit(s) of history read; ${a2} only in history.`,
    "supply.rotate": "Revoke and rotate every secret listed: removing it from the code does not remove it from the history.",
    "supply.kind": "kind",
    "supply.mask": "mask (never the value)",
    "supply.first": "first commit",
    "supply.removed": "removed in",
    "supply.now": "still there",
    "supply.beforehistory": "* its first commit is where the fetched history stops: it may be older.",
    "supply.truncated": "The history was too large to read whole; the timeline is partial.",
    "surface.none": "No entry point was recognised.",
    "surface.notinv": (a0) => `Not inventoried (languages not read): ${a0}`,
    "surface.boundaries": "Trust boundaries",
    "surface.boundariesnote": "Untrusted input crosses into the application at each entry, and from there into what it touches.",
    "surface.via": "entry",
    "surface.to": "reaches",
    "surface.entries": "entries",
    "surface.noauth": "no auth seen",
    "surface.items": "Entry points",
    "surface.route": "route",
    "surface.auth": "auth",
    "surface.touches": "touches",
    "kind.endpoint": "endpoint",
    "kind.webhook": "webhook",
    "kind.file_upload": "file upload",
    "kind.websocket": "websocket",
    "kind.cli": "CLI",
    "kind.scheduled": "scheduled job",
    "kind.mcp_tool": "MCP tool",
    "asset.database": "database",
    "asset.filesystem": "filesystem",
    "asset.network": "network",
    "asset.subprocess": "subprocess",
    "asset.deserialization": "deserialization",
    "asset.template": "raw template",
    "asset.application": "application",
    "auth.declared": "declared",
    "auth.file_level": "in the file",
    "auth.none_seen": "none seen",
    "auth.unknown": "unknown",
    "auth.not_applicable": "n/a",
    "changes.findings": "Findings since the previous audit",
    "changes.first": "This is the first finished audit of the project: nothing to compare with.",
    "changes.against": (a0, a1) => `Compared with ${a0} → ${a1}.`,
    "changes.new": "new",
    "changes.reintroduced": "reintroduced",
    "changes.fixed": "fixed",
    "changes.persisting": "persisting",
    "changes.total": "total",
    "changes.drift": "Security drift",
    "changes.files": (a0, a1, a2) => `${a0} file(s) changed, ${a1} critical, ${a2} workflow(s).`,
    "changes.driftnote": "Patterns on the diff: a place to look, not a verdict.",
    "changes.control": "control",
    "changes.side": "line",
    "changes.line": "text",
    "changes.nodrift": "No weakened control was recognised in the diff.",
    "side.added": "added",
    "side.removed": "removed",
    "changes.dna": "Project history (DNA)",
    "changes.recurrent": (a0) => `${a0} finding(s) have appeared in more than one audit.`,
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
    "jewels.phase": "Lo que un atacante querría por encima de todo en el proyecto " +
      "de la auditoría seleccionada. secaudit sugiere las que señala el " +
      "repositorio; las declaradas las sustituyen, y una sugerencia quitada no " +
      "vuelve. Cuentan desde la siguiente auditoría.",
    "jewels.none": "Selecciona una auditoría para ver las joyas de la corona de su proyecto.",
    "jewels.empty": "Aún no hay joyas de la corona: la siguiente auditoría las sugiere.",
    "jewels.kind": "tipo",
    "jewels.target": "qué exactamente",
    "jewels.add": "añadir",
    "jewels.remove": "quitar",
    "jewels.by.user": "declarada",
    "jewels.by.suggested": "sugerida",
    "jewels.removelabel": (k) => `quitar ${k}`,
    "jewel.secrets": "secretos",
    "jewel.user_data": "datos de usuarios",
    "jewel.deployment": "despliegue",
    "jewel.administration": "administración",
    "jewel.code_execution": "ejecución de código",
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
      "y el arreglo único que cierra más caminos.",
    "summary.nopaths": "Ningún perfil de atacante llega a una joya de la corona con lo que se ha demostrado.",
    "summary.pathcount": (n, c) => `${n} camino(s) a una joya de la corona, ${c} crítico(s).`,
    "summary.topfix": "El arreglo que más corta:",
    "summary.seeattacker": "ver los caminos",
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
    "attacker.notrun": "La mirada del atacante no se ejecutó en esta auditoría: es anterior al módulo.",
    "attacker.failed": "La mirada del atacante falló en esta auditoría; los hallazgos siguen en pie sin ella.",
    "attacker.profile": "perfil de atacante",
    "attacker.jewel": "joya de la corona",
    "attacker.cut": "el arreglo que más corta",
    "attacker.cutintro": "Quitarlo deja estos pares de perfil y joya sin ningún " +
      "camino, no con uno más largo. Los pasos no concluyentes nunca cuentan.",
    "attacker.cutsome": (n) => `corta ${n} camino(s)`,
    "attacker.then": "después",
    "attacker.nocut": "Ningún arreglo único corta un camino: cada par tiene otra entrada.",
    "attacker.matrix": "cada perfil frente a cada joya",
    "attacker.matrixintro": "El coste del camino más barato; vacío donde no lo hay.",
    "attacker.nopath": "sin camino",
    "attacker.path": "el camino",
    "attacker.nopathhere": "Este perfil no tiene camino a esta joya con lo que se ha demostrado.",
    "attacker.cost": (c) => `coste ${c}`,
    "attacker.tentative": "provisional: un paso se apoya en un hallazgo no concluyente",
    "attacker.sees": "qué vería",
    "attacker.works": "por qué funciona",
    "attacker.needs": "qué necesita",
    "attacker.gains": "qué gana",
    "attacker.implied": "se sigue de tener la capacidad anterior",
    "attacker.costdetail": (d) => `${d.steps} paso(s) · privilegios: ${d.privileges}` +
      `${d.interaction ? " · necesita una acción de la víctima" : ""}${d.trace ? " · deja rastro" : ""}`,
    "attacker.nofindings": "Ningún hallazgo demostrado, ningún fichero poco vigilado y " +
      "ningún camino de agentes: no hay nada que encadenar.",
    "attacker.limits": "Los caminos se describen, no se arman: ni exploits ni payloads. " +
      "Solo usan hallazgos demostrados (alcanzables o corroborados); los no " +
      "concluyentes van discontinuos. El coste cuenta pasos, privilegios, una acción " +
      "de la víctima y el rastro.",
    "fix.finding": (x) => `arreglar el hallazgo «${x.title || "?"}» (${x.file || "—"})`,
    "fix.divergence": (x) => `quitar la ${t(`kind.${x.kind}`)} de ${x.file || "—"}`,
    "fix.leverage": (x) => `poner ${x.file || "?"} bajo revisión (un responsable, aprobaciones obligatorias)`,
    "fix.agent": (x) => `acotar la configuración de agentes de ${(x.files || []).join(", ")}`,
    "persona.anonymous": "anónimo",
    "persona.authenticated_user": "usuario autenticado",
    "persona.malicious_contributor": "contribuidor malicioso",
    "persona.compromised_dependency": "dependencia comprometida",
    "persona.manipulated_agent": "agente manipulado",
    "personadesc.anonymous": "desde internet, sin cuenta",
    "personadesc.authenticated_user": "con una cuenta de pocos privilegios",
    "personadesc.malicious_contributor": "puede abrir pull requests",
    "personadesc.compromised_dependency": "el código de un paquete se ejecuta dentro de la aplicación",
    "personadesc.manipulated_agent": "un agente de IA en el repositorio, con instrucciones inyectadas",
    "node.sends_requests": "envía peticiones a la aplicación",
    "node.user_account": "tiene una cuenta de usuario",
    "node.gets_session": "tiene la sesión de otro usuario",
    "node.accesses_admin": "administra la aplicación",
    "node.executes_code": "ejecuta código donde corre la aplicación",
    "node.reads_user_data": "lee datos de usuarios",
    "node.writes_db": "escribe en la base de datos",
    "node.reads_files": "lee ficheros del servidor",
    "node.reads_secret": "lee un secreto",
    "node.reaches_internal": "llega a la red interna",
    "node.reads_repository": "lee el repositorio",
    "node.changes_code": "consigue meter un cambio en la rama por defecto",
    "node.runs_in_ci": "ejecuta código en CI",
    "node.executes_on_developer": "ejecuta código en la máquina de un desarrollador",
    "node.controls_agent": "dirige un agente de IA en el repositorio",
    "node.publishes_release": "publica una versión o despliega",
    "works.sql_injection": "la consulta se construye con la entrada en vez de con parámetros",
    "works.command_injection": "la entrada llega a una orden de shell",
    "works.code_injection": "la entrada se evalúa como código",
    "works.deserialization": "se deserializan en objetos datos que no son de fiar",
    "works.path_traversal": "una ruta que viene de la entrada no se limita a su directorio",
    "works.ssrf": "el servidor pide una URL que elige quien llama",
    "works.idor": "el registro se pide por su id sin comprobar de quién es",
    "works.privilege": "no se comprueba el rol antes de la acción",
    "works.missing_auth": "el endpoint no exige autenticación",
    "works.session": "las sesiones no se atan, rotan ni protegen",
    "works.xss": "la entrada se pinta como marcado sin escapar",
    "works.csrf": "las peticiones que cambian estado no llevan token anti-falsificación",
    "works.brute_force": "no se limitan los intentos",
    "works.hardcoded_secret": "hay una credencial guardada en el código",
    "works.info_disclosure": "los errores revelan detalles internos",
    "works.cors": "otros orígenes pueden hacer peticiones con credenciales",
    "works.pr_target": "el workflow corre con pull_request_target, con los secretos del repositorio base, para el PR de cualquiera",
    "works.ci_secrets": "el workflow recibe secretos del repositorio",
    "works.ci_deploy": "el workflow despliega o publica lo que ejecuta",
    "works.merge": "los cambios entran con poca revisión",
    "works.hidden_instructions": "el fichero dice una cosa a una persona y otra al agente que lo lee",
    "works.runs_on_open": "hay código que se ejecuta al instalar, hacer checkout o abrir la carpeta, sin que nadie lo pida",
    "works.in_repository": "lo que se fusiona es lo que clonan los desarrolladores",
    "filter.context": "severidad contextual",
    "filter.onnopath": "en ningún camino",
    "filter.persona": "perfil de atacante",
    "findings.context": "severidad contextual",
    "findings.personas": "quién puede usarlo",
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
    "nav.mcp": "MCP",
    "nav.supply": "Cadena de suministro",
    "nav.surface": "Superficie de ataque",
    "nav.changes": "Cambios",
    "mcp.question": "¿Qué servidores, herramientas y configuraciones MCP lleva este repositorio, y qué exponen?",
    "mcp.what": "Comprobaciones estáticas contra el OWASP MCP Top 10. No se instala, arranca ni conecta nada: lo que solo un servidor en ejecución puede mostrar se marca como pendiente de prueba dinámica.",
    "supply.question": "¿De qué depende, de dónde viene y qué credenciales ha filtrado?",
    "supply.what": "Manifiestos y lockfiles leídos como texto (no se ejecuta ningún gestor de paquetes), un SBOM CycloneDX, señales de confusión de dependencias, dependencias aparentemente sin uso y cada credencial del código y del historial descargado.",
    "surface.question": "¿Por dónde entra la entrada externa y qué puede alcanzar?",
    "surface.what": "Endpoints, webhooks, subidas, CLIs, tareas y herramientas MCP, leídos del código, con los límites de confianza que cruzan. La falta de un rastro de autenticación es un sitio que mirar, no un hallazgo.",
    "changes.question": "¿Qué cambió desde la última auditoría y se debilitó algún control?",
    "changes.what": "Hallazgos nuevos, corregidos, persistentes y reintroducidos por huella; ficheros críticos y workflows cambiados; y deriva de seguridad leída del diff entre los dos commits auditados.",
    "filter.assessment": "evaluación",
    "assessment.confirmed": "confirmado",
    "assessment.potential": "potencial",
    "assessment.discarded": "descartado",
    "assessment.unverifiable": "no verificable",
    "source.model": "modelo (comprobado)",
    "source.rule": "regla determinista",
    "source.immune": "regla inmunológica",
    "band.high": "alta",
    "band.medium": "media",
    "band.low": "baja",
    "cond.verified": "verificada",
    "cond.discarded": "descartada",
    "cond.unknown": "desconocida",
    "p3.notrun": "este módulo no se ejecutó en esta auditoría (auditorías anteriores a él)",
    "p3.modulefailed": (a0) => `el módulo falló: ${a0}`,
    "p3.notmeasured": "no medido",
    "p3.trust": "Confianza de la auditoría",
    "p3.trustintro": "Tres dimensiones, separadas a propósito: ninguna compensa a otra.",
    "p3.dimension": "dimensión",
    "p3.score": "puntuación",
    "p3.reasons": "por qué",
    "p3.dim.coverage": "cobertura",
    "p3.dim.evidence": "calidad de la evidencia",
    "p3.dim.adversarial": "resistencia adversarial",
    "p3.limits": "límites de esta auditoría",
    "p3.exports": "Exportaciones",
    "p3.exportswait": "disponibles cuando termine la auditoría",
    "p3.export.html": "informe (imprimir a PDF)",
    "p3.export.replay": "manifiesto de replay",
    "p3.exportsnote": "Todas salen de la misma evidencia guardada. No se calcula CVSS; los secretos van enmascarados en todas.",
    "p3.assessment": "evaluación",
    "p3.source": "origen",
    "p3.rule": "regla",
    "p3.confidence": "confianza",
    "p3.prerequisites": "Prerrequisitos",
    "p3.impact": "Impacto",
    "p3.mitigation": "Mitigación",
    "p3.limitsone": "Límites",
    "p3.references": "Referencias",
    "p3.why": "por qué",
    "p3.snippethash": "sha256 del fragmento",
    "p3.checks": "Comprobaciones",
    "p3.counterfactuals": "Condiciones de explotación",
    "nav.views": "Vistas",
    "nav.twin": "Gemelo digital",
    "views.question": "¿Qué significa esta auditoría para cada lector?",
    "views.what": "Tres lecturas de los mismos hallazgos y la misma evidencia: qué está en juego, qué corregir y dónde, y en qué se apoya cada conclusión.",
    "views.intro": "La misma evidencia en todas las vistas; solo cambia la lectura.",
    "views.exec": "Dirección",
    "views.dev": "Desarrollo",
    "views.analyst": "Analista",
    "views.stake": "Qué está en juego",
    "views.execline": (n, c, s) => `${n} hallazgo(s) en pie, ${c} confirmados, ${s} críticos o altos.`,
    "views.execpaths": (n, c) => `${n} camino(s) de ataque, ${c} hasta algo crítico. Todos se argumentan desde el código; ninguno se ha demostrado.`,
    "views.top": "Lo más grave",
    "views.devnote": "Dónde, el código y qué cambiar. Los descartados no aparecen.",
    "views.analystnote": "Todos los hallazgos, descartados incluidos, con cómo se evaluaron. Abre uno para ver su cadena de evidencia.",
    "twin.question": "¿De qué está hecho este sistema y dónde están las incógnitas?",
    "twin.what": "Un modelo navegable del commit auditado, construido con lo que midieron los módulos: zonas de código, puntos de entrada, activos, servicios, dependencias, hallazgos y caminos de ataque. Es un mapa, no una copia ejecutable.",
    "twin.note": "Construido con las mediciones de la auditoría. Todos los caminos de ataque son hipotéticos: no se ejecutó nada. Que falte un nodo no significa que falte la cosa.",
    "twin.counts": (n, e, u) => `${n} nodo(s), ${e} enlace(s); ${u} nodo(s) con algo desconocido.`,
    "twin.type.area": "Zonas",
    "twin.type.entry": "Entradas",
    "twin.type.asset": "Activos",
    "twin.type.service": "Servicios",
    "twin.type.dependency": "Dependencias",
    "twin.type.finding": "Hallazgos",
    "twin.type.persona": "Atacantes",
    "twin.type.jewel": "Objetivos",
    "twin.pick": "Elige un nodo para ver con qué enlaza y qué se desconoce de él.",
    "twin.unknown": "Desconocido",
    "twin.nounknown": "Nada marcado como desconocido.",
    "twin.links": "Enlaces",
    "twin.sim.title": "Simular: arreglar o confirmar hallazgos y recalcular los caminos de ataque",
    "twin.sim.intro": "Elige qué pasa con cada hallazgo que está en un camino de ataque. Arreglarlo quita sus pasos; confirmarlo los vuelve sólidos, como haría una prueba dinámica.",
    "twin.sim.none": "Ningún hallazgo está en un camino de ataque: no hay nada que simular.",
    "twin.sim.finding": "Hallazgo",
    "twin.sim.keep": "dejar",
    "twin.sim.fix": "arreglar",
    "twin.sim.confirm": "confirmar",
    "twin.sim.run": "recalcular caminos",
    "twin.sim.nothing": "Elige al menos un hallazgo que arreglar o confirmar.",
    "twin.sim.cost": (c) => `coste ${c}`,
    "twin.sim.summary": (b, a) => `Caminos: ${b} antes, ${a} después.`,
    "twin.sim.closed": "Cerrados",
    "twin.sim.changed": "Cambiados",
    "twin.sim.opened": "Abiertos",
    "twin.sim.remaining": "Siguen abiertos",
    "twin.sim.note": "Recalculado sobre el grafo de ataque que midió la auditoría; no se ejecutó nada y el código no cambia. Un camino que el grafo no contiene no se puede cerrar aquí.",
    "twin.rel.contains": "contiene",
    "twin.rel.touches": "toca",
    "twin.rel.depends_on": "depende de",
    "twin.rel.affects": "afecta a",
    "twin.rel.reaches": "alcanza",
    "twin.rel.crosses": "entra en",
    "twin.rel.runs": "ejecuta",
    "attacker.hypothetical": "hipotético",
    "attacker.hypotheticalnote": "argumentado desde el código; no se ejecutó ningún paso",
    "blue.show": "propuesta de detección (Blue Team)",
    "blue.none": "No hay plantilla de detección para esta categoría.",
    "blue.title": "Propuesta de detección",
    "blue.log": "registrar",
    "blue.detect": "detectar",
    "whatif.title": "¿Y si…? Prueba un arreglo en una copia",
    "whatif.intro": "Pega un diff unificado. Se aplica a una copia temporal del commit auditado; el repositorio original no se toca. Su código no se ejecuta, salvo sus tests si el administrador activó el sandbox, y entonces solo en un contenedor aislado.",
    "whatif.patch": "parche (diff unificado)",
    "whatif.run": "probar este arreglo",
    "whatif.running": "clonando el commit y midiendo el arreglo…",
    "whatif.failed": "No se pudo evaluar el arreglo.",
    "whatif.verdict.promising": "Prometedor: el código citado ya no está y no ha aparecido nada nuevo",
    "whatif.verdict.introduces_issues": "El arreglo introduce algo que revisar",
    "whatif.verdict.not_shown": "No se ha visto que corrija el hallazgo",
    "whatif.cited": "el código citado sigue ahí",
    "whatif.gone": "hallazgos de regla que desaparecen",
    "whatif.new": "hallazgos de regla nuevos",
    "whatif.drift": "controles debilitados por el parche",
    "whatif.immune": "reglas inmunes aprobadas que coinciden",
    "whatif.immuneoff": "no ejecutadas",
    "whatif.untouched": "original sin tocar",
    "whatif.tests": "Tests",
    "whatif.diff": "el diff aplicado",
    "whatif.sandboxrunning": "Ejecutando los tests del repositorio en un contenedor aislado, antes y después del parche. Tarda unos minutos…",
    "whatif.t.before": "commit auditado",
    "whatif.t.after": "con el parche",
    "whatif.t.pass": "pasan",
    "whatif.t.fail": "fallan",
    "whatif.t.none": "no se recogió ningún test",
    "whatif.t.timeout": "se agotó el tiempo",
    "whatif.t.isolation": "dónde",
    "whatif.t.isolationtext": (img) => `contenedor desechable ${img}, sin red, solo lectura, sin capacidades, como nobody`,
    "whatif.t.installed": "dependencias instaladas",
    "whatif.t.broken": "Tests que rompe el parche",
    "whatif.t.fixed": "Tests que arregla el parche",
    "whatif.t.output": "salida de los tests (con el parche)",
    "whatif.t.candidates": "Tests que cubren los ficheros cambiados, por nombre:",
    "whatif.t.reason.off": "Los tests del repositorio no se ejecutan: el administrador puede activar el sandbox.",
    "whatif.t.reason.no_runner": "No se reconoció ningún ejecutor de tests (pytest o npm test).",
    "whatif.t.reason.error": "El sandbox no pudo ejecutar los tests.",
    "memory.approval": "aprobación",
    "memory.approved": (who) => `aprobada por ${who}`,
    "memory.pending": "pendiente de aprobación: aún no se usa",
    "memory.approve": "aprobar",
    "memory.revoke": "retirar",
    "replay.title": "Replay",
    "replay.intro": "Audita otra vez el mismo commit con el motor y la configuración actuales, y compara. Un modelo no responde dos veces igual; las reglas deterministas sí deberían.",
    "replay.run": "repetir esta auditoría",
    "replay.compare": "Frente a la original",
    "replay.agreement": (a, both, o, r) => `Coincidencia ${a}: ${both} hallazgo(s) en ambas, ${o} solo en la original, ${r} solo en la repetición.`,
    "replay.rulesagree": "Los hallazgos de regla coinciden exactamente.",
    "replay.rulesdiffer": "Los hallazgos de regla difieren: cambió el motor o su configuración.",
    "replay.note": "Los hallazgos del modelo varían entre ejecuciones: esa diferencia se espera y se mide, no se oculta.",
    "replay.only_original": "Solo en la original",
    "replay.only_replay": "Solo en la repetición",
    "mcp.check": "comprobar ahora la taxonomía contra la página oficial",
    "mcp.checkfailed": (e) => `No se pudo comprobar (${e}): se sigue usando la versión fijada.`,
    "mcp.checkok": (at, ed) => `Coincide con el OWASP MCP Top 10 oficial (edición ${ed}), comprobado el ${at}.`,
    "mcp.checkdiff": (d) => `Los nombres oficiales difieren: ${d}`,
    "surface.services": "Servicios",
    "surface.servicesnote": "Contenedores, almacenes de datos, SDKs de terceros y hosts externos que nombran el código y su configuración.",
    "surface.ports": "puertos publicados",
    "surface.flags": "marcas",
    "surface.datastores": "almacenes de datos",
    "surface.thirdparty": "servicios de terceros",
    "surface.hosts": "hosts externos",
    "surface.noservices": "No se encontraron servicios en el código.",
    "surface.novalidation": "sin validación visible",
    "surface.validation": "validación",
    "validation.declared": "visible",
    "validation.none_seen": "no visible",
    "taint.title": "Taint: de la fuente al sumidero",
    "taint.line": (l, k) => `Analizado: ${l}. Flujos por sumidero: ${k}.`,
    "taint.flow": "Flujo",
    "taint.step.source": "fuente",
    "taint.step.assign": "pasa por",
    "taint.step.sink": "sumidero",
    "claims.title": "Documentación frente a código",
    "claims.intro": "Promesas de seguridad del README, SECURITY y la documentación, y si el código las muestra.",
    "claims.none": "La documentación no hace ninguna afirmación de seguridad de las que se comprueban.",
    "claims.lowers": "La documentación promete controles que el código no muestra: fíate del código, no del README.",
    "claims.claim": "afirmación",
    "claims.status": "estado",
    "claims.said": "dicho en",
    "claims.code": "en el código",
    "claims.backed": "respaldada",
    "claims.unbacked": "no se ve en el código",
    "claims.contradicted": "contradicha",
    "dead.title": "Código aparentemente sin uso",
    "dead.note": "Funciones, ficheros y blueprints que nada del repositorio menciona. La reflexión, los plugins y las importaciones dinámicas pueden alcanzarlos igualmente.",
    "dead.none": "Nada aparentemente sin uso.",
    "dead.function": "función",
    "dead.class": "clase",
    "dead.export": "export",
    "dead.file": "fichero",
    "dead.blueprint": "blueprint sin registrar",
    "supply.maintdone": (n, s, d, days) => `Se preguntó a los registros por ${n} dependencia(s) directa(s): ${s} sin versiones en ${days} días, ${d} obsoletas.`,
    "supply.maintoff": "Mantenimiento no comprobado: los registros solo se consultan con SECAUDIT_ABANDONED_CHECK=1 (salen del servidor los nombres de paquetes).",
    "supply.directonly": "Sin lockfile: solo se conocen las dependencias directas; las transitivas necesitan un lockfile.",
    "supply.maint": "mantenimiento",
    "supply.deprecated": "obsoleta",
    "supply.days": (d) => `${d} días desde la última versión`,
    "detail.pr": "pull request",
    "detail.base": "comparado con",
    "detail.replayof": "repetición de",
    "trigger.replay": "replay",
    "changes.pr": (n) => `Pull request #${n}: la cabeza comparada con su base.`,
    "changes.replay": "Una repetición: comparada con la auditoría que repite.",
    "changes.basenoaudit": (b) => `No hay una auditoría terminada de ${b} con la que comparar hallazgos; los cambios de código están abajo.`,
    "audit.advanced": "opciones",
    "audit.branch": "rama",
    "audit.base": "comparar con (rama o commit)",
    "audit.baseph": "main o un sha de commit",
    "audit.commit": "commit exacto",
    "audit.err.url": "Introduce un repositorio de GitHub: https://github.com/<owner>/<repo> o <owner>/<repo>.",
    "audit.err.name": "Ese nombre de repositorio no es válido.",
    "audit.err.owner": (owners) => `Esta instancia solo audita repositorios de: ${owners}.`,
    "audit.err.ref": "Una rama o un commit de las opciones no es válido: usa un nombre de rama (main, feature/x) o un sha de commit completo.",
    "audit.err.sha": "El commit exacto tiene que ser un sha completo de 40 caracteres.",
    "p3.discarded": "Hipótesis descartadas",
    "p3.unknowns": "Incógnitas",
    "p3.showchain": "ver la cadena de evidencia",
    "p3.chain": "Cadena de evidencia",
    "p3.finding": "hallazgo",
    "mcp.taxonomy": (a0, a1, a2) => `Taxonomía: ${a0}, comprobada contra ${a2} el ${a1}.`,
    "mcp.inventory": "Inventario",
    "mcp.none": "No se encontró ningún servidor, cliente ni configuración MCP.",
    "mcp.counts": (a0, a1, a2, a3) => `${a0} servidor(es), ${a1} cliente(s), ${a2} fichero(s) de configuración, ${a3} herramienta(s), recurso(s) o prompt(s).`,
    "mcp.config": "configuración",
    "mcp.servers": "servidores",
    "mcp.tool": "nombre",
    "mcp.kind": "tipo",
    "mcp.categories": "Por categoría OWASP MCP",
    "mcp.count": "hallazgos",
    "mcp.nofindings": "Ningún hallazgo MCP. Eso no prueba que la superficie MCP sea segura.",
    "mcp.catalog": "Reglas por categoría",
    "mcp.inspects": "inspecciona",
    "mcp.static": "detectable estáticamente",
    "mcp.confirm": "se confirma cuando",
    "mcp.fp": "falsos positivos habituales",
    "supply.deps": "Dependencias",
    "supply.components": (a0, a1, a2) => `${a0} componente(s), ${a1} directos. ${a2}`,
    "supply.manifests": (a0) => `Leídos de: ${a0}`,
    "supply.osvdone": (a0, a1) => `Se preguntó a OSV.dev por ${a0} versión(es) exactas: ${a1} afectadas.`,
    "supply.osverror": (a0) => `No se pudo preguntar a OSV.dev: ${a0}`,
    "supply.osvoff": "No se consultaron vulnerabilidades conocidas: OSV.dev solo se consulta con SECAUDIT_OSV_CHECK=1 (salen del servidor nombres y versiones de paquetes).",
    "supply.list": "todos los componentes",
    "supply.name": "paquete",
    "supply.version": "versión",
    "supply.direct": "directa",
    "supply.scope": "ámbito",
    "supply.vulns": "avisos",
    "supply.yes": "sí",
    "supply.no": "no",
    "supply.ghosts": "Aparentemente sin uso",
    "supply.ghostsnote": "Declaradas y no mencionadas en ningún otro sitio. Plugins, entry points e importaciones dinámicas pueden usarlas igualmente.",
    "supply.noghosts": "Todas las dependencias directas se mencionan en algún punto del código.",
    "supply.manifest": "declarada en",
    "supply.signals": "Señales de la cadena de suministro",
    "supply.secrets": "Línea temporal de exposición de secretos",
    "supply.secretsline": (a0, a1, a2) => `${a0} secreto(s) en el checkout; ${a1} commit(s) de historial leídos; ${a2} solo en el historial.`,
    "supply.rotate": "Revoca y rota cada secreto listado: quitarlo del código no lo quita del historial.",
    "supply.kind": "tipo",
    "supply.mask": "máscara (nunca el valor)",
    "supply.first": "primer commit",
    "supply.removed": "eliminado en",
    "supply.now": "sigue ahí",
    "supply.beforehistory": "* su primer commit es donde se corta el historial descargado: puede ser más antiguo.",
    "supply.truncated": "El historial era demasiado grande para leerlo entero; la línea temporal es parcial.",
    "surface.none": "No se reconoció ningún punto de entrada.",
    "surface.notinv": (a0) => `Sin inventariar (lenguajes no leídos): ${a0}`,
    "surface.boundaries": "Límites de confianza",
    "surface.boundariesnote": "La entrada no confiable cruza a la aplicación en cada entrada, y de ahí a lo que toca.",
    "surface.via": "entrada",
    "surface.to": "alcanza",
    "surface.entries": "entradas",
    "surface.noauth": "sin auth visible",
    "surface.items": "Puntos de entrada",
    "surface.route": "ruta",
    "surface.auth": "auth",
    "surface.touches": "toca",
    "kind.endpoint": "endpoint",
    "kind.webhook": "webhook",
    "kind.file_upload": "subida de ficheros",
    "kind.websocket": "websocket",
    "kind.cli": "CLI",
    "kind.scheduled": "tarea programada",
    "kind.mcp_tool": "herramienta MCP",
    "asset.database": "base de datos",
    "asset.filesystem": "sistema de ficheros",
    "asset.network": "red",
    "asset.subprocess": "subproceso",
    "asset.deserialization": "deserialización",
    "asset.template": "plantilla sin escapar",
    "asset.application": "aplicación",
    "auth.declared": "declarada",
    "auth.file_level": "en el fichero",
    "auth.none_seen": "no vista",
    "auth.unknown": "desconocida",
    "auth.not_applicable": "n/a",
    "changes.findings": "Hallazgos desde la auditoría anterior",
    "changes.first": "Es la primera auditoría terminada del proyecto: no hay con qué comparar.",
    "changes.against": (a0, a1) => `Comparado con ${a0} → ${a1}.`,
    "changes.new": "nuevos",
    "changes.reintroduced": "reintroducidos",
    "changes.fixed": "corregidos",
    "changes.persisting": "persistentes",
    "changes.total": "total",
    "changes.drift": "Deriva de seguridad",
    "changes.files": (a0, a1, a2) => `${a0} fichero(s) cambiados, ${a1} críticos, ${a2} workflow(s).`,
    "changes.driftnote": "Patrones sobre el diff: un sitio que mirar, no un veredicto.",
    "changes.control": "control",
    "changes.side": "línea",
    "changes.line": "texto",
    "changes.nodrift": "No se reconoció ningún control debilitado en el diff.",
    "side.added": "añadida",
    "side.removed": "eliminada",
    "changes.dna": "Historia del proyecto (ADN)",
    "changes.recurrent": (a0) => `${a0} hallazgo(s) han aparecido en más de una auditoría.`,
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
  persona: null,           // the attacker profile and jewel chosen
  jewel: null,
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
  else if (state.section === "attacker") renderAttacker();
  else if (state.section === "mcp") renderMcp();
  else if (state.section === "supply") renderSupply();
  else if (state.section === "surface") renderSurface();
  else if (state.section === "changes") renderChanges();
  else if (state.section === "views") renderViews();
  else if (state.section === "twin") renderTwin();
  else if (state.section === "settings") renderJewels();
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
  if (audit.pr_number) pairs.push([t("detail.pr"), `#${audit.pr_number}`]);
  if (audit.base_ref) pairs.push([t("detail.base"), shortSha(audit.base_ref) || audit.base_ref]);
  if (audit.replay_of) pairs.push([t("detail.replayof"), audit.replay_of]);
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
    findings.append(assessmentCounts(audit),
                    node("p", "muted", t("findings.counted", total, audit.verified_count || 0)),
                    button(t("summary.seefindings"), "link", () => go("findings")));
  } else if (ACTIVE_STATUSES.has(audit.status)) {
    findings.append(node("p", "muted", t("findings.inprogress")));
  }

  // Keep open whatever the reader had open across the re-render polling does.
  const open = new Set([...target.querySelectorAll("details[open] > summary")]
    .map((s) => s.textContent));
  target.replaceChildren(
    auditHead(audit),
    trustBlock(audit),
    integrityBlock(audit, total),
    coverageBlock(audit),
    findings,
    exportsBlock(audit),
    replayBlock(audit),
    pathsBlock(audit),
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
  const context = el("filter-context").value;
  const persona = el("filter-persona").value;
  const assessed = el("filter-assessment").value;
  const query = state.query.trim().toLowerCase();
  const order = new Map(SEVERITIES.map((s, i) => [s, i]));
  return (state.current.findings || [])
    .filter((f) => !severity || f.severity === severity)
    .filter((f) => evidence !== "unverified" || f.verification_status !== "verified")
    .filter((f) => !epistemic
            || (epistemic === "none" ? !f.epistemic_status : f.epistemic_status === epistemic))
    .filter((f) => origin !== "zombie" || f.zombie_of)
    .filter((f) => origin !== "ai" || (f.provenance && f.provenance.ai_declared))
    .filter((f) => !context || (context === "none" ? !f.contextual_severity
                                : f.contextual_severity === context))
    .filter((f) => !persona || (f.personas || []).includes(persona))
    .filter((f) => !assessed || (f.assessment || "unverifiable") === assessed)
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
    pairs.push(...ruleFacts(finding));
    if (finding.contextual_severity) {
      pairs.push([t("findings.context"), severityNode(finding.contextual_severity)],
                 [t("findings.personas"),
                  (finding.personas || []).map((x) => t(`persona.${x}`)).join(", ")]);
    }
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
  if (full) {
    parts.append(flowNode(finding), ruleNotes(finding), hypothesisNodes(finding));
    if (finding.id !== undefined && state.current) {
      parts.append(chainButton(finding), blueTeamButton(finding));
      if (state.current.status === "done") parts.append(whatIfForm(finding));
    }
  }
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
  titleCell.append(" ", assessmentNode(finding));
  if (finding.detail && finding.detail.owasp_mcp) {
    titleCell.append(" ", node("span", "badge", finding.detail.owasp_mcp));
  }

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

for (const id of ["filter-severity", "filter-epistemic", "filter-origin", "filter-context",
                  "filter-persona", "filter-assessment"]) {
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
  parts.push(publishedBlock(run), claimsBlock(audit),
             node("p", "muted small", t("parallax.notes")));
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
     { text: t("memory.validation") }, { text: t("memory.approval") },
     { text: t("memory.fixedin"), className: "hide-narrow" },
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
        approvalNode(audit, r),
        { className: "hide-narrow", content: commitNode(r.fix_commit) },
        { className: "num", content: r.matches || 0 },
      ]);
    })));
  if (rules.some((r) => r.validated && r.approved) && audit.project_id) {
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
// attacker's view (module 5)
// ---------------------------------------------------------------------------

const PERSONAS = ["anonymous", "authenticated_user", "malicious_contributor",
                  "compromised_dependency", "manipulated_agent"];
const JEWELS = ["secrets", "user_data", "deployment", "administration", "code_execution"];
const JEWEL_NODES = { secrets: "reads_secret", user_data: "reads_user_data",
                      deployment: "publishes_release", administration: "accesses_admin",
                      code_execution: "executes_code" };

function attackerRun(audit) {
  return (audit.modules || []).filter((r) => r.module === "attacker").pop() || null;
}

function fixText(cut) {
  return t(`fix.${cut.fix.type}`, cut);
}

function nodeLabel(node) {
  if (!node) return "?";
  if (node.persona) return t(`persona.${node.persona}`);
  const value = t(`node.${node.key}`);
  return value === `node.${node.key}` ? node.label : value;
}

function attackIndex(audit) {
  const attack = audit.attack || { nodes: [], edges: [], paths: [] };
  const nodes = new Map(attack.nodes.map((n) => [n.id, n]));
  const edges = new Map(attack.edges.map((e) => [e.id, e]));
  const paths = new Map();
  for (const p of attack.paths) {
    const target = nodes.get(p.target);
    const jewel = Object.keys(JEWEL_NODES).find((k) => JEWEL_NODES[k] === (target || {}).key);
    paths.set(`${p.persona}|${jewel}`, p);
  }
  return { attack, nodes, edges, paths };
}

function pathsBlock(audit) {
  const section = block(t("summary.paths"));
  const run = attackerRun(audit);
  if (!run || run.status !== "ok") {
    section.append(node("p", "muted", t("summary.pathsphase")));
    return section;
  }
  const d = run.detail || {};
  const n = d.items || 0;
  if (!n) {
    section.append(node("p", "muted", t("summary.nopaths")));
    return section;
  }
  section.append(node("p", null, t("summary.pathcount", n, (d.by_severity || {}).critical || 0)));
  const [first] = d.min_cut || [];
  if (first) {
    const p = node("p", "topfix");
    p.append(node("strong", null, t("summary.topfix")), " ", fixText(first),
             node("span", "muted", ` — ${t("attacker.cutsome", first.cuts.length)}`));
    section.append(p);
  }
  section.append(button(t("summary.seeattacker"), "link", () => go("attacker")));
  return section;
}

function cutBlock(run) {
  const cut = (run.detail || {}).min_cut || [];
  const section = block(t("attacker.cut"), node("p", "muted", t("attacker.cutintro")));
  if (!cut.length) {
    section.append(node("p", "muted", t("attacker.nocut")));
    return section;
  }
  const list = node("ol", "cut-list");
  cut.forEach((c, i) => {
    const li = node("li", i === 0 ? "cut-first" : null);
    li.append(node("span", null, `${i ? `${t("attacker.then")}: ` : ""}${fixText(c)}`),
              node("div", "muted small", `${t("attacker.cutsome", c.cuts.length)}: ` +
                   c.cuts.map(([p, j]) => `${t(`persona.${p}`)} → ${t(`jewel.${j}`)}`).join("; ")));
    list.append(li);
  });
  section.append(list);
  return section;
}

function matrixBlock(index) {
  const section = block(t("attacker.matrix"), node("p", "muted", t("attacker.matrixintro")));
  const jewels = JEWELS.filter((j) => PERSONAS.some((p) => index.paths.has(`${p}|${j}`))
                               || (state.current.crown_jewels || []).some((x) => x.kind === j));
  section.append(table(
    [{ text: t("attacker.profile") }, ...jewels.map((j) => ({ text: t(`jewel.${j}`) }))],
    PERSONAS.map((persona) => row([
      t(`persona.${persona}`),
      ...jewels.map((jewel) => {
        const p = index.paths.get(`${persona}|${jewel}`);
        if (!p) return node("span", "muted", "—");
        const b = button("", `link matrix-cell${p.tentative ? " tentative" : ""}`, () => {
          state.persona = persona;
          state.jewel = jewel;
          renderAttacker();
          const target = document.getElementById("attack-path");
          if (target) target.scrollIntoView({ block: "start" });
        });
        b.append(severityNode(p.severity), ` ${p.cost}`);
        b.setAttribute("aria-label", `${t(`persona.${persona}`)} → ${t(`jewel.${jewel}`)}: ` +
                       `${t(`severity.${p.severity}`)}, ${t("attacker.cost", p.cost)}`);
        if (state.persona === persona && state.jewel === jewel) b.setAttribute("aria-current", "true");
        return b;
      }),
    ]))));
  return section;
}

function select(id, label, values, current, text, onChange) {
  const field = node("div", "field");
  const l = node("label", null, label);
  l.htmlFor = id;
  const s = document.createElement("select");
  s.id = id;
  for (const v of values) {
    const o = node("option", null, text(v));
    o.value = v;
    if (v === current) o.selected = true;
    s.append(o);
  }
  s.addEventListener("change", () => onChange(s.value));
  field.append(l, s);
  return field;
}

function stepNode(edge, index) {
  const ex = edge.explanation || {};
  const li = node("li", `attack-step${edge.tentative ? " tentative" : ""}` +
                        `${ex.structural ? " implied" : ""}`);
  const target = index.nodes.get(edge.target);
  const head = node("div", "attack-step-head");
  head.append(node("span", "attack-gain", nodeLabel(target)));
  if (ex.cwe) head.append(node("span", "badge", ex.cwe));
  if (ex.attack) head.append(node("span", "badge", `ATT&CK ${ex.attack}`));
  if (ex.owasp_mcp) head.append(node("span", "badge", `OWASP ${ex.owasp_mcp}`));
  head.append(node("span", "muted small", t("attacker.cost", edge.cost)));
  li.append(head);
  if (ex.structural) {
    li.append(node("p", "muted small", ex.kind === "start"
      ? t(`personadesc.${(index.nodes.get(edge.source) || {}).persona}`)
      : `${t("attacker.implied")}: ${ex.works}`));
    return li;
  }
  const sees = ex.sees || {};
  const seen = [sees.where, sees.title, sees.entry].filter(Boolean).join(" — ");
  const works = t(`works.${ex.kind}`);
  const pairs = [
    [t("attacker.sees"), node("span", "where", seen || "—")],
    [t("attacker.works"), works === `works.${ex.kind}` ? ex.works || "—" : works],
    [t("attacker.needs"), (ex.needs || []).join("; ") || "—"],
    [t("attacker.gains"), nodeLabel(target)],
  ];
  li.append(facts(pairs));
  if (edge.cost_detail) li.append(node("p", "muted small", t("attacker.costdetail", edge.cost_detail)));
  if (edge.finding_id !== null && edge.finding_id !== undefined) {
    const f = (state.current.findings || []).find((x) => x.id === edge.finding_id);
    if (f) {
      const b = button(f.title, "link");
      b.dataset.finding = String(f.id);
      b.addEventListener("click", () => openFinding(f.id, b));
      li.append(b);
    }
  }
  return li;
}

function pathBlock(index) {
  const section = block(t("attacker.path"));
  section.id = "attack-path";
  const available = PERSONAS.filter((p) => JEWELS.some((j) => index.paths.has(`${p}|${j}`)));
  if (!state.persona || !PERSONAS.includes(state.persona)) {
    state.persona = available[0] || PERSONAS[0];
  }
  const jewels = JEWELS.filter((j) => index.paths.has(`${state.persona}|${j}`));
  if (!state.jewel || !JEWELS.includes(state.jewel)) state.jewel = jewels[0] || JEWELS[0];
  const controls = node("div", "filters");
  controls.append(
    select("attack-persona", t("attacker.profile"), PERSONAS, state.persona,
           (p) => t(`persona.${p}`), (v) => { state.persona = v; renderAttacker(); }),
    select("attack-jewel", t("attacker.jewel"), JEWELS, state.jewel,
           (j) => t(`jewel.${j}`), (v) => { state.jewel = v; renderAttacker(); }));
  section.append(controls, node("p", "muted small", t(`personadesc.${state.persona}`)));
  const p = index.paths.get(`${state.persona}|${state.jewel}`);
  if (!p) {
    section.append(node("p", "muted", t("attacker.nopathhere")));
    return section;
  }
  const head = node("p", "attack-path-head");
  head.append(severityNode(p.severity), ` ${t("attacker.cost", p.cost)}`);
  if (p.tentative) head.append(node("span", "muted", ` · ${t("attacker.tentative")}`));
  head.append(" ", node("span", "badge", t("attacker.hypothetical")),
              node("span", "muted small", ` ${t("attacker.hypotheticalnote")}`));
  const chain = node("ol", "attack-chain");
  const start = index.nodes.get((index.edges.get(p.edges[0]) || {}).source);
  const first = node("li", "attack-step attack-start");
  first.append(node("span", "attack-gain", nodeLabel(start)));
  chain.append(first);
  for (const id of p.edges) {
    const edge = index.edges.get(id);
    if (edge) chain.append(stepNode(edge, index));
  }
  section.append(head, chain);
  return section;
}

function renderAttacker() {
  const target = el("attacker-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = attackerRun(audit);
  if (!run) {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("attacker.notrun")));
    return;
  }
  const parts = [];
  if (run.status === "error") parts.push(node("p", "error", t("attacker.failed")));
  const index = attackIndex(audit);
  if (!index.attack.paths.length) {
    parts.push(node("p", "muted", t("attacker.nofindings")));
  } else {
    parts.push(cutBlock(run), pathBlock(index), matrixBlock(index));
  }
  parts.push(node("p", "muted small", t("attacker.limits")));
  target.replaceChildren(...parts);
}

// ---------------------------------------------------------------------------
// crown jewels (settings)
// ---------------------------------------------------------------------------

async function jewelRequest(path, options) {
  try {
    await api(path, options);
    if (state.selectedId) await loadDetail(state.selectedId);
  } catch (e) {
    el("settings-error").textContent = e.message;
    el("settings-error").hidden = false;
  }
  renderJewels();
}

function renderJewels() {
  const target = el("jewels-body");
  if (!target) return;
  const audit = state.current;
  if (!audit || !audit.project_id) {
    target.replaceChildren(node("p", "muted", t("jewels.none")));
    return;
  }
  const base = `/api/projects/${encodeURIComponent(audit.project_id)}/crown-jewels`;
  const jewels = audit.crown_jewels || [];
  const parts = [node("p", "muted small", repoLabel(audit.repo_url))];
  if (!jewels.length) {
    parts.push(node("p", "muted", t("jewels.empty")));
  } else {
    parts.push(table(
      [{ text: t("jewels.kind") }, { text: t("jewels.target") }, { text: "" }, { text: "" }],
      jewels.map((j) => row([
        t(`jewel.${j.kind}`), j.target,
        node("span", "muted small", t(`jewels.by.${j.declared_by}`)),
        (() => {
          const b = button(t("jewels.remove"), "link", () =>
            jewelRequest(`${base}/${j.id}`, { method: "DELETE" }));
          b.setAttribute("aria-label", t("jewels.removelabel", t(`jewel.${j.kind}`)));
          return b;
        })(),
      ]))));
  }
  const form = node("form", "filters jewel-form");
  form.append(
    select("jewel-kind", t("jewels.kind"), JEWELS, JEWELS[0], (j) => t(`jewel.${j}`), () => {}));
  const field = node("div", "field");
  const label = node("label", null, t("jewels.target"));
  label.htmlFor = "jewel-target";
  const input = document.createElement("input");
  input.id = "jewel-target";
  input.type = "text";
  input.maxLength = 512;
  input.required = true;
  field.append(label, input);
  const submit = node("button", null, t("jewels.add"));
  submit.type = "submit";
  form.append(field, submit);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    jewelRequest(base, { method: "POST", headers: { "Content-Type": "application/json" },
                         body: JSON.stringify({ kind: form.querySelector("select").value,
                                                target: input.value }) });
  });
  parts.push(form);
  target.replaceChildren(...parts);
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

// What people paste is rarely the bare clone URL: "owner/repo", a URL without
// the scheme, "http://", "www.", or a link to a branch, file or PR. The server
// accepts only https://github.com/<owner>/<repo>, so the form turns any of
// those into that shape and leaves anything else for the server to reject.
function normalizeRepoUrl(raw) {
  let v = raw.trim().replace(/[?#].*$/, "");
  if (/^[\w.-]+\/[\w.-]+\/?$/.test(v)) v = `github.com/${v}`;
  v = v.replace(/^(?:https?:\/\/)?(?:www\.)?github\.com\//i, "https://github.com/");
  const m = v.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?(?:\/.*)?$/);
  return m ? `https://github.com/${m[1]}/${m[2]}` : v;
}

// The API answers in English for every client; the form shows its refusals
// in the language of the interface. Anything unrecognised is shown as sent.
function auditFormError(message) {
  if (message.startsWith("repo_url must be")) return t("audit.err.url");
  if (message === "invalid repository name") return t("audit.err.name");
  const owners = message.match(/^this instance only audits repositories of: (.*)$/);
  if (owners) return t("audit.err.owner", owners[1]);
  if (message === "invalid branch name") return t("audit.err.ref");
  if (message.startsWith("commit must be a full")) return t("audit.err.sha");
  return message;
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
      body: JSON.stringify({
        repo_url: normalizeRepoUrl(input.value), language: lang,
        branch: el("audit-branch").value.trim() || null,
        base_ref: el("audit-base").value.trim() || null,
        commit: el("audit-commit").value.trim() || null,
      }),
    });
    input.value = "";
    for (const id of ["audit-branch", "audit-base", "audit-commit"]) el(id).value = "";
    await refresh();
    go("summary", audit.id);
  } catch (e) {
    error.textContent = auditFormError(e.message);
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

// ---------------------------------------------------------------------------
// practice 3: one assessment per finding, audit confidence, exports, the MCP
// auditor, the supply chain, the attack surface and what changed. Everything
// here reads what the server computed on its own checkout; nothing is
// inferred in the browser.
// ---------------------------------------------------------------------------

const ASSESSMENTS = ["confirmed", "potential", "unverifiable", "discarded"];
const MCP_CATEGORIES = ["MCP01", "MCP02", "MCP03", "MCP04", "MCP05", "MCP06", "MCP07",
                        "MCP08", "MCP09", "MCP10"];

function assessmentNode(finding) {
  const a = finding.assessment || "unverifiable";
  return node("span", `badge badge-a-${a}`, t(`assessment.${a}`));
}

function runOf(audit, name) {
  return (audit.modules || []).filter((r) => r.module === name).pop() || null;
}

// Fills target with why a module has nothing to show, and says so.
function moduleMissing(target, audit, run, notRunKey) {
  if (run) return false;
  target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
    ? t("findings.inprogress") : t(notRunKey)));
  return true;
}

function moduleError(run) {
  return run.status === "error"
    ? node("p", "error", t("p3.modulefailed", run.error || "")) : null;
}

// Per-audit answers fetched once; an audit still running is asked again.
const fetched = new Map();

async function fetchOnce(key, path, audit) {
  const k = `${key}:${audit.id}:${audit.status}`;
  if (fetched.has(k)) return fetched.get(k);
  const value = await api(path);
  fetched.set(k, value);
  return value;
}

function cachedOnly(key, audit) {
  return fetched.get(`${key}:${audit.id}:${audit.status}`);
}

function lazyBlock(title, key, path, audit, render) {
  const section = block(title);
  const cached = cachedOnly(key, audit);
  if (cached !== undefined) {
    section.append(render(cached));
    return section;
  }
  const holder = node("p", "muted", t("summary.loading"));
  section.append(holder);
  fetchOnce(key, path, audit).then((value) => {
    holder.replaceWith(render(value));
  }).catch((e) => {
    holder.replaceWith(node("p", "error", e.message));
  });
  return section;
}

function list(items) {
  const ul = document.createElement("ul");
  for (const item of items) {
    const li = document.createElement("li");
    if (item instanceof Node) li.append(item);
    else li.textContent = String(item);
    ul.append(li);
  }
  return ul;
}

function scoreText(d) {
  if (!d || d.score === null || d.score === undefined) return t("p3.notmeasured");
  return `${Math.round(d.score * 100)}% · ${t(`band.${d.band}`)}`;
}

function trustBlock(audit) {
  if (audit.status !== "done") {
    return block(t("p3.trust"), node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("findings.failed")));
  }
  return lazyBlock(t("p3.trust"), "trust",
                   `/api/audits/${encodeURIComponent(audit.id)}/trust`, audit, (tr) => {
    const wrap = document.createDocumentFragment();
    wrap.append(node("p", "muted", t("p3.trustintro")));
    wrap.append(table(
      [{ text: t("p3.dimension") }, { text: t("p3.score") }, { text: t("p3.reasons") }],
      ["coverage", "evidence", "adversarial"].map((k) => row([
        t(`p3.dim.${k}`), scoreText(tr[k]), (tr[k].reasons || []).join(" · ") || "—"]))));
    if (tr.unreliable_clean) wrap.append(node("p", "coverage-warning", t("summary.unreliable")));
    const details = node("details", "block");
    details.append(node("summary", null, t("p3.limits")), list(tr.limits || []));
    wrap.append(details);
    return wrap;
  });
}

function download(label, path, newTab) {
  const a = node("a", "button-link ghost", label);
  a.href = path;
  if (newTab) {
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  } else {
    a.setAttribute("download", "");
  }
  return a;
}

function exportsBlock(audit) {
  const section = block(t("p3.exports"));
  if (audit.status !== "done") {
    section.append(node("p", "muted", t("p3.exportswait")));
    return section;
  }
  const base = `/api/audits/${encodeURIComponent(audit.id)}`;
  const row1 = node("div", "export-links");
  row1.append(download(t("p3.export.html"), `${base}/report.html`, true),
              download("PDF", `${base}/report.pdf`),
              download("JSON", `${base}/report.json`),
              download("SARIF", `${base}/report.sarif`),
              download("CycloneDX SBOM", `${base}/sbom.cdx.json`),
              download(t("p3.export.replay"), `${base}/replay.json`));
  section.append(row1, node("p", "muted", t("p3.exportsnote")));
  return section;
}

function assessmentCounts(audit) {
  const counts = Object.fromEntries(ASSESSMENTS.map((a) => [a, 0]));
  for (const f of audit.findings || []) counts[f.assessment || "unverifiable"] += 1;
  const wrap = node("p", "assessment-counts");
  for (const a of ASSESSMENTS) {
    wrap.append(node("span", `badge badge-a-${a}`, `${t(`assessment.${a}`)} ${counts[a]}`), " ");
  }
  return wrap;
}

// The detail a deterministic rule gives about its own finding.
function ruleFacts(finding) {
  const d = finding.detail || {};
  const pairs = [[t("p3.assessment"), assessmentNode(finding)],
                 [t("p3.source"), t(`source.${finding.source || "model"}`)]];
  if (finding.rule_id) pairs.push([t("p3.rule"), node("span", "where", finding.rule_id)]);
  if (d.owasp_mcp) pairs.push(["OWASP MCP", `${d.owasp_mcp} · ${d.owasp_mcp_name || ""}`]);
  if (d.cwe) pairs.push(["CWE", d.cwe]);
  if (d.confidence) pairs.push([t("p3.confidence"), t(`confidence.${d.confidence}`)]);
  return pairs;
}

function ruleNotes(finding) {
  const d = finding.detail || {};
  const parts = document.createDocumentFragment();
  const add = (key, value) => {
    if (!value || (Array.isArray(value) && !value.length)) return;
    parts.append(node("h3", null, t(key)));
    parts.append(Array.isArray(value) ? list(value) : node("p", "prose", String(value)));
  };
  add("p3.prerequisites", d.prerequisites);
  add("p3.impact", d.impact);
  add("p3.mitigation", d.mitigation);
  add("p3.limitsone", d.limits);
  if (d.references) add("p3.references", d.references);
  return parts;
}

function chainNode(chain) {
  const wrap = node("div", "chain");
  wrap.append(facts([
    [t("p3.assessment"), node("span", `badge badge-a-${chain.conclusion.assessment}`,
                              chain.conclusion.label)],
    [t("p3.why"), chain.conclusion.why],
    [t("detail.commit"), shortSha(chain.anchor.commit_sha) || "—"],
    [t("findings.location"), node("span", "where", [chain.anchor.file,
      chain.anchor.line].filter(Boolean).join(":") || "—")],
    [t("p3.snippethash"), node("span", "where", chain.anchor.snippet_sha256
      ? chain.anchor.snippet_sha256.slice(0, 16) : "—")],
    [t("p3.confidence"), t(`confidence.${chain.confidence}`)],
  ]));
  wrap.append(node("h3", null, t("p3.checks")),
              list(chain.checks.map((c) => `${c.check}: ${c.result}${c.note ? ` — ${c.note}` : ""}`)));
  wrap.append(node("h3", null, t("p3.counterfactuals")),
              list(chain.counterfactuals.map((c) => `[${t(`cond.${c.status}`)}] ${c.condition}`)));
  if (chain.discarded_hypotheses.length) {
    wrap.append(node("h3", null, t("p3.discarded")),
                list(chain.discarded_hypotheses.map((h) => `${h.hypothesis} (${h.by})`)));
  }
  wrap.append(node("h3", null, t("p3.unknowns")), list(chain.unknowns));
  wrap.append(node("p", "muted", `sha256 ${chain.sha256} — ${chain.integrity_note}`));
  return wrap;
}

function chainButton(finding) {
  const holder = node("div");
  const b = button(t("p3.showchain"), "ghost", async () => {
    b.disabled = true;
    try {
      const chain = await api(`/api/audits/${encodeURIComponent(state.current.id)}`
        + `/findings/${finding.id}/evidence-chain`);
      holder.replaceChildren(node("h3", null, t("p3.chain")), chainNode(chain));
    } catch (e) {
      holder.replaceChildren(node("p", "error", e.message));
      b.disabled = false;
    }
  });
  holder.append(b);
  return holder;
}

function findingLink(f) {
  const b = button(f.title, "link", () => openFinding(f.id, b));
  b.dataset.finding = String(f.id);
  return b;
}

function findingsTable(findings) {
  return table(
    [{ text: t("findings.severity") }, { text: t("p3.assessment") }, { text: t("p3.finding") },
     { text: t("findings.location") }],
    findings.map((f) => row([severityNode(f.severity), assessmentNode(f), findingLink(f),
                             { className: "where", content: whereText(f) }])));
}

// --- MCP --------------------------------------------------------------------

function renderMcp() {
  const target = el("mcp-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = runOf(audit, "mcp");
  if (moduleMissing(target, audit, run, "p3.notrun")) return;
  const d = run.detail || {};
  const parts = [];
  const err = moduleError(run);
  if (err) parts.push(err);
  if (d.taxonomy) {
    parts.push(node("p", "muted", t("mcp.taxonomy", d.taxonomy.name, d.taxonomy.checked,
                                    d.taxonomy.url)));
  }
  parts.push(taxonomyCheck());
  const inv = d.inventory || { servers: [], clients: [], configs: [], tools: [] };
  if (!d.detected) {
    parts.push(block(t("mcp.inventory"), node("p", null, t("mcp.none"))));
  } else {
    const invBlock = block(t("mcp.inventory"),
      node("p", null, t("mcp.counts", inv.servers.length, inv.clients.length,
                        inv.configs.length, inv.tools.length)));
    if (inv.configs.length) {
      invBlock.append(table([{ text: t("mcp.config") }, { text: t("mcp.servers") }],
        inv.configs.map((c) => row([{ className: "where", content: c.file },
          (c.servers || []).map((s) => `${s.name} (${s.type}${s.command ? `: ${s.command}`
            : s.url ? `: ${s.url}` : ""})`).join(" · ") || "—"]))));
    }
    if (inv.tools.length) {
      invBlock.append(table([{ text: t("mcp.tool") }, { text: t("mcp.kind") },
                             { text: t("findings.location") }],
        inv.tools.map((x) => row([x.name, x.kind,
                                  { className: "where", content: `${x.file}:${x.line}` }]))));
    }
    parts.push(invBlock);
  }
  const byCat = d.by_category || {};
  const findings = (audit.findings || []).filter((f) => f.category === "mcp");
  parts.push(block(t("mcp.categories"), table(
    [{ text: "OWASP" }, { text: t("mcp.count"), className: "num" }],
    MCP_CATEGORIES.map((c) => row([c, { className: "num", content: String(byCat[c] || 0) }])))));
  parts.push(block(t("nav.findings"), findings.length ? findingsTable(findings)
    : node("p", "muted", t("mcp.nofindings"))));
  parts.push(lazyBlock(t("mcp.catalog"), `mcp-catalog-${lang}`,
                       `/api/mcp/catalog?language=${lang}`, audit, (cat) => {
    const wrap = document.createDocumentFragment();
    for (const c of cat.categories) {
      const det = node("details", "block");
      det.append(node("summary", null, `${c.id} · ${c.name} · ${c.cwe}`), facts([
        [t("mcp.inspects"), c.inspects], [t("mcp.static"), c.static],
        [t("mcp.confirm"), c.confirm], [t("mcp.fp"), c.false_positives],
        [t("p3.mitigation"), c.mitigation], [t("p3.limitsone"), c.limits]]));
      wrap.append(det);
    }
    return wrap;
  }));
  target.replaceChildren(...parts);
}

// --- supply chain -------------------------------------------------------------

function renderSupply() {
  const target = el("supply-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const depRun = runOf(audit, "dependencies");
  const secRun = runOf(audit, "secrets");
  if (moduleMissing(target, audit, depRun || secRun, "p3.notrun")) return;
  const parts = [];
  if (depRun) {
    const d = depRun.detail || {};
    const err = moduleError(depRun);
    if (err) parts.push(err);
    const eco = Object.entries(d.by_ecosystem || {}).map(([k, v]) => `${k} ${v}`).join(" · ");
    const b = block(t("supply.deps"),
      node("p", null, t("supply.components", d.components || 0, d.direct || 0, eco || "—")),
      node("p", "muted", t("supply.manifests", (d.manifests || []).join(", ") || "—")));
    const osv = d.osv || {};
    b.append(node("p", osv.error ? "error" : "muted",
                  osv.queried ? t("supply.osvdone", osv.asked || 0, osv.vulnerable || 0)
                    : osv.error ? t("supply.osverror", osv.error) : t("supply.osvoff")));
    const mt = d.maintenance || {};
    b.append(node("p", "muted", mt.queried
      ? t("supply.maintdone", mt.asked || 0, mt.stale || 0, mt.deprecated || 0,
          mt.threshold_days || 730)
      : t("supply.maintoff")));
    if (d.transitive_note === "direct_only") b.append(node("p", "muted", t("supply.directonly")));
    const details = node("details", "block");
    details.append(node("summary", null, t("supply.list")));
    const holder = node("div");
    details.append(holder);
    details.addEventListener("toggle", async () => {
      if (!details.open || holder.childElementCount) return;
      holder.append(node("p", "muted", t("summary.loading")));
      try {
        const comps = await fetchOnce("components",
          `/api/audits/${encodeURIComponent(audit.id)}/components`, audit);
        holder.replaceChildren(table(
          [{ text: t("supply.name") }, { text: t("supply.version") }, { text: t("supply.direct") },
           { text: t("supply.scope") }, { text: t("supply.vulns") },
           { text: t("supply.maint") }],
          comps.slice(0, 500).map((c) => row([
            `${c.ecosystem} · ${c.name}`, c.version || "—",
            c.direct ? t("supply.yes") : t("supply.no"), c.scope || "—",
            c.vulns === null ? "—" : (c.vulns || []).map((v) => v.id).join(", ") || "0",
            !c.maintenance ? "—" : c.maintenance.deprecated ? t("supply.deprecated")
              : c.maintenance.days_since_release === null ? "?"
              : t("supply.days", c.maintenance.days_since_release)]))));
      } catch (e) {
        holder.replaceChildren(node("p", "error", e.message));
      }
    });
    b.append(details);
    parts.push(b);
    const ghosts = d.ghosts || [];
    parts.push(block(t("supply.ghosts"), node("p", "muted", t("supply.ghostsnote")),
      ghosts.length ? table([{ text: t("supply.name") }, { text: t("supply.manifest") }],
        ghosts.map((g) => row([`${g.ecosystem} · ${g.name}`,
          { className: "where", content: g.line ? `${g.manifest}:${g.line}` : g.manifest }])))
        : node("p", null, t("supply.noghosts"))));
    parts.push(deadcodeBlock(audit));
    const depFindings = (audit.findings || []).filter((f) => f.category === "dependencies"
                                                          && f.source === "rule");
    if (depFindings.length) parts.push(block(t("supply.signals"), findingsTable(depFindings)));
  }
  if (secRun) {
    const d = secRun.detail || {};
    const err = moduleError(secRun);
    if (err) parts.push(err);
    const tl = d.timeline || { secrets: [] };
    const b = block(t("supply.secrets"),
      node("p", null, t("supply.secretsline", d.found || 0, tl.commits_read || 0,
                        d.history_only || 0)),
      node("p", "coverage-warning", t("supply.rotate")));
    if ((tl.secrets || []).length) {
      b.append(table(
        [{ text: t("supply.kind") }, { text: t("supply.mask") }, { text: t("supply.first") },
         { text: t("supply.removed") }, { text: t("supply.now") }],
        tl.secrets.map((s) => row([
          s.kind, { className: "where", content: s.mask },
          s.first_commit ? `${shortSha(s.first_commit)}${s.before_history ? " *" : ""}` : "—",
          (s.removed_in || []).map((r) => shortSha(r.commit)).join(", ") || "—",
          s.present_at_head ? t("supply.yes") : t("supply.no")]))));
      if (tl.secrets.some((s) => s.before_history)) {
        b.append(node("p", "muted", t("supply.beforehistory")));
      }
    }
    if (tl.truncated) b.append(node("p", "muted", t("supply.truncated")));
    parts.push(b);
  }
  target.replaceChildren(...parts);
}

// --- attack surface -----------------------------------------------------------

function renderSurface() {
  const target = el("surface-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  const run = runOf(audit, "surface");
  if (moduleMissing(target, audit, run, "p3.notrun")) return;
  const d = run.detail || {};
  const parts = [];
  const err = moduleError(run);
  if (err) parts.push(err);
  const kinds = Object.entries(d.by_kind || {}).map(([k, v]) => `${t(`kind.${k}`)} ${v}`);
  parts.push(node("p", null, kinds.join(" · ") || t("surface.none")));
  if ((d.not_inventoried || []).length) {
    parts.push(node("p", "muted", t("surface.notinv", d.not_inventoried.join(", "))));
  }
  if ((d.boundaries || []).length) {
    parts.push(block(t("surface.boundaries"), node("p", "muted", t("surface.boundariesnote")),
      table([{ text: t("surface.via") }, { text: t("surface.to") },
             { text: t("surface.entries"), className: "num" },
             { text: t("surface.noauth"), className: "num" },
             { text: t("surface.novalidation"), className: "num" }],
        d.boundaries.map((x) => row([t(`kind.${x.via}`), t(`asset.${x.to}`),
          { className: "num", content: String(x.entries) },
          { className: "num", content: String(x.auth_none_seen) },
          { className: "num", content: x.validation_none_seen === undefined ? "—"
            : String(x.validation_none_seen) }])))));
  }
  if ((d.items || []).length) {
    parts.push(block(t("surface.items"), table(
      [{ text: t("mcp.kind") }, { text: t("surface.route") }, { text: t("findings.location") },
       { text: t("surface.auth") }, { text: t("surface.validation") },
       { text: t("surface.touches") }],
      d.items.map((i) => row([t(`kind.${i.kind}`),
        [i.method, i.path || i.name].filter(Boolean).join(" ") || "—",
        { className: "where", content: `${i.file}:${i.line}` },
        t(`auth.${i.auth}`),
        i.validation ? t(`validation.${i.validation}`) : "—",
        (i.touches || []).map((x) => t(`asset.${x}`)).join(", ") || "—"])))));
  }
  if (d.services) parts.push(servicesBlock(d.services));
  parts.push(taintBlock(audit));
  target.replaceChildren(...parts);
}

// --- what changed -------------------------------------------------------------

function renderChanges() {
  const target = el("changes-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  if (audit.status !== "done") {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("findings.failed")));
    return;
  }
  const parts = [lazyBlock(t("changes.findings"), "diff",
    `/api/audits/${encodeURIComponent(audit.id)}/diff`, audit, (d) => {
      const wrap = document.createDocumentFragment();
      if (d.pr_number) wrap.append(node("p", null, t("changes.pr", d.pr_number)));
      if (d.replay_of) wrap.append(node("p", "muted", t("changes.replay")));
      if (!d.previous_audit) {
        wrap.append(node("p", "muted", d.base_ref ? t("changes.basenoaudit",
          shortSha(d.base_ref) || d.base_ref) : t("changes.first")));
      } else {
        wrap.append(node("p", null, t("changes.against", shortSha(d.previous_commit) || "—",
                                      shortSha(d.commit) || "—")));
        for (const k of ["new", "reintroduced", "fixed", "persisting"]) {
          const items = d[k] || [];
          const det = node("details", "block");
          det.append(node("summary", null, `${t(`changes.${k}`)} · ${items.length}`));
          if (items.length) {
            det.append(table([{ text: t("findings.severity") }, { text: t("p3.finding") },
                              { text: t("findings.location") }],
              items.map((f) => row([severityNode(f.severity), f.title,
                { className: "where", content: f.line ? `${f.file}:${f.line}` : f.file || "" }]))));
          }
          if (k !== "persisting") det.open = items.length > 0 && items.length <= 20;
          wrap.append(det);
        }
      }
      const c = d.changes;
      const drift = block(t("changes.drift"));
      if (!c) {
        drift.append(node("p", "muted", t("p3.notrun")));
      } else if (!c.compared) {
        drift.append(node("p", "muted", c.reason || t("changes.first")));
      } else {
        drift.append(node("p", null, t("changes.files", c.files_changed,
                                       (c.critical_changed || []).length,
                                       (c.workflows_changed || []).length)));
        if ((c.critical_changed || []).length) {
          drift.append(table([{ text: t("coverage.file") }, { text: t("coverage.tier") }],
            c.critical_changed.map((f) => row([{ className: "where", content: f.file },
                                                t(RISK_TIERS[f.risk_tier] || "tier.5")]))));
        }
        drift.append(node("p", "muted", t("changes.driftnote")));
        drift.append((c.drift || []).length ? table(
          [{ text: t("changes.control") }, { text: t("findings.location") },
           { text: t("changes.side") }, { text: t("changes.line") }],
          c.drift.map((x) => row([x.label,
            { className: "where", content: x.line ? `${x.file}:${x.line}` : x.file },
            t(`side.${x.side}`), { className: "where", content: x.text }])))
          : node("p", null, t("changes.nodrift")));
      }
      wrap.append(drift);
      return wrap;
    })];
  if (audit.project_id) {
    parts.push(lazyBlock(t("changes.dna"), "history",
      `/api/projects/${audit.project_id}/history`, audit, (h) => {
        const wrap = document.createDocumentFragment();
        wrap.append(node("p", "muted", t("changes.recurrent", h.recurrent_fingerprints || 0)));
        wrap.append(table(
          [{ text: t("detail.commit") }, { text: t("changes.new"), className: "num" },
           { text: t("changes.fixed"), className: "num" },
           { text: t("changes.reintroduced"), className: "num" },
           { text: t("changes.total"), className: "num" }],
          (h.audits || []).map((a) => row([shortSha(a.commit_sha) || "—",
            { className: "num", content: String(a.new) },
            { className: "num", content: String(a.fixed) },
            { className: "num", content: String(a.reintroduced) },
            { className: "num", content: String(a.total) }]))));
        return wrap;
      }));
  }
  target.replaceChildren(...parts);
}

// ---------------------------------------------------------------------------
// Practice 3, second part: views, twin, what if, blue team, approval, replay
// ---------------------------------------------------------------------------

const auditPath = (audit, rest = "") => `/api/audits/${encodeURIComponent(audit.id)}${rest}`;

// --- C31: three views over the same evidence ----------------------------------

const VIEWS = ["exec", "dev", "analyst"];

function renderViews() {
  const target = el("views-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  if (!VIEWS.includes(state.view)) state.view = stored("secaudit-view") || "dev";
  if (!VIEWS.includes(state.view)) state.view = "dev";
  const tabs = node("div", "view-tabs");
  tabs.setAttribute("role", "tablist");
  for (const v of VIEWS) {
    const b = button(t(`views.${v}`), v === state.view ? "" : "ghost", () => {
      state.view = v;
      store("secaudit-view", v);
      renderViews();
    });
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", String(v === state.view));
    tabs.append(b);
  }
  const findings = (audit.findings || []).slice();
  const live = findings.filter((f) => f.assessment !== "discarded");
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  live.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  const parts = [node("p", "muted", t("views.intro")), tabs];
  if (audit.status !== "done") {
    parts.push(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("findings.failed")));
    target.replaceChildren(...parts);
    return;
  }
  if (state.view === "exec") {
    const confirmed = live.filter((f) => f.assessment === "confirmed");
    const severe = live.filter((f) => ["critical", "high"].includes(f.severity));
    const run = attackerRun(audit);
    const paths = run && run.status === "ok" ? (run.detail || {}) : {};
    parts.push(block(t("views.stake"),
      node("p", null, t("views.execline", live.length, confirmed.length, severe.length)),
      node("p", null, t("views.execpaths", paths.items || 0,
                        (paths.by_severity || {}).critical || 0)),
      assessmentCounts(audit)));
    const [first] = paths.min_cut || [];
    if (first) parts.push(block(t("summary.topfix"), node("p", null, fixText(first))));
    parts.push(trustBlock(audit));
    parts.push(block(t("views.top"), live.length ? list(live.slice(0, 5).map((f) =>
      `${t(`severity.${f.severity}`)} · ${f.title}`)) : node("p", "muted", t("findings.none"))));
  } else if (state.view === "dev") {
    parts.push(node("p", "muted", t("views.devnote")));
    for (const f of live.slice(0, 100)) {
      const d = f.detail || {};
      const card = node("section", "block view-card");
      const head = node("p", "view-head");
      head.append(severityNode(f.severity), " ", assessmentNode(f), " ", findingLink(f));
      card.append(head, node("p", "where", whereText(f) || "—"));
      if (f.code_snippet && f.verification_status === "verified") {
        card.append(node("pre", "snippet", f.code_snippet));
      }
      const fix = d.mitigation || (f.hypothesis && f.hypothesis.fix) || f.description;
      if (fix) card.append(node("p", "prose", fix));
      parts.push(card);
    }
    if (!live.length) parts.push(node("p", "muted", t("findings.none")));
  } else {
    parts.push(node("p", "muted", t("views.analystnote")));
    parts.push(table(
      [{ text: t("findings.severity") }, { text: t("p3.assessment") }, { text: t("p3.finding") },
       { text: t("p3.source") }, { text: "CWE" }, { text: t("findings.epistemic") },
       { text: t("p3.confidence") }],
      findings.map((f) => row([severityNode(f.severity), assessmentNode(f), findingLink(f),
        t(`source.${f.source || "model"}`), (f.detail || {}).cwe || "—",
        f.epistemic_status || "—",
        (f.detail || {}).confidence ? t(`confidence.${f.detail.confidence}`) : "—"]))));
  }
  target.replaceChildren(...parts);
}

// --- C34: the digital twin ------------------------------------------------------

const TWIN_TYPES = ["area", "entry", "asset", "service", "dependency", "finding", "persona",
                    "jewel"];

function renderTwin() {
  const target = el("twin-body");
  if (needsAudit(target)) return;
  const audit = state.current;
  if (audit.status !== "done") {
    target.replaceChildren(node("p", "muted", ACTIVE_STATUSES.has(audit.status)
      ? t("findings.inprogress") : t("findings.failed")));
    return;
  }
  const cached = cachedOnly("twin", audit);
  if (cached === undefined) {
    target.replaceChildren(node("p", "muted", t("summary.loading")));
    fetchOnce("twin", auditPath(audit, "/twin"), audit).then(() => renderTwin())
      .catch((e) => target.replaceChildren(node("p", "error", e.message)));
    return;
  }
  const tw = cached;
  const byId = new Map(tw.nodes.map((n) => [n.id, n]));
  if (!state.twinType || !TWIN_TYPES.includes(state.twinType)) {
    state.twinType = TWIN_TYPES.find((x) => tw.counts[x]) || "area";
  }
  const parts = [node("p", "muted", t("twin.note")),
                 node("p", null, t("twin.counts", tw.nodes.length, tw.edges.length,
                                   tw.uncertain_nodes))];
  const tabs = node("div", "view-tabs");
  for (const ty of TWIN_TYPES) {
    if (!tw.counts[ty]) continue;
    tabs.append(button(`${t(`twin.type.${ty}`)} · ${tw.counts[ty]}`,
                       ty === state.twinType ? "" : "ghost",
                       () => { state.twinType = ty; state.twinNode = null; renderTwin(); }));
  }
  parts.push(tabs);
  const nodes = tw.nodes.filter((n) => n.type === state.twinType);
  const layout = node("div", "twin");
  const listing = node("ul", "twin-list");
  for (const n of nodes.slice(0, 400)) {
    const li = document.createElement("li");
    const b = button(n.label || n.id, n.id === state.twinNode ? "" : "link",
                     () => { state.twinNode = n.id; renderTwin(); });
    li.append(b);
    if (n.uncertainty.length) li.append(node("span", "badge badge-a-unverifiable", "?"));
    listing.append(li);
  }
  layout.append(listing);
  const detail = node("div", "twin-detail");
  const current = byId.get(state.twinNode);
  if (!current) {
    detail.append(node("p", "muted", t("twin.pick")));
  } else {
    detail.append(node("h3", null, `${t(`twin.type.${current.type}`)}: ${current.label}`));
    const pairs = [];
    for (const [k, v] of Object.entries(current)) {
      if (["id", "type", "label", "uncertainty"].includes(k) || v === null
          || v === undefined || (Array.isArray(v) && !v.length)) continue;
      pairs.push([k, Array.isArray(v) ? v.join(", ") : String(v)]);
    }
    if (pairs.length) detail.append(facts(pairs));
    detail.append(node("h3", null, t("twin.unknown")),
                  current.uncertainty.length ? list(current.uncertainty)
                    : node("p", "muted", t("twin.nounknown")));
    const links = tw.edges.filter((e) => e.from === current.id || e.to === current.id);
    detail.append(node("h3", null, t("twin.links")));
    detail.append(links.length ? list(links.slice(0, 200).map((e) => {
      const other = byId.get(e.from === current.id ? e.to : e.from) || {};
      const li = node("span");
      li.append(node("span", "muted", `${e.from === current.id ? "→" : "←"} ${t(`twin.rel.${e.rel}`)} `),
                button(other.label || other.id || "?", "link", () => {
                  state.twinType = other.type;
                  state.twinNode = other.id;
                  renderTwin();
                }));
      if (e.hypothetical) li.append(node("span", "muted small", ` (${t("attacker.hypothetical")})`));
      return li;
    })) : node("p", "muted", "—"));
  }
  layout.append(detail);
  parts.push(layout);
  parts.push(twinSimulator(audit, tw));
  target.replaceChildren(...parts);
}

// What a change to the twin does to the attack paths.
function twinSimulator(audit, tw) {
  const box = node("details", "block twin-sim");
  box.append(node("summary", null, t("twin.sim.title")));
  box.append(node("p", "muted", t("twin.sim.intro")));
  const onPath = new Set(tw.edges.filter((e) => e.rel === "reaches" && e.to.startsWith("finding:"))
    .map((e) => e.to));
  const findings = tw.nodes.filter((n) => n.type === "finding" && onPath.has(n.id));
  if (!findings.length) {
    box.append(node("p", "muted", t("twin.sim.none")));
    return box;
  }
  const choice = new Map();
  const table = node("table", "data");
  const head = document.createElement("tr");
  for (const h of ["twin.sim.finding", "twin.sim.keep", "twin.sim.fix", "twin.sim.confirm"]) {
    head.append(node("th", null, t(h)));
  }
  table.append(head);
  for (const f of findings) {
    const id = Number(f.id.split(":")[1]);
    const tr = document.createElement("tr");
    tr.append(node("td", null, `${f.label} (${f.assessment ? t(`assessment.${f.assessment}`) : "—"})`));
    for (const action of ["keep", "fix", "confirm"]) {
      const td = document.createElement("td");
      const r = document.createElement("input");
      r.type = "radio";
      r.name = `twin-sim-${id}`;
      r.checked = action === "keep";
      r.setAttribute("aria-label", `${t(`twin.sim.${action}`)}: ${f.label}`);
      r.addEventListener("change", () => choice.set(id, action));
      td.append(r);
      tr.append(td);
    }
    table.append(tr);
  }
  const out = node("div");
  const go_ = button(t("twin.sim.run"), "", async () => {
    const fix = [...choice].filter(([, a]) => a === "fix").map(([i]) => i);
    const confirm = [...choice].filter(([, a]) => a === "confirm").map(([i]) => i);
    if (!fix.length && !confirm.length) {
      out.replaceChildren(node("p", "muted", t("twin.sim.nothing")));
      return;
    }
    go_.disabled = true;
    try {
      const r = await api(auditPath(audit, "/twin/simulate"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fix_findings: fix, confirm_findings: confirm }),
      });
      out.replaceChildren(twinSimResult(r));
    } catch (e) {
      out.replaceChildren(node("p", "error", e.message));
    } finally {
      go_.disabled = false;
    }
  });
  box.append(table, go_, out);
  return box;
}

function twinSimResult(r) {
  const pathText = (p) => `${t(`persona.${p.persona}`)} → ${t(`jewel.${p.jewel}`)}`
    + ` (${t("twin.sim.cost", p.cost)}${p.tentative ? `, ${t("attacker.hypothetical")}` : ""})`;
  const wrap = node("div");
  wrap.append(node("p", null, t("twin.sim.summary", r.before, r.after)));
  const section = (key, items, text) => {
    wrap.append(node("h4", null, `${t(key)} · ${items.length}`));
    wrap.append(items.length ? list(items.map(text)) : node("p", "muted", "—"));
  };
  section("twin.sim.closed", r.closed, pathText);
  section("twin.sim.changed", r.changed, (c) => `${pathText(c.before)} ⇒ ${pathText(c.after)}`);
  section("twin.sim.opened", r.opened, pathText);
  section("twin.sim.remaining", r.remaining, pathText);
  wrap.append(node("p", "muted small", t("twin.sim.note")));
  return wrap;
}

// --- C30: blue team, in the finding --------------------------------------------

function blueTeamButton(finding) {
  const holder = node("div");
  const b = button(t("blue.show"), "ghost", async () => {
    b.disabled = true;
    try {
      const bt = await api(auditPath(state.current, `/findings/${finding.id}/blue-team`));
      if (!bt || !bt.sigma) {
        holder.replaceChildren(node("p", "muted", t("blue.none")));
        return;
      }
      holder.replaceChildren(
        node("h3", null, t("blue.title")),
        node("p", "coverage-warning", bt.label),
        facts([[t("blue.log"), bt.log], [t("blue.detect"), bt.detect]]),
        node("pre", "snippet", bt.sigma));
    } catch (e) {
      holder.replaceChildren(node("p", "error", e.message));
      b.disabled = false;
    }
  });
  holder.append(b);
  return holder;
}

// --- C29: what if ----------------------------------------------------------------

function whatIfResult(w) {
  const wrap = node("div", "chain");
  if (w.status === "running") {
    wrap.append(node("p", "muted", t("whatif.sandboxrunning")));
    return wrap;
  }
  if (w.status !== "ok") {
    wrap.append(node("p", "error", (w.result || {}).error || t("whatif.failed")));
    return wrap;
  }
  const r = w.result || {};
  wrap.append(node("p", r.verdict === "promising" ? "note" : "coverage-warning",
                   `${t(`whatif.verdict.${r.verdict}`)} — ${r.verdict_note}`));
  wrap.append(facts([
    [t("whatif.cited"), t(r.cited_code_still_present ? "supply.yes" : "supply.no")],
    [t("whatif.gone"), String((r.rule_findings_gone || []).length)],
    [t("whatif.new"), String((r.rule_findings_new || []).length)],
    [t("whatif.drift"), String((r.drift || []).length)],
    [t("whatif.immune"), r.immune && r.immune.ran
      ? String((r.immune.matches || []).length) : t("whatif.immuneoff")],
    [t("whatif.untouched"), t("supply.yes")],
  ]));
  if ((r.rule_findings_new || []).length) {
    wrap.append(node("h3", null, t("whatif.new")),
                list(r.rule_findings_new.map((x) => `${x.rule_id} · ${x.file}:${x.line || ""} · ${x.title}`)));
  }
  if ((r.drift || []).length) {
    wrap.append(node("h3", null, t("whatif.drift")),
                list(r.drift.map((x) => `${x.label} · ${x.file}:${x.line || ""}`)));
  }
  const tests = r.tests || {};
  wrap.append(node("h3", null, t("whatif.tests")));
  if (tests.run) {
    const side = (x) => !x ? "—" : x.timed_out ? t("whatif.t.timeout")
      : x.passed === null ? t("whatif.t.none")
      : `${t(x.passed ? "whatif.t.pass" : "whatif.t.fail")}${x.count_passed !== undefined
          ? ` (${x.count_passed} ✓, ${x.count_failed} ✗)` : ""}`;
    wrap.append(facts([
      [t("whatif.t.before"), side(tests.before)],
      [t("whatif.t.after"), side(tests.after)],
      [t("whatif.t.isolation"), t("whatif.t.isolationtext", tests.image)],
      [t("whatif.t.installed"), t(tests.installed ? "supply.yes" : "supply.no")],
    ]));
    if ((tests.broken_by_patch || []).length) {
      wrap.append(node("h4", null, t("whatif.t.broken")), list(tests.broken_by_patch));
    }
    if ((tests.fixed_by_patch || []).length) {
      wrap.append(node("h4", null, t("whatif.t.fixed")), list(tests.fixed_by_patch));
    }
    const out = node("details", "block");
    out.append(node("summary", null, t("whatif.t.output")),
               node("pre", "snippet", tests.after_output || ""));
    wrap.append(out);
  } else {
    wrap.append(node("p", "muted", tests.error || tests.explanation
      || t(`whatif.t.reason.${tests.reason || "off"}`)));
  }
  if ((tests.candidates || []).length) {
    wrap.append(node("p", "muted small", t("whatif.t.candidates")), list(tests.candidates));
  }
  const det = node("details", "block");
  det.append(node("summary", null, t("whatif.diff")), node("pre", "snippet", r.diff || ""));
  wrap.append(det);
  return wrap;
}

function whatIfForm(finding) {
  const det = node("details", "block whatif");
  det.append(node("summary", null, t("whatif.title")));
  det.append(node("p", "muted", t("whatif.intro")));
  const area = document.createElement("textarea");
  area.rows = 8;
  area.spellcheck = false;
  area.className = "patch";
  area.placeholder = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n...";
  area.setAttribute("aria-label", t("whatif.patch"));
  const out = node("div");
  const go_ = button(t("whatif.run"), "", async () => {
    go_.disabled = true;
    out.replaceChildren(node("p", "muted", t("whatif.running")));
    try {
      const audit = state.current;
      let w = await api(auditPath(audit, "/what-if"), {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: finding.id, patch: area.value }),
      });
      out.replaceChildren(whatIfResult(w));
      // With the sandbox on, the tests run in the background: ask until done.
      for (let i = 0; w.status === "running" && i < 240; i++) {
        await new Promise((resolve) => setTimeout(resolve, 5000));
        const all = await api(auditPath(audit, "/what-if"));
        w = all.find((x) => x.id === w.id) || w;
        out.replaceChildren(whatIfResult(w));
      }
    } catch (e) {
      out.replaceChildren(node("p", "error", e.message));
    } finally {
      go_.disabled = false;
    }
  });
  det.append(area, go_, out);
  return det;
}

// --- C26: approving learnt rules --------------------------------------------------

function approvalNode(audit, r) {
  const wrap = node("div");
  if (!r.validated) return wrap;
  wrap.append(node("span", r.approved ? "badge badge-a-confirmed" : "badge badge-a-unverifiable",
                   r.approved ? t("memory.approved", r.approved_by || "—")
                     : t("memory.pending")));
  if (!audit.project_id) return wrap;
  const path = `/api/projects/${encodeURIComponent(audit.project_id)}/immune-rules/${r.id}/approval`;
  wrap.append(" ", button(r.approved ? t("memory.revoke") : t("memory.approve"), "ghost",
    async (event) => {
      event.target.disabled = true;
      try {
        await api(path, { method: r.approved ? "DELETE" : "POST" });
        await loadDetail(audit.id);
      } catch (e) {
        wrap.append(node("p", "error", e.message));
        event.target.disabled = false;
      }
    }));
  return wrap;
}

// --- C32: replay ---------------------------------------------------------------------

function replayBlock(audit) {
  const section = block(t("replay.title"), node("p", "muted", t("replay.intro")));
  if (audit.status === "done" && audit.commit_sha) {
    const b = button(t("replay.run"), "ghost", async () => {
      b.disabled = true;
      try {
        const created = await api(auditPath(audit, "/replay"), { method: "POST" });
        await refresh();
        go("changes", created.id);
      } catch (e) {
        section.append(node("p", "error", e.message));
        b.disabled = false;
      }
    });
    section.append(b);
  }
  if (audit.replay_of) {
    section.append(lazyBlock(t("replay.compare"), "repro", auditPath(audit, "/reproducibility"),
      audit, (r) => {
        const wrap = document.createDocumentFragment();
        wrap.append(node("p", null, t("replay.agreement",
          r.agreement === null ? "—" : `${Math.round(r.agreement * 100)}%`, r.in_both,
          r.only_original.length, r.only_replay.length)));
        wrap.append(node("p", r.rules_agree ? "muted" : "coverage-warning",
                         t(r.rules_agree ? "replay.rulesagree" : "replay.rulesdiffer")));
        wrap.append(node("p", "muted", t("replay.note")));
        for (const [k, items] of [["only_original", r.only_original],
                                  ["only_replay", r.only_replay]]) {
          if (!items.length) continue;
          const det = node("details", "block");
          det.append(node("summary", null, `${t(`replay.${k}`)} · ${items.length}`),
                     list(items.map((f) => `${f.title} · ${f.file || ""}:${f.line || ""}`)));
          wrap.append(det);
        }
        return wrap;
      }));
  }
  return section;
}

// --- MCP: the taxonomy, checked now ------------------------------------------------

function taxonomyCheck() {
  const holder = node("div");
  const b = button(t("mcp.check"), "ghost", async () => {
    b.disabled = true;
    holder.replaceChildren(b, node("p", "muted", t("summary.loading")));
    try {
      const r = await api("/api/mcp/taxonomy-check", { method: "POST" });
      const text = !r.checked ? t("mcp.checkfailed", r.error || "—")
        : r.matches ? t("mcp.checkok", r.at, (r.official_editions || []).join(", "))
        : t("mcp.checkdiff", r.differences.map((d) => `${d.id}: ${d.official || "—"}`).join("; "));
      holder.replaceChildren(b, node("p", r.checked && r.matches ? "note" : "coverage-warning",
                                     text));
    } catch (e) {
      holder.replaceChildren(b, node("p", "error", e.message));
    }
    b.disabled = false;
  });
  holder.append(b);
  return holder;
}

// --- surface, supply and views additions --------------------------------------------

function servicesBlock(s) {
  const section = block(t("surface.services"), node("p", "muted", t("surface.servicesnote")));
  if ((s.containers || []).length) {
    section.append(table([{ text: t("supply.name") }, { text: "image" },
                          { text: t("surface.ports") }, { text: t("surface.flags") }],
      s.containers.map((c) => row([c.name, c.image || c.kubernetes || "—",
        (c.published_ports || []).join(", ") || "—",
        [c.privileged ? "privileged" : "", c.host_network ? "host network" : ""]
          .filter(Boolean).join(", ") || "—"]))));
  }
  const line = (key, items, fmt) => {
    if (items && items.length) section.append(node("p", null, `${t(key)}: ${items.map(fmt).join(" · ")}`));
  };
  line("surface.datastores", s.datastores, (d) => d.kind);
  line("surface.thirdparty", s.third_party, (d) => d.kind);
  line("surface.hosts", (s.external_hosts || []).slice(0, 40), (h) => h.host);
  if (section.childElementCount <= 2) section.append(node("p", "muted", t("surface.noservices")));
  return section;
}

function taintBlock(audit) {
  const run = runOf(audit, "taint");
  const section = block(t("taint.title"));
  if (!run) {
    section.append(node("p", "muted", t("p3.notrun")));
    return section;
  }
  const err = moduleError(run);
  if (err) section.append(err);
  const d = run.detail || {};
  section.append(node("p", "muted", d.limits || ""));
  const kinds = Object.entries(d.by_kind || {}).map(([k, v]) => `${k} ${v}`).join(" · ");
  section.append(node("p", null, t("taint.line", (d.languages || []).join(", ") || "—",
                                    kinds || "0")));
  const found = (audit.findings || []).filter((f) => (f.rule_id || "").startsWith("taint."));
  if (found.length) section.append(findingsTable(found));
  return section;
}

function flowNode(finding) {
  const flow = (finding.detail || {}).flow;
  if (!flow || !flow.length) return document.createDocumentFragment();
  const wrap = document.createDocumentFragment();
  wrap.append(node("h3", null, t("taint.flow")));
  const ol = node("ol", "flow");
  for (const s of flow) {
    const li = node("li");
    li.append(node("span", "badge", t(`taint.step.${s.step}`)), " ",
              node("span", "where", `${finding.file}:${s.line}`), " ",
              node("code", null, s.text || ""));
    ol.append(li);
  }
  wrap.append(ol);
  return wrap;
}

function claimsBlock(audit) {
  const run = runOf(audit, "claims");
  const section = block(t("claims.title"), node("p", "muted", t("claims.intro")));
  if (!run) {
    section.append(node("p", "muted", t("p3.notrun")));
    return section;
  }
  const err = moduleError(run);
  if (err) section.append(err);
  const d = run.detail || {};
  const items = d.items || [];
  if (!items.length) {
    section.append(node("p", null, t("claims.none")));
    return section;
  }
  if (d.lowers_confidence) section.append(node("p", "coverage-warning", t("claims.lowers")));
  section.append(table(
    [{ text: t("claims.claim") }, { text: t("claims.status") }, { text: t("claims.said") },
     { text: t("claims.code") }],
    items.map((i) => row([i.label,
      node("span", i.status === "backed" ? "badge badge-a-confirmed"
        : i.status === "contradicted" ? "badge badge-a-discarded" : "badge badge-a-unverifiable",
        t(`claims.${i.status}`)),
      { className: "where", content: `${i.claim.file}:${i.claim.line} — ${i.claim.text}` },
      { className: "where", content: i.contradiction
        ? `${i.contradiction.file}:${i.contradiction.line} — ${i.contradiction.match}`
        : i.evidence ? `${i.evidence.file}:${i.evidence.line} — ${i.evidence.match}` : "—" }]))));
  if (d.note) section.append(node("p", "muted", d.note));
  return section;
}

function deadcodeBlock(audit) {
  const run = runOf(audit, "deadcode");
  const section = block(t("dead.title"), node("p", "muted", t("dead.note")));
  if (!run) {
    section.append(node("p", "muted", t("p3.notrun")));
    return section;
  }
  const items = (run.detail || {}).items || [];
  section.append(items.length ? table(
    [{ text: t("mcp.kind") }, { text: t("supply.name") }, { text: t("findings.location") }],
    items.map((i) => row([t(`dead.${i.kind}`), i.name,
                          { className: "where", content: `${i.file}:${i.line}` }])))
    : node("p", null, t("dead.none")));
  return section;
}
