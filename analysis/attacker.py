"""Module 5: the attacker's view. Which path would they take, and what cuts it?

Findings stop being a list with a severity each. Every capability an attacker
can hold is a node — sending requests, holding a user account, running code,
reading a secret, publishing a release — and every way from one to another
is an edge, with what makes it possible: a finding shown to hold, a
divergence from module 1, a weakly watched file from module 4, the agent
surface. From where each attacker profile starts, the cheapest path to each
crown jewel is found (Dijkstra by cost). A finding is then worth what the
cheapest path it enables is worth, and the fix that matters most is the one
that cuts the most paths at once.

Describe, never arm (principle 6): each step says what the attacker would
see, why it works (with its CWE and MITRE ATT&CK technique), what it needs
and what it gains — no exploit, no payload. Everything here is computed from
what the other modules established; no model is asked, and no token spent.
"""

import heapq
import re
from dataclasses import dataclass, field

# Attacker profiles and where each one starts.
PERSONAS = ("anonymous", "authenticated_user", "malicious_contributor",
            "compromised_dependency", "manipulated_agent")

# Capabilities. start:* nodes are where a profile begins.
REQUESTS = "sends_requests"            # reaches the application over the network
ACCOUNT = "user_account"               # holds a low-privilege account
SESSION = "gets_session"               # holds someone else's session
ADMIN = "accesses_admin"
EXEC = "executes_code"                 # runs code where the application runs
READ_DB = "reads_user_data"
WRITE_DB = "writes_db"
READ_FILES = "reads_files"
SECRET = "reads_secret"
INTERNAL = "reaches_internal"          # reaches the internal network
REPO = "reads_repository"
MERGE = "changes_code"                 # gets a change into the default branch
CI = "runs_in_ci"
DEV = "executes_on_developer"          # runs code on a developer's machine
AGENT = "controls_agent"               # steers an AI agent working in the repo
RELEASE = "publishes_release"

LABELS = {
    REQUESTS: "sends requests to the application", ACCOUNT: "holds a user account",
    SESSION: "holds another user's session", ADMIN: "administers the application",
    EXEC: "runs code where the application runs", READ_DB: "reads user data",
    WRITE_DB: "writes to the database", READ_FILES: "reads the server's files",
    SECRET: "reads a secret", INTERNAL: "reaches the internal network",
    REPO: "reads the repository", MERGE: "gets a change into the default branch",
    CI: "runs code in CI", DEV: "runs code on a developer's machine",
    AGENT: "steers an AI agent working in the repository",
    RELEASE: "publishes a release or deploys",
}

# Crown jewels: what they are after, and the capability that is having it.
JEWEL_KINDS = {"secrets": SECRET, "user_data": READ_DB, "deployment": RELEASE,
               "administration": ADMIN, "code_execution": EXEC}

SOLID = ("reachable", "corroborated")
TENTATIVE = ("inconclusive",)

_PRIVILEGE = {"none": 0.0, "user": 1.0, "contributor": 2.0, "maintainer": 3.0}


def cost_of(detail: dict) -> float:
    """Steps, plus what it takes: privileges, a victim's click, and half a
    step more if it leaves a trace someone could notice."""
    return round(detail.get("steps", 1)
                 + _PRIVILEGE.get(detail.get("privileges", "none"), 0.0)
                 + (1.0 if detail.get("interaction") else 0.0)
                 + (0.5 if detail.get("trace") else 0.0), 3)


@dataclass
class Edge:
    source: str
    target: str
    cost_detail: dict
    explanation: dict
    finding_id: int | None = None
    divergence_id: int | None = None
    leverage_id: int | None = None
    capability_ids: list = field(default_factory=list)
    tentative: bool = False
    persona: str | None = None
    structural: bool = False       # follows from the capability itself, not a flaw

    @property
    def cost(self) -> float:
        return cost_of(self.cost_detail)

    @property
    def fix(self) -> tuple | None:
        """What one fixes to remove this edge."""
        if self.finding_id is not None:
            return ("finding", self.finding_id)
        if self.divergence_id is not None:
            return ("divergence", self.divergence_id)
        if self.leverage_id is not None:
            return ("leverage", self.leverage_id)
        if self.capability_ids:
            return ("agent", tuple(self.capability_ids))
        return None


def _cd(steps=1, privileges="none", trace=False, interaction=False) -> dict:
    return {"steps": steps, "privileges": privileges, "trace": trace,
            "interaction": interaction}


# ---------------------------------------------------------------------------
# Findings as steps
# ---------------------------------------------------------------------------

# (pattern over the finding's text, technique key, gained capabilities)
_KINDS = (
    ("sql_injection", r"\bsql\b|sqli|query|inyecci[oó]n sql|execute\(", ("injection",)),
    ("command_injection", r"command|comando|os\.system|subprocess|shell|popen|exec\(",
     ("injection",)),
    ("code_injection", r"\beval\b|\bexec\b|code injection|template injection|ssti",
     ("injection",)),
    ("deserialization", r"deserial|pickle|yaml\.load|marshal|unserialize",
     ("injection", "other", "dependencies")),
    ("path_traversal", r"path traversal|directory traversal|\.\./|recorrido de rutas|"
                       r"lfi|arbitrary file|fichero arbitrario", ("file_handling", "injection")),
    ("ssrf", r"ssrf|server-side request|request forgery|urlopen|requests\.get", ("injection", "other")),
    # Before idor and privilege: a door with no lock is open to anyone, even
    # when what lies behind it is another user's or an administrator's.
    ("missing_auth", r"no auth|without auth|unauthenticated|sin autentic|missing auth|"
                     r"auth(entication)? bypass|bypass de autenticaci|"
                     r"(no|sin) (exige|requiere|pide)[a-z ]* (autenticaci|login|sesi)|"
                     r"(no|without) login|sin login", ("authz", "sessions")),
    ("idor", r"idor|insecure direct|ownership|propiedad|another user|otro usuario|"
             r"cualquier (pedido|usuario)|any (order|user)", ("authz",)),
    ("privilege", r"admin|privilege|privilegio|role|rol\b|escalat", ("authz",)),
    ("session", r"session|sesi[oó]n|cookie|jwt|token", ("sessions",)),
    ("xss", r"xss|cross-site scripting|innerhtml|script", ("xss",)),
    ("csrf", r"csrf", ("csrf",)),
    ("brute_force", r"brute|rate limit|fuerza bruta|limitaci[oó]n|enumerat|enumeraci",
     ("rate_limiting", "sessions", "authz")),
    ("hardcoded_secret", r"hardcoded|hard-coded|committed|en el c[oó]digo|credential|"
                         r"api[_ ]?key|password|secret|token", ("secrets",)),
    ("info_disclosure", r"stack trace|traceback|debug|verbose|disclos|filtra|expone",
     ("error_handling",)),
    ("cors", r"cors|credentials", ("cors",)),
)

# kind -> (CWE, ATT&CK technique, missing defense, gains, cost detail factory)
TECHNIQUES = {
    "sql_injection": ("CWE-89", "T1190", "the query is built from input instead of "
                      "bound parameters", (READ_DB, WRITE_DB), lambda: _cd(1)),
    "command_injection": ("CWE-78", "T1059", "input reaches a shell command",
                          (EXEC,), lambda: _cd(1)),
    "code_injection": ("CWE-94", "T1059", "input is evaluated as code", (EXEC,),
                       lambda: _cd(1)),
    "deserialization": ("CWE-502", "T1190", "untrusted data is deserialized into objects",
                        (EXEC,), lambda: _cd(2)),
    "path_traversal": ("CWE-22", "T1083", "a path from input is not confined to its "
                       "directory", (READ_FILES,), lambda: _cd(1)),
    "ssrf": ("CWE-918", "T1090", "the server fetches a URL the caller chooses",
             (INTERNAL,), lambda: _cd(1)),
    "idor": ("CWE-639", "T1190", "the record is fetched by its id with no check of whose "
             "it is", (READ_DB,), lambda: _cd(1, trace=True)),
    "privilege": ("CWE-285", "T1078", "the role is not checked before the action",
                  (ADMIN,), lambda: _cd(1)),
    "missing_auth": ("CWE-306", "T1190", "the endpoint does not require authentication",
                     (ACCOUNT,), lambda: _cd(1)),
    "session": ("CWE-384", "T1539", "sessions are not bound, rotated or protected",
                (SESSION,), lambda: _cd(2)),
    "xss": ("CWE-79", "T1189", "input is rendered as markup without escaping",
            (SESSION,), lambda: _cd(1, interaction=True)),
    "csrf": ("CWE-352", "T1204", "state-changing requests carry no anti-forgery token",
             (WRITE_DB,), lambda: _cd(1, interaction=True)),
    "brute_force": ("CWE-307", "T1110", "attempts are not limited", (ACCOUNT,),
                    lambda: _cd(3, trace=True)),
    "hardcoded_secret": ("CWE-798", "T1552.001", "a credential is kept in the source",
                         (SECRET,), lambda: _cd(1, trace=False)),
    "info_disclosure": ("CWE-209", "T1592", "errors reveal internals", (),
                        lambda: _cd(1)),
    "cors": ("CWE-942", "T1557", "other origins may make credentialed requests",
             (SESSION,), lambda: _cd(1, interaction=True)),
}

_AUTH_NEEDED = re.compile(r"(?i)\b(authenticated|logged[- ]in|login required|must be "
                          r"signed in|any (logged|signed)|autenticad|con sesi[oó]n|"
                          r"usuario registrado|low[- ]privilege)")
# Behind the admin door: a step that starts from administering the application.
_ADMIN_NEEDED = re.compile(r"(?i)(\b(only|solo|sólo)\b[^.;]{0,30}?\badmin|admins? only|requires? (an? )?admin|"
                           r"admin(istrator)? (role|account|session|privileges?) "
                           r"(is )?required|requiere (un |el )?(rol de )?admin|"
                           r"(cuenta|sesi[oó]n|rol) de administrador)")


def kind_of(finding: dict) -> str | None:
    h = finding.get("hypothesis") or {}
    text = " ".join(str(x or "") for x in (
        finding.get("title"), finding.get("description"), h.get("sink"),
        finding.get("code_snippet"))).lower()
    category = finding.get("category") or "other"
    for kind, pattern, categories in _KINDS:
        if category in categories and re.search(pattern, text):
            return kind
    fallback = {"xss": "xss", "csrf": "csrf", "secrets": "hardcoded_secret",
                "rate_limiting": "brute_force", "sessions": "session",
                "file_handling": "path_traversal", "cors": None}
    return fallback.get(category)


def finding_edges(f: dict) -> list[Edge]:
    status = f.get("epistemic_status")
    if status not in SOLID + TENTATIVE or f.get("verification_status") != "verified":
        return []
    kind = kind_of(f)
    if not kind or kind not in TECHNIQUES:
        return []
    cwe, attack, missing, gains, cost = TECHNIQUES[kind]
    h = f.get("hypothesis") or {}
    preconditions = [str(p) for p in (h.get("preconditions") or [])][:5]
    text = " ".join([str(f.get("description") or ""), *preconditions])
    if kind == "hardcoded_secret":
        source = REPO
        needs = preconditions or ["read access to the repository or to a copy of it"]
    # Only what it needs says so: a description of a missing admin check
    # talks about administrators too.
    elif kind not in ("privilege", "missing_auth") and \
            _ADMIN_NEEDED.search(" ".join(preconditions)):
        source = ADMIN
        needs = preconditions or ["an administrator's account or session"]
    elif kind in ("idor", "privilege", "csrf") or _AUTH_NEEDED.search(text):
        source = ACCOUNT
        needs = preconditions or ["a low-privilege account"]
    else:
        source = REQUESTS
        needs = preconditions or ["network access to the application"]
    where = f"{f.get('file')}:{f.get('line')}" if f.get("line") else str(f.get("file") or "")
    edges = []
    for gain in gains:
        edges.append(Edge(source, gain, cost(), {
            "kind": kind, "cwe": cwe, "attack": attack,
            "sees": {"where": where, "entry": str(h.get("source") or "")[:300],
                     "title": str(f.get("title") or "")[:300]},
            "works": missing, "needs": needs, "gains": gain,
        }, finding_id=f.get("id"), tentative=status in TENTATIVE))
    return edges


# ---------------------------------------------------------------------------
# Divergences, leverage and the agent surface as steps
# ---------------------------------------------------------------------------

def _oversight_cost(oversight: float) -> float:
    """Getting a change merged costs more the more it is watched."""
    return round(1 + 4 * max(0.0, min(1.0, oversight or 0.0)), 2)


def leverage_edges(rows: list[dict]) -> list[Edge]:
    out = []
    for r in rows:
        codes = {x.get("code") for x in r.get("reasons") or []}
        lev, ovs = r.get("leverage", 0), r.get("oversight", 0)
        base = {"where": r["file"], "oversight": ovs, "leverage": lev,
                "reasons": sorted(c for c in codes if c)}
        # No merge needed, so no review in the way: however watched it is.
        if "ci_pr_target" in codes:
            out.append(Edge("start:malicious_contributor", CI, _cd(1, "none"), {
                "kind": "pr_target", "cwe": "CWE-829", "attack": "T1195.002",
                "sees": base, "works": "the workflow runs on pull_request_target, "
                "with the base repository's secrets, for anyone's pull request",
                "needs": ["opening a pull request"], "gains": CI},
                leverage_id=r.get("id")))
        # Getting a change in only goes through files that are badly watched.
        # CODEOWNERS is not one: changing it gains the merge it already took.
        if lev >= 0.7 and ovs < 0.6 and (
                "ci_workflow" in codes or "install_script" in codes or "run_by" in codes \
                or "agent_config" in codes):
            what = ("a CI workflow" if "ci_workflow" in codes else
                    "agent configuration" if "agent_config" in codes else
                    "a script that runs on its own")
            gain = (CI if "ci_workflow" in codes or "run_by" in codes else
                    AGENT if "agent_config" in codes else DEV)
            out.append(Edge(MERGE, gain, _cd(1, "contributor"), {
                "kind": "high_leverage_file", "cwe": "CWE-284", "attack": "T1195.002",
                "sees": base, "works": f"{what} with much leverage and little oversight "
                f"(leverage {lev:.2f}, oversight {ovs:.2f})",
                "needs": ["a change to that file merged"], "gains": gain},
                leverage_id=r.get("id")))
        if "ci_secrets" in codes:
            out.append(Edge(CI, SECRET, _cd(1), {
                "kind": "ci_secrets", "cwe": "CWE-522", "attack": "T1552",
                "sees": base, "works": "the workflow is handed repository secrets",
                "needs": ["running in that workflow"], "gains": SECRET},
                leverage_id=r.get("id"), structural=True))
        if "ci_deploy" in codes:
            out.append(Edge(CI, RELEASE, _cd(1), {
                "kind": "ci_deploy", "cwe": "CWE-494", "attack": "T1195.002",
                "sees": base, "works": "the workflow deploys or publishes what it runs",
                "needs": ["running in that workflow"], "gains": RELEASE},
                leverage_id=r.get("id"), structural=True))
    # The weakest watched file sets how hard a contributor's change is to land.
    watched = [r for r in rows if r.get("leverage", 0) >= 0.7]
    if watched:
        weakest = min(watched, key=lambda r: r.get("oversight", 0))
        out.append(Edge("start:malicious_contributor", MERGE,
                        {**_cd(1, "none"), "steps": _oversight_cost(weakest["oversight"])}, {
            "kind": "merge", "cwe": "CWE-1357", "attack": "T1195.002",
            "sees": {"where": weakest["file"], "oversight": weakest.get("oversight", 0)},
            "works": "changes to it land with little review",
            "needs": ["opening a pull request"], "gains": MERGE},
            leverage_id=weakest.get("id")))
    return out


def divergence_edges(rows: list[dict], oversight_by_file: dict[str, float]) -> list[Edge]:
    out = []
    for d in rows:
        kind, file = d.get("kind"), d.get("file") or ""
        base = {"where": file, "detail": str(d.get("detail") or "")[:300]}
        if kind == "hidden_content":
            out.append(Edge(MERGE, AGENT, _cd(1), {
                "kind": "hidden_instructions", "cwe": "CWE-451", "attack": "T1027",
                "sees": base, "works": "the file says one thing to a person and "
                "another to the agent that reads it",
                "needs": ["the file in the default branch"], "gains": AGENT},
                divergence_id=d.get("id")))
        elif kind == "unexpected_execution":
            out.append(Edge(REPO, DEV, _cd(1, interaction=True), {
                "kind": "runs_on_open", "cwe": "CWE-829", "attack": "T1204.002",
                "sees": base, "works": "code runs on install, checkout or opening the "
                "folder, without anyone asking",
                "needs": ["a developer cloning or installing it"], "gains": DEV},
                divergence_id=d.get("id")))
            out.append(Edge(MERGE, REPO, _cd(0), {
                "kind": "in_repository", "cwe": "CWE-829", "attack": "T1195.002",
                "sees": base, "works": "what is merged is what developers clone",
                "needs": [], "gains": REPO}, divergence_id=d.get("id"), structural=True))
    return out


def agent_edges(capabilities: list[dict], combinations: list[dict]) -> list[Edge]:
    by_id = {c["id"]: c for c in capabilities if "id" in c}
    out = []
    for combo in combinations:
        steps = [by_id[i] for i in combo.get("steps") or [] if i in by_id]
        if not steps:
            continue
        where = sorted({s["source_file"] for s in steps})
        gain = SECRET if combo.get("kind") == "exfiltration" else DEV
        out.append(Edge(AGENT, gain, _cd(1 if combo.get("unattended") else 2), {
            "kind": f"agent_{combo.get('kind')}", "cwe": "CWE-250", "attack": "T1059",
            "sees": {"where": ", ".join(where)[:300]},
            "works": "the agent inherits " + ", ".join(
                s["capability"] for s in steps) + " from the repository",
            "needs": [] if combo.get("unattended") else ["the agent following its instructions"],
            "gains": gain}, capability_ids=[s["id"] for s in steps]))
    return out


# What holding one capability gives without any further flaw.
def structural_edges(has_secrets: bool, has_deploy: bool) -> list[Edge]:
    def e(source, target, steps, works, kind):
        return Edge(source, target, _cd(steps), {
            "kind": kind, "cwe": None, "attack": None, "sees": {}, "works": works,
            "needs": [], "gains": target}, structural=True)
    out = [
        e("start:anonymous", REQUESTS, 0, "the application is reachable", "start"),
        e("start:authenticated_user", REQUESTS, 0, "the application is reachable", "start"),
        e("start:authenticated_user", ACCOUNT, 0, "the profile starts with an account", "start"),
        e("start:malicious_contributor", REPO, 0, "contributors read the repository", "start"),
        e("start:compromised_dependency", EXEC, 0,
          "a dependency's code runs inside the application", "start"),
        e("start:manipulated_agent", AGENT, 0,
          "the profile is an agent whose instructions were injected", "start"),
        e(ACCOUNT, REQUESTS, 0, "an account sends requests too", "implied"),
        e(SESSION, ACCOUNT, 0, "a session is an account", "implied"),
        e(EXEC, SECRET, 1, "the process environment holds its secrets", "implied"),
        e(EXEC, READ_DB, 1, "the process holds its database credentials", "implied"),
        e(EXEC, WRITE_DB, 1, "the process holds its database credentials", "implied"),
        e(EXEC, READ_FILES, 0, "the process reads its own files", "implied"),
        e(ADMIN, READ_DB, 1, "administrators see user data", "implied"),
        e(ADMIN, WRITE_DB, 1, "administrators change data", "implied"),
        e(READ_FILES, SECRET, 1, "configuration files hold secrets", "implied"),
        e(INTERNAL, SECRET, 2, "internal services and cloud metadata hand out "
          "credentials", "implied"),
        e(WRITE_DB, ADMIN, 2, "a written role is a granted role", "implied"),
        e(MERGE, REPO, 0, "what is merged is in the repository", "implied"),
        e(DEV, SECRET, 1, "a developer's machine holds their credentials", "implied"),
        e(AGENT, DEV, 1, "an agent runs as the developer", "implied"),
    ]
    if has_deploy:
        out.append(e(SECRET, RELEASE, 1, "the deploy credentials are among the "
                     "secrets", "implied"))
    return out


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def cheapest(edges: list[Edge], start: str, goal: str, allowed=None):
    """Dijkstra from start to goal; the indices of the edges taken, and the cost."""
    adj: dict[str, list[int]] = {}
    for i, e in enumerate(edges):
        if allowed is None or i in allowed:
            adj.setdefault(e.source, []).append(i)
    best = {start: 0.0}
    back: dict[str, int] = {}
    heap = [(0.0, start)]
    while heap:
        d, node = heapq.heappop(heap)
        if node == goal:
            path, n = [], goal
            while n != start:
                i = back[n]
                path.append(i)
                n = edges[i].source
            return list(reversed(path)), round(d, 3)
        if d > best.get(node, float("inf")):
            continue
        for i in adj.get(node, []):
            e = edges[i]
            nd = d + e.cost
            if nd < best.get(e.target, float("inf")):
                best[e.target] = nd
                back[e.target] = i
                heapq.heappush(heap, (nd, e.target))
    return None, None


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def path_severity(cost: float, tentative: bool) -> str:
    level = 0 if cost <= 3 else 1 if cost <= 5 else 2 if cost <= 8 else 3
    return SEVERITY_ORDER[min(3, level + (1 if tentative else 0))]


def _paths(edges, goals, allowed=None):
    out = []
    for persona in PERSONAS:
        for kind, node in goals.items():
            path, cost = cheapest(edges, f"start:{persona}", node, allowed)
            if path is None:
                continue
            # A path that uses only what the profile is by definition, with no
            # flaw anywhere, is not worth reporting.
            if all(edges[i].structural for i in path):
                continue
            tentative = any(edges[i].tentative for i in path)
            out.append({"persona": persona, "jewel": kind, "target": node,
                        "edges": path, "cost": cost, "tentative": tentative,
                        "severity": path_severity(cost, tentative)})
    return out


def through(edges: list[Edge], i: int, start: str, goal: str):
    """The cheapest path from start to goal that takes edge i, and its cost.

    None when the step gains nothing: when what it gives is had already, at
    no more than it costs to get to the step (a login bypass, to someone who
    holds an account).
    """
    e = edges[i]
    head, before = cheapest(edges, start, e.source)
    if head is None:
        return None, None
    _, held = cheapest(edges, start, e.target, set(range(len(edges))) - {i})
    if held is not None and held <= before:
        return None, None
    tail, after = ([], 0.0) if e.target == goal else cheapest(edges, e.target, goal)
    if tail is None:
        return None, None
    return head + [i] + tail, round(before + e.cost + after, 3)


def contextual_severity(edges: list[Edge], goals: dict) -> dict[int, dict]:
    """A finding is worth the cheapest path it enables.

    Measured through the finding's own step, not only on the cheapest path to
    each jewel: of two flaws that open the same door at the same price, the
    one that loses the tie is no less worth fixing.
    """
    out: dict[int, dict] = {}
    for i, e in enumerate(edges):
        if e.finding_id is None:
            continue
        for persona in PERSONAS:
            for node in goals.values():
                path, cost = through(edges, i, f"start:{persona}", node)
                if path is None:
                    continue
                severity = path_severity(cost, any(edges[j].tentative for j in path))
                entry = out.setdefault(e.finding_id, {"severity": severity, "personas": []})
                if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(entry["severity"]):
                    entry["severity"] = severity
                if persona not in entry["personas"]:
                    entry["personas"].append(persona)
    return out


def min_cut(edges: list[Edge], goals: dict, paths: list[dict], limit: int = 3) -> list[dict]:
    """The fixes that leave the most profile-jewel pairs without a solid path.

    Removing a fix's edges and searching again, so that a path that merely
    reroutes is not counted as cut. Tentative edges are left out: an
    inconclusive finding is not the fix to recommend.
    """
    solid = {i for i, e in enumerate(edges) if not e.tentative}
    reached = {(p["persona"], p["jewel"]) for p in _paths(edges, goals, solid)}
    if not reached:
        return []
    fixes: dict[tuple, set[int]] = {}
    for i in solid:
        f = edges[i].fix
        if f is not None and not edges[i].structural:
            fixes.setdefault(f, set()).add(i)
    chosen, removed, out = [], set(), []
    remaining = set(reached)
    for _ in range(limit):
        best = None
        for fix, ids in fixes.items():
            if fix in chosen:
                continue
            allowed = solid - removed - ids
            still = {(p["persona"], p["jewel"]) for p in _paths(edges, goals, allowed)}
            cut = remaining - still
            cost_gain = sum(p["cost"] for p in _paths(edges, goals, allowed)) \
                - sum(p["cost"] for p in _paths(edges, goals, solid - removed))
            score = (len(cut), cost_gain)
            if cut and (best is None or score > best[0]):
                best = (score, fix, ids, cut)
        if best is None:
            break
        (_, _), fix, ids, cut = best
        chosen.append(fix)
        removed |= ids
        remaining -= cut
        out.append({"fix": {"type": fix[0], "id": list(fix[1]) if fix[0] == "agent"
                            else fix[1]},
                    "cuts": sorted([list(c) for c in cut]),
                    "remaining": len(remaining)})
        if not remaining:
            break
    return out


def analyze(findings: list[dict], divergences: list[dict], leverage: list[dict],
            agent: dict, jewels: list[dict]) -> dict:
    codes = {c.get("code") for r in leverage for c in r.get("reasons") or []}
    edges = structural_edges(True, "ci_deploy" in codes)
    for f in findings:
        edges += finding_edges(f)
    edges += leverage_edges(leverage)
    edges += divergence_edges(divergences, {r["file"]: r.get("oversight", 0)
                                            for r in leverage})
    edges += agent_edges(agent.get("capabilities") or [], agent.get("combinations") or [])
    goals = {}
    for j in jewels:
        node = JEWEL_KINDS.get(j.get("kind"))
        if node:
            goals.setdefault(j["kind"], node)
    paths = _paths(edges, goals)
    contextual = contextual_severity(edges, goals)
    attack_files = set()
    for p in paths:
        for i in p["edges"]:
            where = (edges[i].explanation.get("sees") or {}).get("where") or ""
            if where and edges[i].finding_id is not None:
                attack_files.add(where.rsplit(":", 1)[0])
            elif where and edges[i].leverage_id is not None:
                attack_files.add(where)
    nodes = sorted({n for e in edges for n in (e.source, e.target)})
    used = {i for p in paths for i in p["edges"]}
    return {"nodes": nodes, "edges": edges, "used": used, "paths": paths,
            "min_cut": min_cut(edges, goals, paths), "contextual": contextual,
            "attack_files": attack_files, "goals": goals}


# ---------------------------------------------------------------------------
# Crown jewels secaudit suggests
# ---------------------------------------------------------------------------

_DB = re.compile(r"(?i)\b(sqlite3|psycopg|pymysql|sqlalchemy|mongoose|mongodb|prisma|"
                 r"sequelize|typeorm|knex|django\.db|activerecord|\bpg\b|mysql)")
_ADMIN = re.compile(r"(?i)(/admin\b|is_admin|isadmin|role\s*==\s*['\"]admin|superuser|"
                    r"@admin|admin_required)")


# What a suggested jewel says, in the language of the audit that suggests it.
_JEWEL_TEXT = {
    "en": {"secrets": "the secrets the running application holds",
           "user_data": "the user data in the database", "used_in": "used in {}",
           "deployment": "deployment ({})", "administration": "administration ({})"},
    "es": {"secrets": "los secretos que tiene la aplicación en marcha",
           "user_data": "los datos de usuarios de la base de datos", "used_in": "se usa en {}",
           "deployment": "el despliegue ({})", "administration": "la administración ({})"},
}


def suggest_jewels(texts: dict[str, str], leverage: list[dict],
                   findings: list[dict], language: str = "en") -> list[dict]:
    """The crown jewels the repository itself points at, with the evidence."""
    t = _JEWEL_TEXT.get(language, _JEWEL_TEXT["en"])
    out = [{"kind": "secrets", "target": t["secrets"]}]
    db = next((rel for rel, text in texts.items() if _DB.search(text)), None)
    if db or any(kind_of(f) in ("sql_injection", "idor") for f in findings):
        out.append({"kind": "user_data", "target": t["user_data"]
                    + (f" ({t['used_in'].format(db)})" if db else "")})
    codes = {(r["file"], c.get("code")) for r in leverage for c in r.get("reasons") or []}
    deploy = sorted(f for f, c in codes if c == "ci_deploy")
    if deploy:
        out.append({"kind": "deployment", "target": t["deployment"].format(deploy[0])})
    admin = next((rel for rel, text in texts.items() if _ADMIN.search(text)), None)
    if admin:
        out.append({"kind": "administration", "target": t["administration"].format(admin)})
    return out
