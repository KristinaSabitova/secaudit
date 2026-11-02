"""Security Digital Twin: a navigable model of the audited system (C34).

Built only from what the other modules measured on the audited commit — no
model is asked, nothing runs. It is a map, not a copy: it cannot be
executed, and every node says what is unknown about it.

Nodes:
  area       a top-level part of the code (first directory, or "(root)")
  entry      an endpoint, webhook, upload, CLI, job or MCP tool (surface)
  asset      what entries touch: database, filesystem, network, subprocess...
  service    a container or Kubernetes object, a datastore, an external host
  dependency a direct dependency, with its known vulnerabilities if asked
  finding    a finding shown to exist, with its assessment
  persona    an attacker profile with a path (attack graph)
  jewel      what that path reaches

Edges carry a relation: contains, touches, depends_on, affects, reaches,
crosses (a trust boundary), runs.

Uncertainty is first class: an area the audit did not fully read, an entry
with no authentication or validation seen, a language not inventoried, a
finding that needs a dynamic test, a dependency whose vulnerabilities were
never asked. Absence of a node is not absence of the thing.
"""

from pathlib import PurePosixPath

TWIN_VERSION = "1"
MAX_NODES = 1500


def _area(path: str | None) -> str:
    parts = PurePosixPath(str(path or "")).parts
    return parts[0] if len(parts) > 1 else "(root)"


def build(audit: dict, coverage: list[dict] | None = None) -> dict:
    modules = {m["module"]: m for m in audit.get("modules") or []}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid, node_type, label, **attrs):
        if nid not in nodes and len(nodes) < MAX_NODES:
            nodes[nid] = {"id": nid, "type": node_type, "label": label, "uncertainty": [],
                          **attrs}
        return nodes.get(nid)

    def edge(a, b, rel, **attrs):
        if a in nodes and b in nodes:
            edges.append({"from": a, "to": b, "rel": rel, **attrs})

    def area_of(path):
        a = _area(path)
        node(f"area:{a}", "area", a, files=0)
        return f"area:{a}"

    # Areas, with what the audit read of them.
    for row in coverage or []:
        nid = area_of(row.get("file"))
        n = nodes[nid]
        n["files"] = n.get("files", 0) + 1
        if not row.get("audited"):
            n.setdefault("not_fully_read", 0)
            n["not_fully_read"] += 1
    for n in nodes.values():
        if n["type"] == "area" and n.get("not_fully_read"):
            n["uncertainty"].append(f"{n['not_fully_read']} file(s) not fully read")

    # Entries and what they touch.
    surface = (modules.get("surface") or {}).get("detail") or {}
    for i, it in enumerate(surface.get("items") or []):
        nid = f"entry:{i}"
        label = " ".join(x for x in (it.get("method"), it.get("path") or it.get("name")) if x)
        n = node(nid, "entry", label or it.get("kind"), kind=it.get("kind"),
                 file=it.get("file"), line=it.get("line"), auth=it.get("auth"),
                 validation=it.get("validation"), confidence=it.get("confidence"))
        if n is None:
            break
        if it.get("auth") == "none_seen":
            n["uncertainty"].append("no authentication seen on this entry")
        if it.get("validation") == "none_seen":
            n["uncertainty"].append("no input validation seen")
        if it.get("confidence") != "high":
            n["uncertainty"].append(f"read by pattern ({it.get('confidence')} confidence)")
        edge(area_of(it.get("file")), nid, "contains")
        node("boundary:untrusted", "persona", "untrusted input")
        edge("boundary:untrusted", nid, "crosses")
        for t in it.get("touches") or []:
            node(f"asset:{t}", "asset", t)
            edge(nid, f"asset:{t}", "touches")
    for lang in surface.get("not_inventoried") or []:
        node(f"gap:{lang}", "area", f"*.{lang}",
             uncertainty=[f"{lang} entries are not inventoried"])

    services = surface.get("services") or {}
    for c in services.get("containers") or []:
        nid = f"service:{c.get('name')}"
        n = node(nid, "service", c.get("name"), image=c.get("image"),
                 ports=c.get("published_ports"), file=c.get("file"),
                 kubernetes=c.get("kubernetes"))
        if n is not None:
            if c.get("privileged"):
                n["uncertainty"].append("runs privileged")
            if c.get("host_network"):
                n["uncertainty"].append("uses the host network")
            edge(area_of(c.get("file")), nid, "runs")
    for d in services.get("datastores") or []:
        nid = f"asset:{d['kind']}"
        node(nid, "service", d["kind"], files=d.get("files"))
        for f in d.get("files") or []:
            edge(area_of(f), nid, "touches")
    for h in (services.get("external_hosts") or [])[:60]:
        nid = f"host:{h['host']}"
        node(nid, "service", h["host"], external=True, mentions=h.get("mentions"))
        for f in h.get("files") or []:
            edge(area_of(f), nid, "touches")

    # Dependencies.
    deps_run = (modules.get("dependencies") or {}).get("detail") or {}
    osv = deps_run.get("osv") or {}
    for c in [c for c in audit.get("components") or [] if c.get("direct")][:150]:
        nid = f"dep:{c['ecosystem']}:{c['name']}"
        vulns = c.get("vulns")
        n = node(nid, "dependency", c["name"], ecosystem=c["ecosystem"],
                 version=c.get("version"), vulns=[v["id"] for v in vulns or []])
        if n is None:
            break
        if vulns is None:
            n["uncertainty"].append("known vulnerabilities not asked (OSV off)"
                                    if not osv.get("queried") else
                                    "no exact version: not asked")
        edge(area_of(c.get("manifest")), nid, "depends_on")

    # Findings shown to exist.
    for f in audit.get("findings") or []:
        if f.get("verification_status") != "verified" or f.get("assessment") == "discarded":
            continue
        nid = f"finding:{f['id']}"
        n = node(nid, "finding", f.get("title"), severity=f.get("severity"),
                 assessment=f.get("assessment"), file=f.get("file"), line=f.get("line"),
                 source=f.get("source") or "model")
        if n is None:
            break
        if f.get("assessment") == "unverifiable":
            n["uncertainty"].append("needs a dynamic test")
        elif f.get("assessment") == "potential":
            n["uncertainty"].append("static evidence only")
        edge(nid, area_of(f.get("file")), "affects")
        for e in [x for x in nodes.values() if x["type"] == "entry"
                  and x.get("file") == f.get("file")]:
            edge(nid, e["id"], "affects")

    # Attack paths: persona -> jewel, through findings.
    attack = audit.get("attack") or {}
    label_of = {n["id"]: n for n in attack.get("nodes") or []}
    edge_of = {e["id"]: e for e in attack.get("edges") or []}
    for p in attack.get("paths") or []:
        persona = f"persona:{p['persona']}"
        node(persona, "persona", p["persona"].replace("_", " "))
        target = label_of.get(p["target"]) or {}
        jewel = f"jewel:{target.get('key')}"
        node(jewel, "jewel", target.get("label") or target.get("key"))
        steps = [edge_of[i] for i in p.get("edges") or [] if i in edge_of]
        tentative = any(s.get("tentative") for s in steps)
        via = [f"finding:{s['finding_id']}" for s in steps if s.get("finding_id")]
        edge(persona, jewel, "reaches", cost=p.get("cost"), severity=p.get("severity"),
             via=via, hypothetical=True, tentative=tentative)
        for v in via:
            edge(persona, v, "reaches")

    counts: dict[str, int] = {}
    for n in nodes.values():
        counts[n["type"]] = counts.get(n["type"], 0) + 1
    return {"version": TWIN_VERSION, "commit": audit.get("commit_sha"),
            "nodes": list(nodes.values()), "edges": edges[:6000], "counts": counts,
            "truncated": len(nodes) >= MAX_NODES,
            "uncertain_nodes": sum(1 for n in nodes.values() if n["uncertainty"]),
            "note": ("A map built from the audit's measurements, not an executable copy. "
                     "Every path is hypothetical: nothing was run.")}
