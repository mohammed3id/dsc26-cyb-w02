"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass

import yaml

from collections import Counter

import re

class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ModelError(f"cannot load model: {e}") from e

    if not isinstance(data, dict):
        raise ModelError("top level of the model must be a mapping")

    for key in ("zones", "elements", "flows", "threats"):
        value = data.get(key)
        if value is None:
            data[key] = []
        elif not isinstance(value, list):
            raise ModelError(f"section {key!r} must be a list")
    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return {"S", "T", "R", "I", "D", "E"}
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown kind: {kind!r}")

STRIDE = ("S", "T", "R", "I", "D", "E")
KINDS = ("external_entity", "process", "data_store")
STATUSES = ("open", "mitigated", "accepted")


def _items(model, key):
    """Dict items of one section; tolerate a missing or null section."""
    return [x for x in (model.get(key) or []) if isinstance(x, dict)]


def _is_score(value):
    # type(...) is int rejects True/False (bool is a subclass of int) and 4.0
    return type(value) is int and 1 <= value <= 5


def _has_text(value):
    return isinstance(value, str) and value.strip() != ""


def _check_duplicate_ids(model):
    ids = []
    for key in ("zones", "elements", "flows", "threats"):
        ids += [x["id"] for x in _items(model, key) if "id" in x]
    return [
        Issue(str(i), "DUPLICATE_ID", "id is used more than once")
        for i, n in Counter(ids).items()
        if n > 1
    ]


def _check_elements(model):
    zone_ids = [z.get("id") for z in _items(model, "zones")]
    issues = []
    for e in _items(model, "elements"):
        ref = str(e.get("id"))
        if e.get("kind") not in KINDS:
            issues.append(Issue(ref, "BAD_KIND", "unknown element kind"))
        if e.get("zone") not in zone_ids:
            issues.append(Issue(ref, "UNKNOWN_ZONE", "zone is not defined"))
    return issues


def _check_flows(model):
    kinds = {e.get("id"): e.get("kind") for e in _items(model, "elements")}
    issues = []
    for f in _items(model, "flows"):
        ref = str(f.get("id"))
        src, dst = f.get("source"), f.get("target")
        both_known = True
        for end in (src, dst):
            if end not in kinds:
                issues.append(Issue(ref, "UNKNOWN_REF", f"{end!r} is not an element"))
                both_known = False
        if src == dst:
            issues.append(Issue(ref, "INVALID_FLOW", "source equals target"))
        elif both_known and "process" not in (kinds[src], kinds[dst]):
            issues.append(Issue(ref, "INVALID_FLOW", "neither end is a process"))
    return issues


def _check_threats(model):
    elements = {e.get("id"): e for e in _items(model, "elements")}
    flow_ids = [f.get("id") for f in _items(model, "flows")]
    issues = []
    for t in _items(model, "threats"):
        ref = str(t.get("id"))
        target = t.get("target")
        element = elements.get(target)

        # target must exist
        if element is None and target not in flow_ids:
            issues.append(Issue(ref, "UNKNOWN_REF", f"target {target!r} not found"))

        # category: exactly one STRIDE letter, then it must fit the target
        category = t.get("category")
        if not (isinstance(category, str) and category in STRIDE):
            issues.append(Issue(ref, "BAD_CATEGORY", "not one of S T R I D E"))
        else:
            allowed = None
            if element is not None:
                if element.get("kind") in KINDS:
                    allowed = applicable(element["kind"], is_log=element.get("is_log") is True)
            elif target in flow_ids:
                allowed = applicable("data_flow")
            if allowed is not None and category not in allowed:
                issues.append(Issue(ref, "INAPPLICABLE_CATEGORY", "category does not apply to target"))

        # scores
        bad = [n for n in ("likelihood", "impact") if not _is_score(t.get(n))]
        if bad:
            issues.append(Issue(ref, "BAD_SCORE", "invalid " + ", ".join(bad)))

        # status and the text it requires
        status = t.get("status")
        if status not in STATUSES:
            issues.append(Issue(ref, "BAD_STATUS", "unknown status"))
        elif status == "mitigated" and not _has_text(t.get("mitigation")):
            issues.append(Issue(ref, "MISSING_MITIGATION", "mitigated without mitigation text"))
        elif status == "accepted" and not _has_text(t.get("justification")):
            issues.append(Issue(ref, "MISSING_JUSTIFICATION", "accepted without justification"))
    return issues

SAFE_PROTOCOLS = {"https", "tls", "mtls", "sftp", "ssh"}


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = (
        _check_duplicate_ids(model)
        + _check_elements(model)
        + _check_flows(model)
        + _check_threats(model)
    )
    return sorted(set(issues))


def _crossing(model):
    """Flow dicts whose ends are known elements in different zones, in file order."""
    zone_of = {e.get("id"): e.get("zone") for e in _items(model, "elements")}
    return [
        f
        for f in _items(model, "flows")
        if f.get("source") in zone_of
        and f.get("target") in zone_of
        and zone_of[f.get("source")] != zone_of[f.get("target")]
    ]


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    return [f.get("id") for f in _crossing(model)]


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = {e.get("id"): e for e in _items(model, "elements")}
    covered = {(t.get("target"), t.get("category")) for t in _items(model, "threats")}
    needed = set()

    def need(ref, kind, is_log=False):
        for cat in applicable(kind, is_log=is_log):
            needed.add((ref, cat))

    for f in _crossing(model):
        need(f.get("id"), "data_flow")
        for end in (f.get("source"), f.get("target")):
            e = elements[end]
            if e.get("kind") in KINDS:
                need(end, e["kind"], e.get("is_log") is True)

    missing = [Gap(str(ref), cat) for ref, cat in needed if (ref, cat) not in covered]
    # Gap's own ordering is alphabetical (D, E, I, R, S, T), so sort with a custom key
    return sorted(missing, key=lambda g: (g.ref, STRIDE.index(g.category)))


def _number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    trust_of_zone = {z.get("id"): z.get("trust") for z in _items(model, "zones")}
    zone_of = {e.get("id"): e.get("zone") for e in _items(model, "elements")}
    findings = []

    for f in _crossing(model):
        ref = str(f.get("id"))
        protocol = f.get("protocol")
        if not (isinstance(protocol, str) and protocol.lower() in SAFE_PROTOCOLS):
            findings.append(Issue(ref, "UNENCRYPTED_CROSSING", "crossing flow is not encrypted"))

        src_trust = trust_of_zone.get(zone_of.get(f.get("source")))
        dst_trust = trust_of_zone.get(zone_of.get(f.get("target")))
        if _number(src_trust) and _number(dst_trust) and dst_trust > src_trust:
            if f.get("authenticated") is not True:
                findings.append(Issue(ref, "UNAUTHENTICATED_INBOUND", "inbound crossing is not authenticated"))

    i_targets = {t.get("target") for t in _items(model, "threats") if t.get("category") == "I"}
    for e in _items(model, "elements"):
        if (
            e.get("kind") == "data_store"
            and e.get("holds_pii") is True
            and e.get("id") not in i_targets
        ):
            findings.append(
                Issue(str(e.get("id")), "PII_STORE_WITHOUT_I_THREAT", "PII store has no I threat")
            )
    return sorted(set(findings))


def _natural_key(value):
    # "T2" -> ["T", 2, ""], "T10" -> ["T", 10, ""]: numbers compare as numbers
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", str(value))]


def _level(score):
    if score >= 15:
        return "high"
    if score >= 8:
        return "medium"
    return "low"


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    open_threats = [
        t
        for t in _items(model, "threats")
        if t.get("status") == "open"
        and _is_score(t.get("likelihood"))
        and _is_score(t.get("impact"))
    ]
    open_threats.sort(
        key=lambda t: (-(t["likelihood"] * t["impact"]), -t["impact"], _natural_key(t.get("id")))
    )
    return [
        RankedThreat(str(t.get("id")), t["likelihood"] * t["impact"], _level(t["likelihood"] * t["impact"]))
        for t in open_threats
    ]