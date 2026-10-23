
from tmcheck.core import coverage_gaps, policy_findings, rank, crossing_flows


def m():
    return {
        "zones": [{"id": "net", "trust": 0}, {"id": "core", "trust": 2}],
        "elements": [
            {"id": "user", "kind": "external_entity", "zone": "net"},
            {"id": "api", "kind": "process", "zone": "core"},
            {"id": "db", "kind": "data_store", "zone": "core", "holds_pii": True},
        ],
        "flows": [
            {"id": "f1", "source": "user", "target": "api", "protocol": "HTTPS", "authenticated": True},
            {"id": "f2", "source": "api", "target": "db", "protocol": "tls"},
        ],
        "threats": [],
    }


def test_crossing_only_f1():
    assert crossing_flows(m()) == ["f1"]


def test_gaps_scope_and_order():
    gaps = coverage_gaps(m())
    assert len(gaps) == 11          # f1: T,I,D + user: S,R + api: all six
    assert [g.category for g in gaps if g.ref == "api"] == list("STRIDE")
    assert [g.ref for g in gaps] == sorted(g.ref for g in gaps)


def test_any_status_covers_a_gap():
    x = m()
    x["threats"] = [{"id": "T1", "target": "api", "category": "S", "title": "t",
                     "likelihood": 1, "impact": 1, "status": "accepted", "justification": "ok"}]
    assert ("api", "S") not in {(g.ref, g.category) for g in coverage_gaps(x)}


def test_policy_encryption_and_auth():
    x = m()
    assert {f.code for f in policy_findings(x)} == {"PII_STORE_WITHOUT_I_THREAT"}
    x["flows"][0]["protocol"] = "http"
    del x["flows"][0]["authenticated"]
    codes = {(f.ref, f.code) for f in policy_findings(x)}
    assert ("f1", "UNENCRYPTED_CROSSING") in codes
    assert ("f1", "UNAUTHENTICATED_INBOUND") in codes


def test_rank_natural_order_and_levels():
    x = m()
    mk = lambda i, l, im: {"id": i, "target": "api", "category": "D", "title": "t",
                           "likelihood": l, "impact": im, "status": "open"}
    x["threats"] = [mk("T10", 3, 3), mk("T2", 3, 3), mk("T3", 3, 5), mk("T4", 2, 4), mk("T5", 1, 5)]
    r = rank(x)
    assert [t.id for t in r] == ["T3", "T2", "T10", "T4", "T5"]
    assert [t.level for t in r] == ["high", "medium", "medium", "medium", "low"]