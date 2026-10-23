from tmcheck.core import validate


def model(**over):
    m = {
        "zones": [{"id": "z1", "trust": 1}],
        "elements": [
            {"id": "p", "kind": "process", "zone": "z1"},
            {"id": "s", "kind": "data_store", "zone": "z1"},
        ],
        "flows": [{"id": "f1", "source": "p", "target": "s", "protocol": "tls"}],
        "threats": [],
    }
    m.update(over)
    return m


def codes(m):
    return {(i.ref, i.code) for i in validate(m)}


def threat(**kw):
    t = {"id": "T1", "target": "p", "category": "S", "title": "x",
        "likelihood": 3, "impact": 3, "status": "open"}
    t.update(kw)
    return t


def test_clean_model():
    assert validate(model(threats=[threat()])) == []


def test_duplicate_id_across_sections():
    m = model(threats=[threat(id="p")])
    assert ("p", "DUPLICATE_ID") in codes(m)


def test_bool_and_float_are_not_scores():
    for bad in (True, 4.0, "4", 0, 6, None):
        assert ("T1", "BAD_SCORE") in codes(model(threats=[threat(likelihood=bad)]))
        assert ("T1", "BAD_SCORE") in codes(model(threats=[threat(impact=bad)]))


def test_category_must_be_one_letter():
    for bad in ("s", "ST", ""):
        assert ("T1", "BAD_CATEGORY") in codes(model(threats=[threat(category=bad)]))


def test_e_on_store_is_inapplicable():
    assert ("T1", "INAPPLICABLE_CATEGORY") in codes(model(threats=[threat(target="s", category="E")]))


def test_self_loop_and_store_to_store():
    m = model(flows=[{"id": "f9", "source": "p", "target": "p", "protocol": "tls"}])
    assert ("f9", "INVALID_FLOW") in codes(m)