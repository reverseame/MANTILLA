"""Tests for the classifier logic in MANTILLA.py.

These need only pandas + scikit-learn; importing MANTILLA does not pull in the
native binary-analysis dependencies (that import is lazy, used only by -b).
"""
import json

import MANTILLA

FEATURES = [
    'cc', 'cost', 'size', 'stackframe', 'nbbs', 'ninst', 'edges', 'ebbs',
    'noreturn', 'outdegree', 'nlocals', 'nargs', 'entropy', 'fnc_callgraph',
]


def _func(**overrides):
    base = {k: 1 for k in FEATURES}
    base['noreturn'] = False
    base['fnc_callgraph'] = [0]
    base.update(overrides)
    return base


def test_get_feature_dict_full():
    d = MANTILLA.get_feature_dict(_func(cc=3, size=40, fnc_callgraph=[0, 0, 0]))
    assert d['cc'] == 3
    assert d['size'] == 40
    assert d['noreturn'] == 0          # bool -> int
    assert d['fnc_callgraph'] == 3     # list -> length
    assert set(d.keys()) == set(FEATURES)


def test_get_feature_dict_partial_uses_defaults():
    # An incomplete function entry must not raise; missing fields default.
    d = MANTILLA.get_feature_dict({'cc': 7, 'size': 12})
    assert d['cc'] == 7 and d['size'] == 12
    assert d['cost'] == 0 and d['nargs'] == 0
    assert d['entropy'] == -1          # entropy sentinel default
    assert d['fnc_callgraph'] == 0


def test_get_features_test_skips_file_key(tmp_path):
    data = {
        'file': {'file_name': 'whatever'},
        'f0': _func(cc=2),
        'f1': _func(cc=5),
    }
    p = tmp_path / "b.json"
    p.write_text(json.dumps(data))
    feats = MANTILLA.get_features_test([str(p)])
    assert len(feats) == 2             # 'file' entry excluded
    assert all(set(f.keys()) == set(FEATURES) for f in feats)


def _write_model(tmp_path):
    # Two classes well separated in 'size'. Rows within a class are made
    # distinct via 'cc' so train_knn_model's drop_duplicates() keeps them all.
    rows = [",".join(FEATURES) + ",label"]
    for size, label in ((1, "classA"), (1000, "classB")):
        for i in range(1, 6):
            vals = ["1"] * len(FEATURES)
            vals[FEATURES.index('size')] = str(size)
            vals[FEATURES.index('cc')] = str(i)
            rows.append(",".join(vals) + "," + label)
    p = tmp_path / "model.csv"
    p.write_text("\n".join(rows) + "\n")
    return str(p)


def test_train_and_classify_roundtrip(tmp_path):
    model, _, y = MANTILLA.train_knn_model(_write_model(tmp_path), 3, "euclidean")
    near_a = MANTILLA.get_feature_dict(_func(size=1))
    near_b = MANTILLA.get_feature_dict(_func(size=1000))
    ra = MANTILLA.classify_file(model, [near_a], y, threshold=None)
    rb = MANTILLA.classify_file(model, [near_b], y, threshold=None)
    assert set(ra["predictions"]) == {"classA"}
    assert set(rb["predictions"]) == {"classB"}


def test_classify_threshold_semantics(tmp_path):
    model, _, y = MANTILLA.train_knn_model(_write_model(tmp_path), 3, "euclidean")
    far = MANTILLA.get_feature_dict(_func(size=500))   # ~499 away from class A
    # None and negative disable filtering -> all k neighbors vote.
    assert len(MANTILLA.classify_file(model, [far], y, threshold=None)["predictions"]) == 3
    assert len(MANTILLA.classify_file(model, [far], y, threshold=-1)["predictions"]) == 3
    # A tiny threshold filters out the far point's neighbors entirely.
    assert MANTILLA.classify_file(model, [far], y, threshold=0.5)["predictions"] == []


def test_classify_empty_input(tmp_path):
    model, _, y = MANTILLA.train_knn_model(_write_model(tmp_path), 3, "euclidean")
    assert MANTILLA.classify_file(model, [], y, threshold=None)["predictions"] == []
