"""Tested the native-pointer traversal independently of an installed GDB.

Fake pointers model RuleInfo sharing and group-list pointer multiplicity.
These unit tests are not compiled Wazuh differential observations.
"""
import hashlib
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


class FakePtr:
    def __init__(self, address=0, value=None):
        self.address = address
        self.value = value

    def __int__(self):
        return self.address

    def dereference(self):
        if not self.address:
            raise AssertionError("Null pointer dereference")
        return self.value

    def __getitem__(self, index):
        return self.value[index]


def _info(address, rule_id, *, sid_prev=0, sid_search=0, group_search=0,
          group_lists=(), group_array=0):
    return FakePtr(address, {
        "sigid": rule_id,
        "sid_prev_matched": FakePtr(sid_prev),
        "sid_search": FakePtr(sid_search),
        "group_search": FakePtr(group_search),
        "group_prev_matched": FakePtr(group_array, [
            FakePtr(item) for item in group_lists
        ]),
        "group_prev_matched_sz": len(group_lists),
    })


def _node(address, info, *, child=None, next_node=None):
    return FakePtr(address, {
        "ruleinfo": info,
        "child": child or FakePtr(),
        "next": next_node or FakePtr(),
    })


def _probe(monkeypatch):
    class Breakpoint:
        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setitem(sys.modules, "gdb", SimpleNamespace(Breakpoint=Breakpoint))
    path = Path(__file__).resolve().parents[1] / "scripts" / "gdb_wazuh_41410_capture.py"
    return runpy.run_path(str(path))


def test_native_pointer_snapshot_preserves_physical_group_multiplicity(monkeypatch):
    probe = _probe(monkeypatch)
    root_info = _info(101, 1)
    other_root_info = _info(102, 2)
    source = _info(110, 100010, sid_prev=800,
                   group_array=900, group_lists=(700, 700))
    group_consumer = _info(120, 100020, group_search=700)
    sid_consumer = _info(130, 100030, sid_search=800)

    sid = _node(6, sid_consumer)
    group = _node(5, group_consumer, next_node=sid)
    source1 = _node(3, source, next_node=group)
    source2 = _node(4, source)
    root2 = _node(2, other_root_info, child=source2)
    root1 = _node(1, root_info, child=source1, next_node=root2)
    scenario = {
        "rules": [
            {"id": 1}, {"id": 2},
            {"id": 100010, "if_sid": "1,2"},
            {"id": 100020, "if_sid": "1"},
            {"id": 100030, "if_sid": "1"},
        ],
    }
    snapshot = probe["_capture"](root1, scenario)
    assert snapshot["unexpected_rule_ids"] == []
    assert snapshot["native_occurrence_count"] == 6
    assert snapshot["accepted_rules"] == [
        "1", "100010", "100020", "100030", "2",
    ]
    assert snapshot["registrations"] == [
        {"source_rule_id": "100010", "consumer_rule_id": "100020",
         "relation_type": "if_matched_group", "count": 2},
        {"source_rule_id": "100010", "consumer_rule_id": "100030",
         "relation_type": "if_matched_sid", "count": 1},
    ]
    assert sum(row["count"] for row in snapshot["attachments"]) == 4


def test_native_probe_rejects_corrupt_pointer_cycles(monkeypatch):
    probe = _probe(monkeypatch)
    root = _node(1, _info(101, 1))
    root.value["next"] = root
    with pytest.raises(RuntimeError, match="Cycle"):
        probe["_read_tree"](root)


def test_native_probe_uses_scenario_only_for_attachment_labels(monkeypatch):
    probe = _probe(monkeypatch)
    source = _node(2, _info(102, 100101))
    root = _node(1, _info(101, 1), child=source)
    scenario = {"rules": [{"id": 1}, {"id": 100101, "if_group": "audit"}]}
    result = probe["_capture"](root, scenario)
    assert result["unexpected_rule_ids"] == []
    assert result["attachments"] == [
        {"parent_rule_id": "1", "child_rule_id": "100101",
         "relation_type": "if_group", "count": 1},
    ]
    assert result["registrations"] == []


def test_gdb_probe_records_exact_loaded_rules_hash(tmp_path, monkeypatch):
    probe = _probe(monkeypatch)
    rules = tmp_path / "rules.xml"
    rules.write_bytes(b"<group name='test,'/>\n")

    class StringPointer(FakePtr):
        def string(self, errors="strict"):
            return str(rules)

    includes = FakePtr(500, [StringPointer(501), FakePtr()])
    result = probe["_loaded_rule_files"](includes)
    assert result == [{
        "path": str(rules.resolve()),
        "sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
    }]


def test_gdb_probe_rejects_missing_or_unreadable_rules(tmp_path, monkeypatch):
    probe = _probe(monkeypatch)

    class StringPointer(FakePtr):
        def string(self, errors="strict"):
            return str(tmp_path / "missing.xml")

    with pytest.raises(RuntimeError, match="no configured rules"):
        probe["_loaded_rule_files"](FakePtr())
    with pytest.raises(RuntimeError, match="cannot be read"):
        probe["_loaded_rule_files"](
            FakePtr(600, [StringPointer(601), FakePtr()])
        )
