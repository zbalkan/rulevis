import xml.etree.ElementTree as ET

from internal.catalog import RuleCatalog
from internal.evaluation import EvaluationBuilder
from internal.generator import GraphGenerator


def test_invalid_if_sid_tab_is_skipped_by_evaluator():
    catalog = RuleCatalog()
    for rule_id, level, if_sid in (
        ("1", 0, None),
        ("2", 0, None),
        ("100010", 5, "1\t2"),
    ):
        catalog.append(
            rule_id=rule_id,
            file="test.xml",
            source_level=level,
            accuracy=1,
            noalert=False,
            overwrite=False,
            runtime_group="test,",
            display_groups=[],
            category="syslog",
            if_sid=if_sid,
            if_level=None,
            if_group=None,
            if_matched_sid=None,
            if_matched_group=None,
            conditions=[],
            temporal_conditions=[],
        )

    model = EvaluationBuilder(catalog).build()

    assert "100010" not in model.rules
    assert ("INVALID_IF_SID", "100010") in {
        (issue.code, issue.rule_id) for issue in model.issues
    }


def test_invalid_if_sid_tab_is_not_visual_parent(tmp_path):
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    element = ET.fromstring(
        '<rule id="100010" level="5">'
        '<if_sid>1\t2</if_sid><description>Invalid selector</description>'
        '</rule>'
    )

    generator.parse_groups_and_rules(element, [], "test.xml", {})

    assert "100010" not in generator.G.nodes
    assert generator.catalog.declarations[0].if_sid == "1\t2"
