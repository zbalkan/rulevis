import xml.etree.ElementTree as ET

import pytest

from internal.evaluation import EvaluationBuilder
from internal.generator import GraphGenerator


@pytest.mark.parametrize("raw", ["garbage", "2x", "-1", " 2 "])
def test_invalid_if_level_does_not_fall_back_to_category(tmp_path, raw):
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    group = ET.fromstring(
        '<group name="test,">'
        '<rule id="1" level="5"><description>Root</description></rule>'
        '<rule id="100021" level="6">'
        f'<if_level>{raw}</if_level><description>Invalid</description>'
        '</rule>'
        '</group>'
    )

    generator.parse_groups_and_rules(group, [], "test.xml", {})
    model = EvaluationBuilder(generator.catalog).build()

    assert "100021" not in generator.G.nodes
    assert "100021" not in model.rules
    assert ("INVALID_IF_LEVEL", "100021") in {
        (issue.code, issue.rule_id) for issue in model.issues
    }


def test_valid_if_level_remains_accepted(tmp_path):
    generator = GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"))
    group = ET.fromstring(
        '<group name="test,">'
        '<rule id="1" level="5"><description>Root</description></rule>'
        '<rule id="100022" level="6">'
        '<if_level>2</if_level><description>Valid</description>'
        '</rule>'
        '</group>'
    )

    generator.parse_groups_and_rules(group, [], "test.xml", {})
    model = EvaluationBuilder(generator.catalog).build()

    assert "100022" in generator.G.nodes
    assert "100022" in model.rules
