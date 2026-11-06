"""An explicit manifest preserves the Wazuh-configured rules file order."""
from internal.generator import GraphGenerator


def test_explicit_file_sequence_is_not_sorted(tmp_path):
    early = tmp_path / "z-parent.xml"
    late = tmp_path / "a-child.xml"
    early.write_text('<group name="parent,"><rule id="100001" level="3">'
                     '<description>Root</description></rule></group>',
                     encoding="utf-8")
    late.write_text('<group name="child,"><rule id="100002" level="3">'
                    '<if_group>parent</if_group><description>Child</description>'
                    '</rule></group>', encoding="utf-8")
    generator = GraphGenerator(
        paths=[str(tmp_path)],
        graph_file=str(tmp_path / "graph.pickle"),
        rule_files=[str(early), str(late)],
    )

    assert generator.get_all_xml_files() == [str(early), str(late)]

    generator.build_graph_from_xml()
    assert [rule.file for rule in generator.catalog.declarations] == [
        "z-parent.xml", "a-child.xml"
    ]


def test_explicit_file_sequence_rejects_missing_files(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        GraphGenerator([str(tmp_path)], str(tmp_path / "graph.pickle"),
                       rule_files=[str(tmp_path / "missing.xml")]).get_all_xml_files()
