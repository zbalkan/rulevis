"""Historical registration precedence is visible in both API and path responses."""
import json
import pickle

from internal.generator import GraphGenerator
from internal.visualizer import create_app


def test_mixed_historical_selectors_are_annotated_in_api_and_paths(tmp_path):
    (tmp_path / "rules.xml").write_text(
        '<group name="auth,">'
        '<rule id="100990" level="5"><decoded_as>json</decoded_as>'
        '<description>Source</description></rule>'
        '</group><group name="child,">'
        '<rule id="100991" level="8" frequency="2" timeframe="60">'
        '<if_matched_sid>100990</if_matched_sid>'
        '<if_matched_group>auth</if_matched_group>'
        '<description>Mixed historical selectors</description>'
        '</rule></group>',
        encoding="utf-8",
    )
    graph_path = tmp_path / "graph.pkl"
    generator = GraphGenerator([str(tmp_path)], str(graph_path))
    generator.build_graph_from_xml()
    with graph_path.open("wb") as stream:
        pickle.dump(generator.G, stream)
    stats_path = tmp_path / "stats.json"
    stats_path.write_text(json.dumps({
        "cycles": [], "top_direct_descendants": [],
        "top_indirect_descendants": [], "top_direct_ancestors": [],
        "top_indirect_ancestors": [], "isolated_rules": [],
    }), encoding="utf-8")
    heatmap_path = tmp_path / "heatmap.json"
    heatmap_path.write_text('{"blocks":[]}', encoding="utf-8")
    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path)
    ).test_client()

    detail_response = client.get("/api/nodes?id=100991&include=details")
    assert detail_response.status_code == 200
    details = detail_response.get_json()
    assert details["historical_search"] == "if_matched_sid"
    group_parents = [
        parent for parent in details["parents"]
        if parent["relation_type"] == "if_matched_group"
    ]
    assert group_parents
    assert all(
        parent["shadowed_by"] == "if_matched_sid"
        for parent in group_parents
    )

    edge_response = client.post(
        "/api/edges", json={"ids": ["100990", "100991"]}
    )
    assert edge_response.status_code == 200
    edges = edge_response.get_json()["edges"]
    assert any(
        edge["relation_type"] == "if_matched_group"
        and edge.get("shadowed_by") == "if_matched_sid"
        for edge in edges
    )
    assert any(
        edge["relation_type"] == "if_matched_sid"
        and not edge.get("shadowed_by")
        for edge in edges
    )

    condition_response = client.get("/api/conditions?id=100991")
    assert condition_response.status_code == 200
    paths = condition_response.get_json()["paths"]
    assert any(
        edge["relation_type"] == "if_matched_group"
        and edge.get("shadowed_by") == "if_matched_sid"
        for path in paths for edge in path["edges"]
    )
    inactive_paths = [
        path for path in paths if any(
            edge.get("shadowed_by") == "if_matched_sid"
            for edge in path["edges"]
        )
    ]
    assert inactive_paths
    assert all(
        condition["scope"] == "declared_only"
        for path in inactive_paths
        for condition in path["conditions"]
        if condition["origin_rule_id"] == "100990"
    )
    assert any(
        condition["scope"] == "historical_source"
        for path in paths
        if not any(edge.get("shadowed_by") for edge in path["edges"])
        for condition in path["conditions"]
        if condition["origin_rule_id"] == "100990"
    )
