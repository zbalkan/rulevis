"""Regression coverage for threshold annotations and on-demand relationships."""

import pickle

from internal.visualizer import create_app

from test_visualizer import write_app_files


def make_client(tmp_path, extra_structural=False):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.nodes["100004"]["if_level"] = "5"
    graph.add_edge(
        "100001", "100004", relation_type="if_level",
        selector="5", load_order_candidate=True,
    )
    graph.add_edge(
        "100003", "100004", relation_type="if_level",
        selector="5", load_order_candidate=False,
    )
    if extra_structural:
        graph.add_edge(
            "100003", "100004", relation_type="if_group",
            selector="example",
        )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    return create_app(
        str(graph_path), str(stats_path), str(heatmap_path),
    ).test_client()


def test_default_graph_omits_threshold_edges_but_keeps_other_edges(tmp_path):
    client = make_client(tmp_path)
    response = client.post(
        "/api/edges",
        json={"ids": ["100001", "100003", "100004"]},
    )
    assert response.status_code == 200
    edges = response.get_json()["edges"]
    assert all(edge["relation_type"] != "if_level" for edge in edges)
    assert any(edge["relation_type"] == "if_sid" for edge in edges)


def test_node_metadata_includes_threshold_without_changing_rule_level(tmp_path):
    client = make_client(tmp_path)
    response = client.get("/api/nodes?mode=search&id=100004")
    assert response.status_code == 200
    node = response.get_json()["nodes"][0]
    assert node["level"] == "6"
    assert node["if_level"] == "5"


def test_level_overlay_only_returns_displayed_parent_candidates(tmp_path):
    client = make_client(tmp_path)
    response = client.get(
        "/api/level-parents?id=100004&displayed=100001,100004"
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["selector"] == "5"
    assert payload["candidate_count"] == 2
    assert payload["edges"] == [
        {
            "source": "100001", "target": "100004",
            "relation_type": "if_level", "selector": "5",
            "load_order_candidate": True,
        }
    ]


def test_overlay_does_not_return_unrelated_relationships(tmp_path):
    client = make_client(tmp_path)
    response = client.get(
        "/api/level-parents?id=100004&displayed=100001,100003,100004"
    )
    assert response.status_code == 200
    edges = response.get_json()["edges"]
    assert len(edges) == 2
    assert all(edge["relation_type"] == "if_level" for edge in edges)


def test_overlay_rejects_unknown_and_non_threshold_rules(tmp_path):
    client = make_client(tmp_path)
    assert client.get("/api/level-parents?id=missing").status_code == 404
    assert client.get("/api/level-parents?id=100001").status_code == 400


def test_details_include_threshold_for_low_zoom_panel_control(tmp_path):
    client = make_client(tmp_path)
    response = client.get(
        "/api/nodes?id=100004&neighbors=both&include=details"
    )
    assert response.status_code == 200
    details = response.get_json()
    assert details["if_level"] == "5"
    assert details["level"] == "6"


def test_parallel_if_level_does_not_duplicate_structural_edges(tmp_path):
    client = make_client(tmp_path)
    expected = [
        {"source": "100003", "target": "100004", "relation_type": "if_sid"}
    ]
    response = client.post(
        "/api/edges", json={"ids": ["100003", "100004"]}
    )
    assert response.status_code == 200
    assert response.get_json()["edges"] == expected

    response = client.get(
        "/api/nodes?ids=100003,100004&displayed=100003,100004"
    )
    assert response.status_code == 200
    assert response.get_json()["edges"] == expected


def test_multiple_parallel_structural_edges_appear_once_each(tmp_path):
    client = make_client(tmp_path, extra_structural=True)
    expected = [
        {"source": "100003", "target": "100004", "relation_type": "if_sid"},
        {"source": "100003", "target": "100004", "relation_type": "if_group"},
    ]
    response = client.post(
        "/api/edges", json={"ids": ["100003", "100004"]}
    )
    assert response.status_code == 200
    assert response.get_json()["edges"] == expected

    response = client.get(
        "/api/nodes?ids=100003,100004&displayed=100003,100004"
    )
    assert response.status_code == 200
    assert response.get_json()["edges"] == expected


def test_threshold_only_children_do_not_expand_structural_graph(tmp_path):
    client = make_client(tmp_path)
    # 100001 has a declared level link to 100004, but its other
    # structural children are 100002 and 100003.
    response = client.get(
        "/api/nodes?mode=search&id=100001&displayed=100002,100003"
    )
    assert response.status_code == 200
    node = response.get_json()["nodes"][0]
    assert node["children_ids"] == ["100002", "100003"]
    assert node["expandable"] is False

    response = client.get(
        "/api/nodes?id=100001&neighbors=children&displayed=100001"
    )
    assert response.status_code == 200
    nodes = response.get_json()["nodes"]
    assert "100004" not in {node["id"] for node in nodes}


def test_threshold_only_parent_is_not_returned_in_normal_expansion(tmp_path):
    client = make_client(tmp_path)
    response = client.get(
        "/api/nodes?id=100004&neighbors=parents&displayed=100004"
    )
    assert response.status_code == 200
    assert {node["id"] for node in response.get_json()["nodes"]} == {
        "100004", "100003"
    }
    response = client.get(
        "/api/nodes?id=100004&neighbors=both&include=details"
    )
    assert response.status_code == 200
    parents = response.get_json()["parents"]
    assert all(parent["relation_type"] != "if_level" for parent in parents)


def test_threshold_only_parent_does_not_make_a_node_expandable(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.add_edge(
        "100004", "100002", relation_type="if_level",
        selector="5", load_order_candidate=True,
    )
    graph.nodes["100002"]["if_level"] = "5"
    # Add a rule with no structural successors, only a threshold successor.
    graph.add_node(
        "100099", description="Threshold-only parent",
        level="7", children_ids=["100002"], temporal=False,
    )
    graph.add_edge(
        "100099", "100002", relation_type="if_level",
        selector="5", load_order_candidate=True,
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path),
    ).test_client()
    response = client.get("/api/nodes?mode=search&id=100099")
    assert response.status_code == 200
    node = response.get_json()["nodes"][0]
    assert node["children_ids"] == []
    assert node["expandable"] is False
    response = client.get("/api/nodes?id=100099&neighbors=children")
    assert response.status_code == 200
    assert [node["id"] for node in response.get_json()["nodes"]] == ["100099"]


def test_details_report_declared_and_load_order_level_parent_counts(tmp_path):
    client = make_client(tmp_path)
    response = client.get("/api/nodes?id=100004&include=details")
    assert response.status_code == 200
    details = response.get_json()
    assert details["level_parents"]["declared"] == 2
    assert details["level_parents"]["load_order_candidates"] == 1


def test_shadowed_if_group_is_identified_in_details(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.nodes["100004"]["if_level"] = "5"
    graph.nodes["100004"]["selector_precedence"] = {
        "effective": "if_level",
        "shadowed": ["if_group"],
    }
    graph.add_edge(
        "100001", "100004", relation_type="if_group", selector="example",
    )
    graph.add_edge(
        "100001", "100004", relation_type="if_level", selector="5",
        load_order_candidate=True,
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    client = create_app(str(graph_path), str(stats_path), str(heatmap_path)).test_client()
    response = client.get("/api/nodes?id=100004&include=details")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["selector_precedence"]["effective"] == "if_level"
    group_parents = [row for row in payload["parents"] if row["relation_type"] == "if_group"]
    assert len(group_parents) == 1
    assert group_parents[0]["shadowed_by"] == "if_level"


def test_shadowed_level_selector_cannot_be_activated_as_overlay(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.nodes["100004"]["if_level"] = "5"
    graph.nodes["100004"]["selector_precedence"] = {
        "effective": "if_sid", "shadowed": ["if_level"],
    }
    graph.add_edge(
        "100001", "100004", relation_type="if_level", selector="5",
        load_order_candidate=True,
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    client = create_app(str(graph_path), str(stats_path), str(heatmap_path)).test_client()
    response = client.get("/api/level-parents?id=100004&displayed=100001,100004")
    assert response.status_code == 400


def test_zero_level_selector_is_not_an_eligible_overlay(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.nodes["100004"]["if_level"] = "0"
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)
    client = create_app(str(graph_path), str(stats_path), str(heatmap_path)).test_client()
    response = client.get("/api/level-parents?id=100004")
    assert response.status_code == 400
