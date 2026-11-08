"""Regression coverage for threshold annotations and on-demand relationships."""

import pickle

from internal.visualizer import create_app

from test_visualizer import write_app_files


def make_client(tmp_path):
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
