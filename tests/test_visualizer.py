import json
import pickle

import networkx as nx
import pytest

from internal.visualizer import (
    PRECOMPUTED_HEATMAPS,
    create_app,
    parse_start,
    precompute_heatmaps,
)


def write_app_files(tmp_path):
    graph = nx.MultiDiGraph()
    graph.add_node(
        "0",
        description="Synthetic root node",
        groups=["__meta__"],
        temporal=False,
        conditions=[],
    )
    graph.add_node(
        "100001",
        description="Atomic parent",
        groups=["example"],
        level="3",
        file="rules.xml",
        temporal=False,
        conditions=[{"tag": "decoded_as", "value": "json"}],
    )
    graph.add_node(
        "100002",
        description="Atomic child",
        groups=["example"],
        level="5",
        file="rules.xml",
        temporal=False,
        conditions=[
            {"tag": "if_sid", "value": "100001"},
            {
                "tag": "field",
                "value": "^deny$",
                "attributes": {"name": "event.action"},
            },
        ],
    )
    graph.add_node(
        "100003",
        description="Temporal rule",
        groups=["example"],
        mitre=["T1110", "T1059.001"],
        level="8",
        file="rules.xml",
        temporal=True,
        conditions=[],
    )
    graph.add_node(
        "100004",
        description="Atomic child of temporal rule",
        groups=["example"],
        level="6",
        file="rules.xml",
        temporal=False,
        conditions=[{"tag": "if_sid", "value": "100003"}],
    )

    graph.add_edge("0", "100001", relation_type="root")
    graph.add_edge("100001", "100002", relation_type="if_sid")
    graph.add_edge("100001", "100003", relation_type="if_matched_sid")
    graph.add_edge("100003", "100004", relation_type="if_sid")

    for node_id in graph.nodes:
        graph.nodes[node_id]["children_ids"] = list(
            graph.successors(node_id)
        )

    graph_path = tmp_path / "graph.pickle"
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    stats = {
        "cycles": [],
        "self_loops": [],
        "top_direct_descendants": [],
        "top_indirect_descendants": [],
        "top_direct_ancestors": [],
        "top_indirect_ancestors": [],
        "isolated_rules": [],
    }
    stats_path = tmp_path / "stats.json"
    stats_path.write_text(json.dumps(stats), encoding="utf-8")

    heatmap = {
        "metadata": {
            "block_size": 10,
            "max_id": 100010,
            "total_blocks": 2,
        },
        "blocks": [
            {"id": "100000-100009", "count": 4},
            {"id": "100010-100019", "count": 0},
        ],
    }
    heatmap_path = tmp_path / "heatmap.json"
    heatmap_path.write_text(json.dumps(heatmap), encoding="utf-8")

    PRECOMPUTED_HEATMAPS.clear()
    return graph_path, stats_path, heatmap_path


@pytest.mark.parametrize(
    "value,expected",
    [
        ("100-199", 100),
        ("100–199", 100),
        (" 42 ", 42),
        ("invalid", 0),
        ("", 0),
    ],
)
def test_parse_start(value, expected):
    assert parse_start(value) == expected


def test_precompute_heatmaps_aggregates_blocks():
    PRECOMPUTED_HEATMAPS.clear()
    precompute_heatmaps(
        [
            {"id": "0-9", "count": 3},
            {"id": "10-19", "count": 2},
        ]
    )

    blocks = {
        block["id"]: block["count"]
        for block in PRECOMPUTED_HEATMAPS[10]["blocks"]
    }
    assert blocks == {"0-9": 3, "10-19": 2}


def test_create_app_requires_all_input_files(tmp_path):
    with pytest.raises(FileNotFoundError):
        create_app(
            str(tmp_path / "missing-graph"),
            str(tmp_path / "missing-stats"),
            str(tmp_path / "missing-heatmap"),
        )


def test_root_and_details_endpoints(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    root_response = client.get("/api/nodes?mode=root")
    assert root_response.status_code == 200
    root_payload = root_response.get_json()
    assert {node["id"] for node in root_payload["nodes"]} == {
        "0",
        "100001",
    }
    assert "_temporal_parent" not in root_payload["nodes"][0]

    detail_response = client.get(
        "/api/nodes?id=100003&neighbors=both&include=details"
    )
    assert detail_response.status_code == 200
    details = detail_response.get_json()
    assert details["temporal"] is True
    assert details["mitre"] == ["T1110", "T1059.001"]
    assert details["parents"] == [
        {
            "id": "100001",
            "relation_type": "if_matched_sid",
            "selector": None,
        }
    ]


def test_temporal_rule_condition_paths_are_resolved(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.nodes["100003"]["temporal_conditions"] = [
        {
            "tag": "frequency",
            "value": "4",
            "kind": "rule_attribute",
        },
        {
            "tag": "timeframe",
            "value": "60",
            "kind": "rule_attribute",
        },
        {"tag": "if_matched_sid", "value": "100001"},
    ]
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get("/api/conditions?id=100003")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["condition_type"] == "temporal"
    assert payload["clock_temporal"] is True
    assert [path["nodes"] for path in payload["paths"]] == [
        ["0", "100001", "100003"]
    ]
    assert [
        (row["origin_rule_id"], row["scope"], row["tag"])
        for row in payload["paths"][0]["conditions"]
    ] == [
        ("100001", "historical_source", "decoded_as"),
        ("100003", "temporal", "frequency"),
        ("100003", "temporal", "timeframe"),
    ]


@pytest.mark.parametrize(
    "url,status",
    [
        ("/api/conditions", 400),
        ("/api/conditions?id=missing", 404),
        ("/api/conditions?id=0", 400),
        ("/api/nodes?mode=search", 400),
    ],
)
def test_api_validation_errors(tmp_path, url, status):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    assert client.get(url).status_code == status


def test_index_contains_conditions_modal(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="conditionsModal"' in html
    assert 'id="conditionsCloseBtn"' in html
    assert 'id="conditionsBody"' in html


def test_details_preserve_parallel_parent_relationships(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.add_edge(
        "100001",
        "100002",
        relation_type="if_group",
        selector="example",
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get(
        "/api/nodes?id=100002&neighbors=both&include=details"
    )

    assert response.status_code == 200
    parents = response.get_json()["parents"]
    assert parents == [
        {
            "id": "100001",
            "relation_type": "if_sid",
            "selector": None,
        },
        {
            "id": "100001",
            "relation_type": "if_group",
            "selector": "example",
        },
    ]


def test_atomic_conditions_endpoint_returns_all_paths(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.add_node(
        "100005",
        description="Second parent",
        groups=["example"],
        level="3",
        file="rules.xml",
        temporal=False,
        conditions=[{"tag": "match", "value": "second"}],
    )
    graph.add_edge("0", "100005", relation_type="root")
    graph.add_edge(
        "100005",
        "100002",
        relation_type="if_group",
        selector="example",
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    payload = response.get_json()
    assert [path["nodes"] for path in payload["paths"]] == [
        ["0", "100001", "100002"],
        ["0", "100005", "100002"],
    ]


def test_atomic_condition_paths_include_flattened_rows(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    path = response.get_json()["paths"][0]
    assert path["condition_count"] == 2
    assert [
        (row["origin_rule_id"], row["tag"])
        for row in path["conditions"]
    ] == [
        ("100001", "decoded_as"),
        ("100002", "field"),
    ]


def test_temporal_conditions_do_not_require_clock_classification(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.nodes["100002"]["temporal"] = False
    graph.nodes["100002"]["temporal_conditions"] = [
        {"tag": "check_diff", "value": ""},
    ]
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["clock_temporal"] is False
    assert payload["condition_type"] == "temporal"
    assert (
        payload["paths"][0]["conditions"][-1]["tag"]
        == "check_diff"
    )
    assert (
        payload["paths"][0]["conditions"][-1]["scope"]
        == "temporal"
    )


def test_atomic_condition_api_reports_analysis_and_clock_types(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["condition_type"] == "atomic"
    assert payload["clock_temporal"] is False


def test_if_matched_rule_can_be_temporal_analysis_without_clock(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.nodes["100003"]["temporal"] = False
    graph.nodes["100003"]["temporal_conditions"] = [
        {"tag": "if_matched_sid", "value": "100001"},
    ]
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get("/api/conditions?id=100003")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["clock_temporal"] is False
    assert payload["condition_type"] == "temporal"
    assert [path["nodes"] for path in payload["paths"]] == [
        ["0", "100001", "100003"]
    ]
    assert payload["paths"][0]["conditions"][0]["scope"] == (
        "historical_source"
    )


def test_index_documents_declared_if_level_path_scope(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<code>if_level</code>" in html
    assert "source-level possibilities" in html
    assert "intentionally not modeled" not in html


def test_conditions_api_marks_subsumed_field_constraint(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths

    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.nodes["100001"]["conditions"] = [
        {
            "tag": "field",
            "value": "^root$|^admin$|^administrator$",
            "attributes": {"name": "user"},
        }
    ]
    graph.nodes["100002"]["conditions"] = [
        {"tag": "if_sid", "value": "100001"},
        {
            "tag": "field",
            "value": "^admin$",
            "attributes": {"name": "user"},
        },
    ]
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path),
        str(stats_path),
        str(heatmap_path),
    ).test_client()
    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    rows = response.get_json()["paths"][0]["conditions"]
    assert rows[0]["resolution_status"] == "subsumed"
    assert rows[0]["resolution_note"] == "Subsumed by rule 100002"
    assert "resolution_status" not in rows[1]


def test_conditions_api_surfaces_truncation(tmp_path, monkeypatch):
    from internal.conditions import PathResults

    paths = PathResults()
    paths.truncated = True
    monkeypatch.setattr(
        "internal.visualizer.resolve_atomic_paths",
        lambda graph, target_id: paths,
    )
    app_files = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in app_files)).test_client()
    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    assert response.get_json()["paths_truncated"] is True


def test_group_parent_details_identify_scan_order_candidates(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.add_edge(
        "100001", "100002", relation_type="if_group",
        selector="parent", load_order_candidate=False,
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path)
    ).test_client()
    response = client.get(
        "/api/nodes?id=100002&neighbors=both&include=details"
    )

    assert response.status_code == 200
    parents = response.get_json()["parents"]
    assert any(
        p["relation_type"] == "if_group"
        and p["load_order_candidate"] is False
        for p in parents
    )
    assert any(
        p["relation_type"] == "if_sid"
        and "load_order_candidate" not in p
        for p in parents
    )


def test_details_expose_synthesized_structural_relationship(tmp_path):
    paths = write_app_files(tmp_path)
    graph_path, stats_path, heatmap_path = paths
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    graph.add_edge(
        "100001", "100003", relation_type="if_sid",
        selector="100001", synthesized_from="if_matched_sid",
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path)
    ).test_client()
    response = client.get(
        "/api/nodes?id=100003&neighbors=both&include=details"
    )

    assert response.status_code == 200
    parents = response.get_json()["parents"]
    assert any(
        row["relation_type"] == "if_sid"
        and row["synthesized_from"] == "if_matched_sid"
        for row in parents
    )


def test_conditions_modal_includes_if_level_as_declared_relationship(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()
    html = client.get("/").get_data(as_text=True)

    assert "if_level</code> is intentionally not modeled" not in html
    assert "<code>if_level</code>" in html
    assert "declared" in html.lower()


def test_ui_exposes_wazuh_correlation_warnings(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)

    # Source is declared after the dependent: no retroactive if_group link.
    graph.add_edge(
        "100004", "100002", relation_type="if_group",
        load_order_candidate=False, selector="example",
    )
    # An earlier source has simultaneous historical SID and group consumers.
    graph.add_edge(
        "100001", "100004", relation_type="if_matched_group",
        load_order_candidate=True, selector="example",
    )
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path)
    ).test_client()

    html = client.get("/").get_data(as_text=True)
    assert 'id="correlationNotice"' in html
    assert "Upstream issue #41279" in html
    assert "not verified manager behavior" in html

    root = client.get("/api/nodes?mode=root").get_json()
    parent = next(node for node in root["nodes"] if node["id"] == "100001")
    assert parent["correlation_warning_count"] == 1

    detail = client.get(
        "/api/nodes?id=100002&neighbors=both&include=details"
    ).get_json()
    assert any(warning["code"] == "GROUP_LOAD_ORDER"
               for warning in detail["correlation_warnings"])

    detail = client.get(
        "/api/nodes?id=100004&neighbors=both&include=details"
    ).get_json()
    assert {w["code"] for w in detail["correlation_warnings"]} == {
        "GROUP_LOAD_ORDER", "DUAL_HISTORY"
    }


def test_ui_does_not_flag_unrelated_rules(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'id="correlationNotice"' not in html
    detail = client.get(
        "/api/nodes?id=100002&neighbors=both&include=details"
    ).get_json()
    assert detail["correlation_warnings"] == []


def test_group_only_declaration_shows_upstream_notice_without_specific_warning(tmp_path):
    graph_path, stats_path, heatmap_path = write_app_files(tmp_path)
    with graph_path.open("rb") as stream:
        graph = pickle.load(stream)
    graph.nodes["100002"]["selector_precedence"] = {"effective": "if_group"}
    with graph_path.open("wb") as stream:
        pickle.dump(graph, stream)

    client = create_app(
        str(graph_path), str(stats_path), str(heatmap_path)
    ).test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'id="correlationNotice"' in html
    assert "No specific scan-order risk was identified" in html
    assert client.get(
        "/api/nodes?id=100002&include=details"
    ).get_json()["correlation_warnings"] == []
