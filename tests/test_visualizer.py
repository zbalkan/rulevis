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
        _temporal_parent=False,
    )
    graph.add_node(
        "100001",
        description="Atomic parent",
        groups=["example"],
        level="3",
        file="rules.xml",
        temporal=False,
        conditions=[{"tag": "decoded_as", "value": "json"}],
        _temporal_parent=False,
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
        _temporal_parent=False,
    )
    graph.add_node(
        "100003",
        description="Temporal rule",
        groups=["example"],
        level="8",
        file="rules.xml",
        temporal=True,
        conditions=[],
        _temporal_parent=True,
    )
    graph.add_node(
        "100004",
        description="Atomic child of temporal rule",
        groups=["example"],
        level="6",
        file="rules.xml",
        temporal=False,
        conditions=[{"tag": "if_sid", "value": "100003"}],
        _temporal_parent=False,
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
    assert details["parents"] == [
        {"id": "100001", "relation_type": "if_matched_sid"}
    ]


def test_atomic_condition_tree_reaches_virtual_root(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/api/conditions?id=100002")

    assert response.status_code == 200
    tree = response.get_json()["tree"]
    assert tree["id"] == "100002"
    assert tree["inherited"] is False

    parent = tree["parents"][0]
    assert parent["id"] == "100001"
    assert parent["relation_type"] == "if_sid"
    assert parent["inherited"] is True

    root = parent["parents"][0]
    assert root["id"] == "0"
    assert root["relation_type"] == "root"


def test_temporal_rule_condition_expansion_is_rejected(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/api/conditions?id=100003")

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "Condition expansion is available only for atomic rules"
    )


def test_atomic_trace_stops_at_temporal_parent(tmp_path):
    paths = write_app_files(tmp_path)
    client = create_app(*(str(path) for path in paths)).test_client()

    response = client.get("/api/conditions?id=100004")

    assert response.status_code == 200
    parent = response.get_json()["tree"]["parents"][0]
    assert parent["id"] == "100003"
    assert parent["temporal"] is True
    assert parent["temporal_boundary"] is True
    assert parent["parents"] == []


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
    assert path["condition_count"] == 3
    assert [
        (row["origin_rule_id"], row["tag"])
        for row in path["conditions"]
    ] == [
        ("100001", "decoded_as"),
        ("100002", "if_sid"),
        ("100002", "field"),
    ]
