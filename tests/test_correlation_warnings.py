"""Regression coverage for Wazuh 4.14.10 group-correlation UI warnings."""

import networkx as nx

from internal.correlation_warnings import correlation_warnings


def test_late_group_sources_warn_at_both_ends():
    graph = nx.MultiDiGraph()
    graph.add_node("1", file="rules.xml")
    graph.add_node("100100", file="rules.xml", selector_precedence={"effective": "if_group"})
    graph.add_node("100110", file="rules.xml", historical_search="if_matched_group")
    graph.add_node("100120", file="rules.xml")
    graph.add_edge("1", "100100", relation_type="if_group", load_order_candidate=True)
    graph.add_edge("100120", "100100", relation_type="if_group", load_order_candidate=False)
    graph.add_edge("100120", "100110", relation_type="if_matched_group", load_order_candidate=False)

    warnings = correlation_warnings(graph)

    assert {warning["code"] for warning in warnings["100100"]} == {"GROUP_LOAD_ORDER"}
    assert {warning["code"] for warning in warnings["100110"]} == {"TEMPORAL_GROUP_LOAD_ORDER"}
    assert {warning["code"] for warning in warnings["100120"]} == {
        "GROUP_LOAD_ORDER", "TEMPORAL_GROUP_LOAD_ORDER"
    }
    assert "1" not in warnings
    assert all("100120" in warning["message"] for warning in warnings["100100"] + warnings["100110"])


def test_dual_history_warns_source_and_group_consumer():
    graph = nx.MultiDiGraph()
    graph.add_node("100100", file="rules.xml")
    graph.add_node("100200", file="rules.xml", historical_search="if_matched_sid")
    graph.add_node("100300", file="rules.xml", historical_search="if_matched_group")
    graph.add_edge("100100", "100200", relation_type="if_matched_sid")
    graph.add_edge("100100", "100300", relation_type="if_matched_group", load_order_candidate=True)

    warnings = correlation_warnings(graph)

    assert [warning["code"] for warning in warnings["100100"]] == ["DUAL_HISTORY"]
    assert [warning["code"] for warning in warnings["100300"]] == ["DUAL_HISTORY"]
    assert "100200" not in warnings
    assert "100200" in warnings["100100"][0]["message"]


def test_shadowed_and_out_of_order_subscriptions_do_not_imply_dual_history():
    graph = nx.MultiDiGraph()
    graph.add_node("100200", file="rules.xml", historical_search="if_matched_sid")
    graph.add_node("100100", file="rules.xml")
    graph.add_node("100300", file="rules.xml", historical_search="if_matched_group")
    graph.add_edge("100100", "100200", relation_type="if_matched_sid")
    graph.add_edge("100100", "100300", relation_type="if_matched_group", load_order_candidate=True)
    assert correlation_warnings(graph) == {}

    # An inactive, shadowed group selector is not a group subscriber.
    shadowed = nx.MultiDiGraph()
    shadowed.add_node("100100", file="rules.xml")
    shadowed.add_node("100400", file="rules.xml", historical_search="if_matched_sid")
    shadowed.add_edge("100100", "100400", relation_type="if_matched_sid")
    shadowed.add_edge("100100", "100400", relation_type="if_matched_group",
                      load_order_candidate=True, shadowed_by="if_matched_sid")
    assert correlation_warnings(shadowed) == {}


def test_graph_with_no_group_correlations_has_no_warnings():
    graph = nx.MultiDiGraph()
    graph.add_edge("1", "2", relation_type="if_sid")
    assert correlation_warnings(graph) == {}
