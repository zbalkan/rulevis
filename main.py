from typing import Any, Optional
import xml.etree.ElementTree as ET
import networkx as nx
from networkx import DiGraph
from pyvis.network import Network
from collections import defaultdict
import os

# List of directory paths to search for XML files
# Add your directory paths here
PATHS: list[str] = [
    'C:\\Users\\zafer\\source\\repos\\Personal\\wazuh\\ruleset\\rules']

# Function to enumerate all XML files in the given paths


def get_all_xml_files(paths: list[str], size: int = 0) -> list[str]:
    xml_files: list[str] = []
    for path in paths:
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.xml'):
                    xml_files.append(os.path.join(root, file))

    print(f'Found {len(xml_files)} XML files in the given paths')
    if size > 0:
        return xml_files[:size]
    else:
        return xml_files

# Recursive function to parse groups and rules


def parse_groups_and_rules(element: ET.Element, inherited_groups: list[str], G: DiGraph, group_membership: dict[str, list[str]]) -> None:
    # If the current element is a rule
    if element.tag == 'rule':
        rule_id = element.get('id', '0')
        if_sid = element.findtext('if_sid', None)
        if_matched_sid = element.findtext('if_matched_sid', None)
        if_group = element.findtext('if_group', None)
        if_matched_group = element.findtext('if_matched_group', None)

        # Get the groups attribute from the rule, if present
        rule_groups: Any = element.get('groups', None)
        all_groups: list[str]

        # Combine inherited groups with rule's own groups
        if rule_groups is None:
            all_groups = inherited_groups
        else:
            all_groups = list(
                filter(None, inherited_groups + rule_groups.split(',')))

        # Add the rule node with all groups as a node attribute
        G.add_node(rule_id, groups=all_groups)

        # Track which rules belong to which groups
        for group in all_groups:
            group_membership[group].append(rule_id)

        # Add parent-child relationships based on if_sid and if_matched_sid
        if if_sid:
            G.add_edge(if_sid, rule_id, relation_type='if_sid')
        if if_matched_sid:
            G.add_edge(if_matched_sid, rule_id, relation_type='if_matched_sid')

        # Add relationships based on if_group and if_matched_group
        if if_group:
            for group in if_group.split(','):
                # Add edges from all rules in this group to the current rule
                for parent_rule in group_membership.get(group, []):
                    G.add_edge(parent_rule, rule_id, relation_type='if_group')

        if if_matched_group:
            for group in if_matched_group.split(','):
                # Add edges from all rules in this group to the current rule
                for parent_rule in group_membership.get(group, []):
                    G.add_edge(parent_rule, rule_id,
                               relation_type='if_matched_group')

    # If the current element is a group or contains groups, recurse further
    elif element.tag == 'groups':
        # Get any group information from this groups tag
        group_attribute = element.get('groups', '')
        # Combine the inherited groups with the current groups attribute
        new_inherited_groups = inherited_groups + group_attribute.split(',')

        # Recursively parse children of this group
        for child in element:
            parse_groups_and_rules(
                child, new_inherited_groups, G, group_membership)

# Function to parse XML and build the relationship graph


def build_graph_from_xml(paths: list[str]) -> DiGraph:
    G = nx.DiGraph()  # Use a directed graph to maintain parent-child relationships
    # Track rules belonging to each group
    group_membership: dict[str, list[str]] = defaultdict(list)  # type: ignore

    # Get all XML files from the given paths
    xml_files: list[str] = get_all_xml_files(paths, size=20)

    # Parse each XML file
    for xml_file in xml_files:
        # Read the content of the XML file
        with open(xml_file, 'r', encoding='utf8') as f:
            xml_content: str = f.read()

        # Wrap the content with a root element
        wrapped_content: str = wrap_with_root(xml_content)

        root: Optional[ET.Element] = None
        try:
            # Parse the modified XML content
            parsed_xml: ET.Element = ET.fromstring(wrapped_content)
            tree = ET.ElementTree(parsed_xml)
            root = tree.getroot()
        except Exception as e:
            print(f"Error parsing {xml_file}: {e}")

        # Parse the XML to build relationships, passing an empty inherited_groups list

        if root is not None:
            for child in root.iter():
                parse_groups_and_rules(child, [], G, group_membership)

    return G

# Function to wrap XML content with a temporary root element


def wrap_with_root(xml_content: str) -> str:
    return f"<root>{xml_content}</root>"

# Function to visualize the graph interactively using pyvis with HTML controls


def visualize_graph_interactive_with_controls(G: DiGraph) -> None:
    net = Network(height="800px", width="100%", directed=True, neighborhood_highlight=True,
                  select_menu=True, filter_menu=True, heading='Wazuh Ruleset Graph')

    # Add nodes to the pyvis network
    for node, data in G.nodes(data=True):
        net.add_node(
            node, label=f"{node}\nGroups: {','.join(data.get('groups', []))}")

    # Add edges with their relation_type attribute
    for source, target, edge_data in G.edges(data=True):
        relation_type = edge_data.get('relation_type')
        net.add_edge(
            source, target, title=f"Type: {relation_type}", relation_type=relation_type)

    # Set options for better visualization
    net.set_options("""
    var options = {
      "nodes": {
        "shape": "dot",
        "size": 10,
        "font": {
          "size": 14
        }
      },
      "edges": {
        "arrows": {
          "to": {
            "enabled": true
          }
        }
      },
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100
        },
        "minVelocity": 0.75
      },
	  "layout": {
	    "randomSeed": 191006,
	    "improvedLayout": false
	  }
    }
    """)

    # Generate the network and insert it into the HTML template
    net.show("interactive_graph_with_controls.html",
             local=True, notebook=False)


# Build the graph
G: DiGraph = build_graph_from_xml(PATHS)

# Visualize the graph interactively with HTML controls
visualize_graph_interactive_with_controls(G)
