#!/usr/bin/python3
# -*- coding: utf-8 -*-
# main.py

import argparse
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Final, Optional

import networkx as nx
from networkx import MultiDiGraph
from pyvis.network import Network

ENCODING: Final[str] = "utf-8"
APP_NAME: Final[str] = 'rulevis'
APP_VERSION: Final[str] = '0.1'
DESCRIPTION: Final[str] = f"{APP_NAME} ({APP_VERSION}) is a Wazuh rule visualization tool."


def get_all_xml_files(paths: list[str], top: int = 0) -> list[str]:
    """
        Function to enumerate all XML files in the given paths
    Args:
        paths (list[str]): List to directories to search for Wazuh rule files.
        top (int, optional): Top N files to pick from the files found. Defaults to 0, means all files.

    Returns:
        list[str]: List of Wazuh rule files found in the given paths.
    """
    xml_files: list[str] = []
    for path in paths:
        for root, _, files in os.walk(path):
            for file in files:
                if file.lower().endswith('.xml'):
                    xml_files.append(os.path.join(root, file))

    print(f'Found {len(xml_files)} XML files in the given paths')
    logging.info(f'Found {len(xml_files)} XML files in the given paths')
    if top > 0:
        logging.info(f'Picking {top} files...')
        return xml_files[:top]
    else:
        logging.info('Processing all files...')
        return xml_files


def add_edge_with_type(G: MultiDiGraph, source: str, target: str, relation_type: str, color: str) -> None:
    if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
        logging.debug(
            f"Adding edge from {source} to {target} with type {relation_type}")
    G.add_edge(source, target, relation_type=relation_type, color=color)


def add_relationship_edges(G: MultiDiGraph, rule_id: str, if_sid: Optional[str], if_matched_sid: Optional[str], if_group: Optional[str], if_matched_group: Optional[str], group_membership: dict[str, list[str]]) -> None:
    # Add parent-child relationships based on if_sid and if_matched_sid
    if if_sid:
        add_edge_with_type(G, if_sid, rule_id, 'if_sid', 'blue')
    if if_matched_sid:
        add_edge_with_type(G, if_matched_sid, rule_id,
                           'if_matched_sid', 'green')

    # Add relationships based on if_group and if_matched_group
    if if_group:
        for group in if_group.split(','):
            for parent_rule in group_membership.get(group, []):
                add_edge_with_type(G, parent_rule, rule_id, 'if_group', 'red')

    if if_matched_group:
        for group in if_matched_group.split(','):
            for parent_rule in group_membership.get(group, []):
                add_edge_with_type(G, parent_rule, rule_id,
                                   'if_matched_group', 'purple')


def parse_groups_and_rules(element: ET.Element, inherited_groups: list[str], G: MultiDiGraph, group_membership: dict[str, list[str]]) -> None:
    """Recursive function to parse groups and rules

    Args:
        element (ET.Element): The current XML element to parse
        inherited_groups (list[str]): If the file starts with a group tag, all rules in the group tag will inherit the groups from this tag
        G (MultiDiGraph): The networkx MultiDiGraph object to build the relationships
        group_membership (dict[str, list[str]]): Dictionary to track which rules belong to which groups, required for if_group and if_matched_group relationships
    """

    # If the current element is a rule
    if element.tag == 'rule':
        rule_id = element.get('id', '0')
        if_sid = element.findtext('if_sid', None)
        if_matched_sid = element.findtext('if_matched_sid', None)
        if_group = element.findtext('if_group', None)
        if_matched_group = element.findtext('if_matched_group', None)

        children: list[tuple[str, Optional[str]]] = [
            (i.tag, i.text,) for i in element]

        rule_description: Optional[str] = extract_rule_description(children)
        all_groups: list[str] = extract_rule_groups(inherited_groups, children)

        # Add the rule node with all groups as a node attribute
        G.add_node(rule_id, groups=all_groups, description=rule_description)

        # Track which rules belong to which groups
        for group in all_groups:
            group_membership[group].append(rule_id)

        add_relationship_edges(G, rule_id, if_sid, if_matched_sid,
                               if_group, if_matched_group, group_membership)

    # If the current element is a group or contains groups, recurse further
    elif element.tag == 'group':
        # Get any group information from this groups tag
        group_attribute = element.get('name', '')
        # Combine the inherited groups with the current groups attribute
        internal_groups: list[str] = [
            gr for gr in group_attribute.split(',') if gr != '']
        if len(inherited_groups) == 0:
            new_inherited_groups: list[str] = inherited_groups
        else:
            new_inherited_groups = inherited_groups + internal_groups

        # Recursively parse children of this group
        for child in element:
            parse_groups_and_rules(
                child, new_inherited_groups, G, group_membership)


def extract_rule_groups(inherited_groups: list[str], children: list[tuple[str, Optional[str]]]) -> list[str]:

    all_groups: list[str] = []

    all_groups.extend(inherited_groups)

    for child in children:
        if child[0] == 'group':
            rule_groups = child[1]
            if rule_groups is not None:
                all_groups.extend(rule_groups.split(','))
            break

    return all_groups


def extract_rule_description(children: list[tuple[str, Optional[str]]]) -> Optional[str]:
    rule_description: Optional[str] = None

    for child in children:
        if child[0] == 'description':
            rule_description = child[1]
            if isinstance(rule_description, list):
                rule_description = ' '.join(rule_description)
            else:
                rule_description = str(rule_description)
            break
    return rule_description


def build_graph_from_xml(paths: list[str], top: int = 0) -> MultiDiGraph:
    """
    Function to parse XML and build the relationship graph

    Args:
        paths (list[str]): List of directories to search for Wazuh rule files.
        top (int, optional): Top N files to pick from the files found. Defaults to 0, means all files.

    Returns:
        MultiDiGraph: Networkx MultiDiGraph object representing the relationships between rules
    """
    logging.info(f'Paths: {paths}')

    G = nx.MultiDiGraph()  # Use a directed graph to maintain parent-child relationships
    # Track rules belonging to each group
    # Returns an empty list if the group is not found
    group_membership: dict[str, list[str]] = defaultdict(list)  # type: ignore

    # Get all XML files from the given paths
    xml_files: list[str] = get_all_xml_files(paths, top=top)

    # Parse each XML file
    for xml_file in xml_files:
        logging.info(f'Processing file: {xml_file}')

        # Read the content of the XML file
        try:
            with open(xml_file, 'r', encoding=ENCODING) as f:
                xml_content: str = f.read()

        except OSError as e:
            logging.error(f"Error reading file {xml_file}: {e}", exc_info=True)
            continue

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
            logging.error(f"Error parsing {xml_file}: {e}", exc_info=True)

        # Parse the XML to build relationships, passing an empty inherited_groups list

        if root is not None:
            for child in root.iter():
                parse_groups_and_rules(child, [], G, group_membership)

    return G


def wrap_with_root(xml_content: str) -> str:
    """
    Function to wrap XML content with a temporary root element.
    Wazuh rule files may contain multiple root elements, which is not allowed in XML.

    Args:
        xml_content (str): XML content to wrap

    Returns:
        str: Wrapped XML content
    """
    return f"<root>{xml_content}</root>"


def visualize_graph_interactive_with_controls(G: MultiDiGraph) -> None:
    """
    Function to visualize the graph interactively using pyvis with HTML controls.
    The function generates a file named 'interactive_graph_with_controls.html' in the current directory.

    Args:
        G (MultiDiGraph): Networkx MultiDiGraph object representing the relationships between rules
    """

    net = Network(height="800px", width="100%", directed=True, neighborhood_highlight=True,
                  select_menu=False, filter_menu=True, heading='Wazuh Ruleset Graph')

    # Add nodes to the pyvis network
    for node, data in G.nodes(data=True):
        group_list = ','.join(data.get('groups', []))
        desc = data.get('description', 'No description')
        if isinstance(desc, list):
            desc = ' '.join(desc)

        tooltip = f"Groups: {group_list}"
        net.add_node(
            node, label=f"{node}: {desc}", title=tooltip, group=group_list)

    # Add edges with their relation_type attribute
    for source, target, edge_data in G.edges(data=True):
        relation_type = edge_data.get('relation_type')
        color = edge_data.get('color', 'black')
        net.add_edge(
            source, target, title=f"Type: {relation_type}", relation_type=relation_type, color=color)

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
        },
        "smooth": {
        "type": "continuous"
        }
      },
      "physics": {
        "barnesHut": {
        "gravitationalConstant": -30000,
        "centralGravity": 0.3,
        "springLength": 200,
        "springConstant": 0.04
        },
        "minVelocity": 0.75
      },
	  "layout": {
	    "randomSeed": 191006,
	    "improvedLayout": false
	  }
    }
    """)

    # Set the template for the HTML file
    base = os.path.abspath('./')
    net.set_template_dir(template_directory=base,
                         template_file='template.html')

    timestamp = time.strftime("%Y%m%d-%H%M%S")

    # Output file
    out_file = os.path.join(os.path.abspath(
        './'), f'{timestamp}_interactive_graph.html')

    # Generate the network and insert it into the HTML template
    net.show(out_file,
             local=True, notebook=False)


def validate_paths(paths: list[str]) -> None:
    for path in paths:
        if not os.path.isdir(path):
            logging.error(f"Invalid directory path: {path}", exc_info=True)
            print(f"Error: Invalid directory path: {path}")
            sys.exit(1)


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(prog=APP_NAME,
                                                              description=DESCRIPTION)
    if (len(sys.argv)) == 1:
        parser.print_help()
        sys.exit(1)

    parser.add_argument("--path", "-p",
                        dest="path",
                        required=True,
                        type=str,
                        help="Path to the Wazuh rule directories. Comma-separated multiple paths are accepted.")
    parser.add_argument("--top", "-t",
                        dest="top",
                        required=False,
                        default=0,
                        type=int,
                        help="Top N XML files to process, especially for testing purposes")

    args: argparse.Namespace = parser.parse_args()
    paths: list[str] = [p for p in str(args.path).split(',') if p != '']
    top = int(args.top)

    validate_paths(paths)

    # Build the graph
    G: MultiDiGraph = build_graph_from_xml(paths=paths, top=top)

    # Visualize the graph interactively with HTML controls
    visualize_graph_interactive_with_controls(G)


if __name__ == "__main__":
    try:
        logging.basicConfig(filename=os.path.join(f'./{APP_NAME}.log'),
                            encoding=ENCODING,
                            format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                            datefmt="%Y-%m-%dT%H:%M:%S%z",
                            level=logging.INFO)

        excepthook = logging.error
        logging.info('Starting')
        main()
        logging.info('Exiting.')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.error(str(ex), exc_info=True)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
