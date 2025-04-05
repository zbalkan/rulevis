import logging
import os
import pickle
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Final, Optional

import networkx as nx

ENCODING: Final[str] = "utf-8"


class GraphGenerator:
    def __init__(self, paths: list[str], top: int = 0) -> None:
        self.paths = paths
        self.top = top
        self.group_membership: dict[str, list[str]] = defaultdict(list)
        self.G = nx.MultiDiGraph()

    def get_all_xml_files(self) -> list[str]:
        xml_files: list[str] = []
        for path in self.paths:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.xml'):
                        xml_files.append(os.path.join(root, file))

        print(f'Found {len(xml_files)} XML files in the given paths')
        logging.info(f'Found {len(xml_files)} XML files in the given paths')
        if self.top > 0:
            logging.info(f'Picking {self.top} files...')
            return xml_files[:self.top]
        else:
            logging.info('Processing all files...')
            return xml_files

    def add_edge_with_type(self, source: str, target: str, relation_type: str) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}")
        self.G.add_edge(source, target, relation_type=relation_type)

    def add_relationship_edges(self, rule_id: str, if_sid: Optional[str], if_matched_sid: Optional[str], if_group: Optional[str], if_matched_group: Optional[str]) -> None:
        if if_sid:
            for sid in if_sid.split(','):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_sid')

        if if_matched_sid:
            for sid in if_matched_sid.split(','):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_matched_sid')

        if if_group:
            for group in if_group.split(','):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(parent_rule, rule_id, 'if_group')

        if if_matched_group:
            for group in if_matched_group.split(','):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_matched_group')

    def parse_groups_and_rules(self, element: ET.Element, inherited_groups: list[str]) -> None:
        if element.tag == 'rule':
            rule_id = element.get('id', '0')
            if_sid = element.findtext('if_sid', None)
            if_matched_sid = element.findtext('if_matched_sid', None)
            if_group = element.findtext('if_group', None)
            if_matched_group = element.findtext('if_matched_group', None)

            children = [(i.tag, i.text) for i in element]
            rule_description = self.extract_rule_description(children)
            all_groups = self.extract_rule_groups(inherited_groups, children)

            self.G.add_node(rule_id, groups=all_groups,
                            description=rule_description)
            for group in all_groups:
                self.group_membership[group].append(rule_id)

            self.add_relationship_edges(
                rule_id, if_sid, if_matched_sid, if_group, if_matched_group)

        elif element.tag == 'group':
            group_attribute = element.get('name', '')
            internal_groups = [
                gr for gr in group_attribute.split(',') if gr != '']
            new_inherited_groups = inherited_groups + internal_groups

            for child in element:
                self.parse_groups_and_rules(child, new_inherited_groups)

    def extract_rule_groups(self, inherited_groups: list[str], children: list[tuple[str, Optional[str]]]) -> list[str]:
        all_groups = list(inherited_groups)
        for child in children:
            if child[0] == 'group' and child[1]:
                all_groups.extend(child[1].split(','))
        return all_groups

    def extract_rule_description(self, children: list[tuple[str, Optional[str]]]) -> Optional[str]:
        description: list[str] = []
        for child in children:
            if child[0] == 'description':
                d = child[1]
                if d:
                    description.append(d)
        if len(description) > 0:
            return ' '.join(description)
        return None

    def wrap_with_root(self, xml_content: str) -> str:
        return f"<root>{xml_content}</root>"

    def build_graph_from_xml(self) -> None:
        xml_files = self.get_all_xml_files()

        for xml_file in xml_files:
            logging.info(f'Processing file: {xml_file}')
            try:
                with open(xml_file, 'r', encoding=ENCODING) as f:
                    xml_content = f.read()
            except OSError as e:
                logging.error(
                    f"Error reading file {xml_file}: {e}", exc_info=True)
                continue

            wrapped_content: str = self.wrap_with_root(xml_content)

            try:
                parsed_xml = ET.fromstring(wrapped_content)
                root = parsed_xml
                for child in root.iter():
                    self.parse_groups_and_rules(child, [])
            except Exception as e:
                logging.error(f"Error parsing {xml_file}: {e}", exc_info=True)

        first_level_rules = [
            node for node in self.G.nodes if self.G.in_degree(node) == 0]

        # Add synthetic root and connect to top-level rules
        synthetic_root = '0'  # Root has ID of 0
        self.G.add_node(
            synthetic_root, description="Synthetic root node", groups=["__meta__"])

        for node in first_level_rules:
            self.add_edge_with_type(synthetic_root, node, "root")

        print("Total nodes:", self.G.number_of_nodes())
        print("First-level children (connected to root):",
              len(list(self.G.successors("0"))))

    def save_graph(self, output_path: str) -> None:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            pickle.dump(self.G, open(output_path, 'wb'))
            logging.info(f"Graph saved to {output_path}")
        except Exception as e:
            logging.error(f"Error saving graph: {e}", exc_info=True)


def get_root_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    elif __file__:
        return os.path.dirname(__file__)
    else:
        return './'
