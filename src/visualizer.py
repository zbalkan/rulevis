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


class RuleVisualizer:
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

    def add_edge_with_type(self, source: str, target: str, relation_type: str, color: str) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}")
        self.G.add_edge(
            source, target, relation_type=relation_type, color=color)

    def add_relationship_edges(self, rule_id: str, if_sid: Optional[str], if_matched_sid: Optional[str], if_group: Optional[str], if_matched_group: Optional[str]) -> None:
        if if_sid:
            self.add_edge_with_type(if_sid, rule_id, 'if_sid', 'blue')
        if if_matched_sid:
            self.add_edge_with_type(
                if_matched_sid, rule_id, 'if_matched_sid', 'green')

        # Add relationships based on if_group and if_matched_group
        if if_group:
            for group in if_group.split(','):
                for parent_rule in self.group_membership.get(group, []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_group', 'red')

        if if_matched_group:
            for group in if_matched_group.split(','):
                for parent_rule in self.group_membership.get(group, []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_matched_group', 'purple')

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

    def build_graph_from_xml(self) -> MultiDiGraph:
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

            wrapped_content = self.wrap_with_root(xml_content)

            try:
                parsed_xml = ET.fromstring(wrapped_content)
                root = parsed_xml
                for child in root.iter():
                    self.parse_groups_and_rules(child, [])
            except Exception as e:
                logging.error(f"Error parsing {xml_file}: {e}", exc_info=True)

        return self.G

    def visualize_graph_interactive_with_controls(self) -> None:
        net = Network(height="800px", width="100%", directed=True, neighborhood_highlight=True,
                      select_menu=False, filter_menu=True, heading='Wazuh Ruleset Graph')

        for node, data in self.G.nodes(data=True):
            group_list = ','.join(data.get('groups', []))
            desc = data.get('description', 'No description')
            tooltip = f"Groups: {group_list}"
            net.add_node(node, label=f"{node}: {desc}",
                         title=tooltip, group=group_list)

        for source, target, edge_data in self.G.edges(data=True):
            relation_type = edge_data.get('relation_type')
            color = edge_data.get('color', 'black')
            net.add_edge(
                source, target, title=f"Type: {relation_type}", relation_type=relation_type, color=color)

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
              "gravitationalConstant": -2000,
              "centralGravity": 0.3,
              "springLength": 100,
              "springConstant": 0.05,
              "avoidOverlap": 0.1
            },
            "minVelocity": 0.75,
            "maxVelocity": 50,
            "solver": "barnesHut",
            "timestep": 0.5,
            "adaptiveTimestep": true
          },
          "layout": {
            "randomSeed": 191006,
            "improvedLayout": false
          }
        }
        """)

        # Template file should be in the same directory as the script
        if not os.path.exists(os.path.join(get_root_dir(), 'template.html')):
            raise FileNotFoundError(
                'Template file not found. Please make sure the template.html file is in the same directory as the script.')

        net.set_template_dir(template_directory=os.path.abspath(get_root_dir()),
                             template_file='template.html')

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        out_file = os.path.join(os.path.abspath(
            './'), f'{timestamp}_interactive_graph.html')
        net.show(out_file, local=True, notebook=False)


def get_root_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    elif __file__:
        return os.path.dirname(__file__)
    else:
        return './'
