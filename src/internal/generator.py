import logging
import os
import pickle
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Any, Final, Optional

import networkx as nx

ENCODING: Final[str] = "utf-8"

REGEX_FINDER: re.Pattern[str] = re.compile(r'<regex\s+.*?>(.*?)</regex>',
                                           flags=re.DOTALL | re.IGNORECASE)
REGEX_AMP: re.Pattern[str] = re.compile(r"&(?!amp;|lt;|gt;)")


class GraphGenerator:
    def __init__(self, paths: list[str], graph_file: str) -> None:
        self.paths = paths
        self.group_membership: dict[str, list[str]] = defaultdict(list)
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.graph_file: str = graph_file
        self.overwrite_rules: list[tuple[ET.Element, str]] = []

    def get_all_xml_files(self) -> list[str]:
        xml_files: list[str] = []
        for path in self.paths:
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith('.xml'):
                        abs = os.path.abspath(os.path.join(root, file))
                        xml_files.append(abs)

        logging.info(f'Found {len(xml_files)} XML files in the given paths')
        logging.info('Processing all files...')
        return xml_files

    def add_edge_with_type(self, source: str, target: str, relation_type: str) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}")
        self.G.add_edge(source, target, relation_type=relation_type)

    def add_relationship_edges(self, rule_id: str,
                               if_sid: Optional[str], if_matched_sid: Optional[str],
                               if_group: Optional[str], if_matched_group: Optional[str]) -> None:
        if if_sid:
            for sid in re.split(r'[,\s]+', if_sid.strip()):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_sid')

        if if_matched_sid:
            for sid in re.split(r'[,\s]+', if_matched_sid.strip()):
                self.add_edge_with_type(sid.strip(), rule_id, 'if_matched_sid')

        if if_group:
            for group in re.split(r'[,\s]+', if_group.strip()):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(parent_rule, rule_id, 'if_group')

        if if_matched_group:
            for group in re.split(r'[,\s]+', if_matched_group.strip()):
                for parent_rule in self.group_membership.get(group.strip(), []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_matched_group')

    def parse_groups_and_rules(self, element: ET.Element, inherited_groups: list[str], xml_file: str) -> None:
        if element.tag == 'rule':
            if element.get("overwrite", "").lower() == "yes":
                # defer to second pass
                self.overwrite_rules.append((element, xml_file))
                return

            rule_id = element.get('id', '0')
            rule_level = element.get('level')
            if_sid = element.findtext('if_sid', None)
            if_matched_sid = element.findtext('if_matched_sid', None)
            if_group = element.findtext('if_group', None)
            if_matched_group = element.findtext('if_matched_group', None)

            attributes = [(i.tag, i.text) for i in element]
            rule_description = self.extract_rule_description(attributes)
            all_groups = self.extract_rule_groups(inherited_groups, attributes)

            if self.G.nodes.get(rule_id) is not None:
                logging.debug(
                    f"Duplicate rule ID found with no 'overwrite' tag: {rule_id}. User must fix the rule manually.")

            else:
                self.G.add_node(rule_id,
                                groups=all_groups,
                                description=rule_description,
                                level=rule_level,
                                file=os.path.basename(xml_file))
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
                self.parse_groups_and_rules(child, new_inherited_groups, xml_file)

    def extract_rule_groups(self, inherited_groups: list[str], children: list[tuple[str, Optional[str]]]) -> list[str]:
        all_groups = list(inherited_groups)
        for child in children:
            if child[0] == 'group' and child[1]:
                all_groups.extend([g for g in child[1].split(',') if g])
        return all_groups

    def extract_rule_description(self, attributes: list[tuple[str, Optional[str]]]) -> Optional[str]:
        description: list[str] = []
        for attr in attributes:
            if attr[0] == 'description':
                d = attr[1]
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
                sanitized = self.__remove_regex_field(wrapped_content)
                sanitized = self.__escape_amp(sanitized)
                parsed_xml = ET.fromstring(sanitized)
                root = parsed_xml
                for child in root:
                    self.parse_groups_and_rules(child, [], xml_file)
            except Exception as e:
                logging.error(f"Error parsing {xml_file}: {e}", exc_info=True)

        # second pass: apply overwrites now that all base rules exist
        # Per Wazuh documentation, the overwrite tag is "used to replace a rule
        # with local changes. To maintain consistency between loaded rules,
        # if_sid, if_group, if_level, if_matched_sid, and if_matched_group
        # labels are not taken into account when overwriting a rule. If any of
        # these are encountered, the original value prevails."
        # Therefore, we intentionally do NOT update groups or dependency
        # relationships (if_sid, if_group, etc.) when applying overwrites.
        for element, ow_file in self.overwrite_rules:
            # Only description, level, maxsize, and file are updated
            rule_id = element.get("id")
            if rule_id in self.G.nodes:
                existing = self.G.nodes[rule_id]
                logging.info(f"Applying overwrite for rule {rule_id}")
                attrs = [(i.tag, i.text) for i in element]
                desc = self.extract_rule_description(attrs)
                if desc:
                    existing["description"] = desc
                for attr in ("level", "maxsize"):
                    if element.get(attr):
                        existing[attr] = element.get(attr)
                existing["file"] = os.path.basename(ow_file)
            else:
                logging.warning(
                    f"Overwrite rule {rule_id} found with no base rule; skipping.")

        first_level_rules = [
            node for node in self.G.nodes if self.G.in_degree(node) == 0]

        # Add synthetic root and connect to top-level rules
        synthetic_root = '0'  # Root has ID of 0
        self.G.add_node(
            synthetic_root, description="Synthetic root node", groups=["__meta__"])

        for node in first_level_rules:
            self.add_edge_with_type(synthetic_root, node, "root")

        # Pre-calculate and store all children for every node.
        # This is crucial for the frontend to know if a node is fully expanded.
        logging.info("Pre-calculating child relationships...")
        for node_id in list(self.G.nodes):
            # G.successors(node_id) returns an iterator of all direct children
            children_ids = list(self.G.successors(node_id))
            # Store this list as a new attribute on the node itself.
            self.G.nodes[node_id]['children_ids'] = children_ids
        logging.info("Child relationship calculation complete.")

        logging.info(f"Total nodes: {self.G.number_of_nodes()}")
        logging.info(
            f"First-level children (connected to root): {len(list(self.G.successors("0")))}")

    def save_graph(self) -> None:
        try:
            output_path = self.graph_file
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            pickle.dump(self.G, open(output_path, 'wb'))
            logging.info(f"Graph saved to {output_path}")
        except Exception as e:
            logging.error(f"Error saving graph: {e}", exc_info=True)

    def __remove_regex_field(self, xml_string: str) -> str:
        """
        Sanitizes the XML string by removing the entire <regex>...</regex> block.

        The user indicated the <regex> tag is not needed for future logic, making
        removal the most straightforward and robust sanitization method.
        """
        # Regex to find the <regex> tag, its content (including newlines), and the closing </regex> tag.
        # The 're.DOTALL' flag allows '.' to match newlines.
        # The '?' makes the matching non-greedy (to match the inner-most tag).
        # We are using a simple non-greedy match for content: (.*?)
        # Since the content is the problem, removing the whole block is the fix.
        sanitized_string = REGEX_FINDER.sub(
            '',
            xml_string)
        return sanitized_string

    def __escape_amp(self, xml_string: str) -> str:
        sanitized_string = REGEX_AMP.sub("&amp;", xml_string)
        return sanitized_string
