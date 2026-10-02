import logging
import os
import pickle
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Final, Optional

import networkx as nx

ENCODING: Final[str] = "utf-8"

REGEX_BLOCK: re.Pattern[str] = re.compile(
    r"(<(?:regex|if_matched_regex)\b[^>]*>)"
    r"(.*?)"
    r"(</(?:regex|if_matched_regex)>)",
    flags=re.DOTALL | re.IGNORECASE,
)
REGEX_AMP: re.Pattern[str] = re.compile(
    r"&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9A-Fa-f]+;)"
)

TEMPORAL_RULE_ATTRIBUTES: Final[tuple[str, ...]] = (
    "frequency",
    "timeframe",
)
TEMPORAL_PARENT_TAGS: Final[frozenset[str]] = frozenset({
    "if_matched_sid",
    "if_matched_group",
})

# RuleVis deliberately omits if_level relationships. Keep the condition model
# aligned with the graph model so an "effective conditions" trace is complete.
ATOMIC_CONDITION_TAGS: Final[frozenset[str]] = frozenset({
    "location",
    "decoded_as",
    "category",
    "match",
    "regex",
    "field",
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "protocol",
    "action",
    "id",
    "url",
    "data",
    "extra_data",
    "status",
    "system_name",
    "srcgeoip",
    "dstgeoip",
    "user",
    "hostname",
    "program_name",
    "compiled_rule",
    "list",
    "time",
    "weekday",
    "if_sid",
    "if_group",
})
ATOMIC_PARENT_TAGS: Final[frozenset[str]] = frozenset({
    "if_sid",
    "if_group",
})


class GraphGenerator:
    def __init__(self, paths: list[str], graph_file: str) -> None:
        self.paths = paths
        self.group_membership: dict[str, list[str]] = defaultdict(list)
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.graph_file: str = graph_file
        self.overwrite_rules: list[
            tuple[ET.Element, str, dict[str, str], list[str]]
        ] = []
        self.rule_relationships: dict[
            str,
            tuple[Optional[str], Optional[str], Optional[str], Optional[str]],
        ] = {}

    def get_all_xml_files(self) -> list[str]:
        xml_files: list[str] = []
        for path in self.paths:
            for root, dirs, files in os.walk(path):
                dirs.sort()
                files.sort()
                for file in files:
                    if file.lower().endswith('.xml'):
                        abs = os.path.abspath(os.path.join(root, file))
                        xml_files.append(abs)

        logging.info(f'Found {len(xml_files)} XML files in the given paths')
        logging.info('Processing all files...')
        return xml_files

    def add_edge_with_type(
        self,
        source: str,
        target: str,
        relation_type: str,
        selector: Optional[str] = None,
    ) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}"
            )
        edge_data = {"relation_type": relation_type}
        if selector is not None:
            edge_data["selector"] = selector

        existing_edges = self.G.get_edge_data(source, target) or {}
        if any(
            data.get("relation_type") == relation_type
            and data.get("selector") == selector
            for data in existing_edges.values()
        ):
            return

        self.G.add_edge(source, target, **edge_data)

    def add_relationship_edges(
        self,
        rule_id: str,
        if_sid: Optional[str],
        if_matched_sid: Optional[str],
        if_group: Optional[str],
        if_matched_group: Optional[str],
    ) -> None:
        if if_sid:
            for sid in re.split(r'[,\s]+', if_sid.strip()):
                if sid:
                    self.add_edge_with_type(
                        sid, rule_id, 'if_sid', selector=sid
                    )

        if if_matched_sid:
            for sid in re.split(r'[,\s]+', if_matched_sid.strip()):
                if sid:
                    self.add_edge_with_type(
                        sid, rule_id, 'if_matched_sid', selector=sid
                    )

        if if_group:
            for group in re.split(r'[,\s]+', if_group.strip()):
                if not group:
                    continue
                for parent_rule in self.group_membership.get(group, []):
                    self.add_edge_with_type(
                        parent_rule, rule_id, 'if_group', selector=group
                    )

        if if_matched_group:
            for group in re.split(r'[,\s]+', if_matched_group.strip()):
                if not group:
                    continue
                for parent_rule in self.group_membership.get(group, []):
                    self.add_edge_with_type(
                        parent_rule,
                        rule_id,
                        'if_matched_group',
                        selector=group,
                    )

    def is_temporal_rule(self, element: ET.Element) -> bool:
        return any(
            element.get(attribute) is not None
            for attribute in TEMPORAL_RULE_ATTRIBUTES
        )

    def extract_temporal_conditions(
        self,
        element: ET.Element,
        regex_values: dict[str, str],
    ) -> list[dict[str, object]]:
        conditions: list[dict[str, object]] = []

        for attribute in TEMPORAL_RULE_ATTRIBUTES:
            value = element.get(attribute)
            if value is not None:
                conditions.append({
                    "tag": attribute,
                    "value": value,
                    "kind": "rule_attribute",
                })

        for child in element:
            if not isinstance(child.tag, str):
                continue

            tag = child.tag.lower()
            is_temporal = (
                tag.startswith("if_matched_")
                or tag.startswith("same_")
                or tag.startswith("different_")
                or tag.startswith("not_same_")
                or tag in {"check_diff", "if_fts", "global_frequency"}
            )
            if not is_temporal:
                continue

            value = child.text or ""
            if tag == "if_matched_regex":
                value = regex_values.get(value, value)

            condition: dict[str, object] = {
                "tag": tag,
                "value": value,
            }
            if child.attrib:
                condition["attributes"] = dict(child.attrib)
            conditions.append(condition)

        return conditions

    def extract_atomic_conditions(
        self,
        element: ET.Element,
        regex_values: dict[str, str],
    ) -> list[dict[str, object]]:
        conditions: list[dict[str, object]] = []

        maxsize = element.get("maxsize")
        if maxsize is not None:
            conditions.append({
                "tag": "maxsize",
                "value": maxsize,
                "kind": "rule_attribute",
            })

        for child in element:
            if not isinstance(child.tag, str):
                continue
            tag = child.tag.lower()
            if tag not in ATOMIC_CONDITION_TAGS:
                continue

            value = child.text or ""
            if tag == "regex":
                value = regex_values.get(value, value)

            condition: dict[str, object] = {
                "tag": tag,
                "value": value,
            }
            if child.attrib:
                condition["attributes"] = dict(child.attrib)
            conditions.append(condition)

        return conditions

    def parse_groups_and_rules(
        self,
        element: ET.Element,
        inherited_groups: list[str],
        xml_file: str,
        regex_values: dict[str, str],
    ) -> None:
        if element.tag == 'rule':
            if element.get("overwrite", "").lower() == "yes":
                self.overwrite_rules.append(
                    (
                        element,
                        xml_file,
                        regex_values,
                        list(inherited_groups),
                    )
                )
                return

            rule_id = element.get('id', '0')
            rule_level = element.get('level')
            if_sid = element.findtext('if_sid', None)
            if_matched_sid = element.findtext('if_matched_sid', None)
            if_group = element.findtext('if_group', None)
            if_matched_group = element.findtext('if_matched_group', None)

            attributes = [(i.tag, i.text) for i in element]
            rule_description = self.extract_rule_description(attributes)
            all_groups = self.extract_rule_groups(
                inherited_groups, attributes
            )

            if self.G.nodes.get(rule_id) is not None:
                logging.debug(
                    "Duplicate rule ID found with no 'overwrite' tag: "
                    f"{rule_id}. User must fix the rule manually."
                )
            else:
                self.G.add_node(
                    rule_id,
                    groups=all_groups,
                    description=rule_description,
                    level=rule_level,
                    file=os.path.basename(xml_file),
                    temporal=self.is_temporal_rule(element),
                    mitre=self.extract_mitre_ids(element),
                    conditions=self.extract_atomic_conditions(
                        element, regex_values
                    ),
                    temporal_conditions=self.extract_temporal_conditions(
                        element, regex_values
                    ),
                )
                for group in all_groups:
                    self.group_membership[group].append(rule_id)

                # Relationship resolution is deferred until every rule and
                # group membership has been loaded. This prevents if_group
                # edges from depending on XML/file traversal order.
                self.rule_relationships[rule_id] = (
                    if_sid,
                    if_matched_sid,
                    if_group,
                    if_matched_group,
                )

        elif element.tag == 'group':
            group_attribute = element.get('name', '')
            internal_groups = [
                gr for gr in group_attribute.split(',') if gr != ''
            ]
            new_inherited_groups = inherited_groups + internal_groups

            for child in element:
                self.parse_groups_and_rules(
                    child,
                    new_inherited_groups,
                    xml_file,
                    regex_values,
                )

    def extract_mitre_ids(
        self,
        element: ET.Element,
    ) -> list[str]:
        mitre = element.find("mitre")
        if mitre is None:
            return []

        return [
            child.text.strip()
            for child in mitre
            if child.tag == "id" and child.text and child.text.strip()
        ]

    def extract_rule_groups(
        self,
        inherited_groups: list[str],
        children: list[tuple[str, Optional[str]]],
    ) -> list[str]:
        all_groups = list(inherited_groups)
        for child in children:
            if child[0] == 'group' and child[1]:
                all_groups.extend([g for g in child[1].split(',') if g])
        return all_groups

    def extract_rule_description(
        self,
        attributes: list[tuple[str, Optional[str]]],
    ) -> Optional[str]:
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
                    f"Error reading file {xml_file}: {e}", exc_info=True
                )
                continue

            wrapped_content = self.wrap_with_root(xml_content)

            try:
                protected, regex_values = self.__protect_regex_fields(
                    wrapped_content
                )
                sanitized = self.__escape_amp(protected)
                root = ET.fromstring(sanitized)
                for child in root:
                    self.parse_groups_and_rules(
                        child, [], xml_file, regex_values
                    )
            except Exception as e:
                logging.error(
                    f"Error parsing {xml_file}: {e}", exc_info=True
                )

        # Apply overwrites after all base rules exist. Wazuh preserves the
        # dependency labels (if_sid/if_group and the matched SID/group
        # relationships), but replaces ordinary predicates and other rule
        # properties. Keep the effective condition model consistent with that.
        for (
            element,
            ow_file,
            regex_values,
            inherited_groups,
        ) in self.overwrite_rules:
            rule_id = element.get("id")
            if rule_id in self.G.nodes:
                existing = self.G.nodes[rule_id]
                logging.info(f"Applying overwrite for rule {rule_id}")

                attrs = [(i.tag, i.text) for i in element]
                desc = self.extract_rule_description(attrs)
                if desc:
                    existing["description"] = desc

                effective_groups = self.extract_rule_groups(
                    inherited_groups, attrs
                )
                old_groups = list(existing.get("groups", []))
                for group in old_groups:
                    self.group_membership[group] = [
                        member
                        for member in self.group_membership.get(group, [])
                        if member != rule_id
                    ]
                existing["groups"] = effective_groups
                existing["mitre"] = self.extract_mitre_ids(element)
                for group in effective_groups:
                    if rule_id not in self.group_membership[group]:
                        self.group_membership[group].append(rule_id)

                for attr in ("level", "maxsize"):
                    if element.get(attr):
                        existing[attr] = element.get(attr)

                existing["file"] = os.path.basename(ow_file)

                preserved_parent_conditions = [
                    condition
                    for condition in existing.get("conditions", [])
                    if condition.get("tag") in ATOMIC_PARENT_TAGS
                ]
                overwrite_conditions = [
                    condition
                    for condition in self.extract_atomic_conditions(
                        element, regex_values
                    )
                    if condition.get("tag") not in ATOMIC_PARENT_TAGS
                ]
                existing["conditions"] = (
                    preserved_parent_conditions + overwrite_conditions
                )

                preserved_temporal_parents = [
                    condition
                    for condition in existing.get(
                        "temporal_conditions", []
                    )
                    if condition.get("tag") in TEMPORAL_PARENT_TAGS
                ]
                overwrite_temporal_conditions = [
                    condition
                    for condition in self.extract_temporal_conditions(
                        element, regex_values
                    )
                    if condition.get("tag") not in TEMPORAL_PARENT_TAGS
                ]
                existing["temporal_conditions"] = (
                    preserved_temporal_parents
                    + overwrite_temporal_conditions
                )
                existing["temporal"] = self.is_temporal_rule(element)
            else:
                logging.warning(
                    f"Overwrite rule {rule_id} found with no base rule; "
                    "skipping."
                )

        logging.info("Resolving rule relationships...")
        for rule_id, relationships in self.rule_relationships.items():
            self.add_relationship_edges(rule_id, *relationships)

        first_level_rules = [
            node for node in self.G.nodes if self.G.in_degree(node) == 0
        ]

        synthetic_root = '0'
        self.G.add_node(
            synthetic_root,
            description="Synthetic root node",
            groups=["__meta__"],
            temporal=False,
            mitre=[],
            conditions=[],
            temporal_conditions=[],
        )

        for node in first_level_rules:
            self.add_edge_with_type(synthetic_root, node, "root")

        logging.info("Pre-calculating child relationships...")
        for node_id in list(self.G.nodes):
            children_ids = list(self.G.successors(node_id))
            self.G.nodes[node_id]['children_ids'] = children_ids
        logging.info("Child relationship calculation complete.")

        logging.info(f"Total nodes: {self.G.number_of_nodes()}")
        logging.info(
            "First-level children (connected to root): "
            f"{len(first_level_rules)}"
        )

    def save_graph(self) -> None:
        try:
            output_path = self.graph_file
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            pickle.dump(self.G, open(output_path, 'wb'))
            logging.info(f"Graph saved to {output_path}")
        except Exception as e:
            logging.exception("Error saving graph", e)

    def __protect_regex_fields(
        self,
        xml_string: str,
    ) -> tuple[str, dict[str, str]]:
        """
        Replace regex bodies with XML-safe placeholders before parsing.

        Wazuh regex text can contain characters that generic XML parsers treat
        as markup. RuleVis previously removed regex elements completely. A
        placeholder preserves the exact expression for the condition view
        without changing the source file.
        """
        regex_values: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            token = f"__RULEVIS_REGEX_{len(regex_values)}__"
            regex_values[token] = match.group(2)
            return f"{match.group(1)}{token}{match.group(3)}"

        return REGEX_BLOCK.sub(replace, xml_string), regex_values

    def __escape_amp(self, xml_string: str) -> str:
        return REGEX_AMP.sub("&amp;", xml_string)
