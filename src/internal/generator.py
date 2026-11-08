import logging
import os
import pickle
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Final, Optional

import networkx as nx

from internal.catalog import (
    RuleCatalog,
    normalize_rule_id,
    os_match,
    os_word_match,
    valid_if_sid,
    resolve_structural_parent_selectors,
)

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

# Preserve declared if_level relationships independently of the runtime
# occurrence simulator. Source-level edges can include unavailable parents.
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
    "if_level",
})
ATOMIC_PARENT_TAGS: Final[frozenset[str]] = frozenset({
    "if_sid",
    "if_group",
    "if_level",
})


class GraphGenerator:
    def __init__(self, paths: list[str], graph_file: str) -> None:
        self.paths = paths
        self.group_membership: dict[str, list[str]] = defaultdict(list)
        self.runtime_group_by_rule: dict[str, str] = {}
        self.runtime_group_history: dict[str, list[str]] = defaultdict(list)
        self.runtime_priority_by_rule: dict[str, int] = {}
        # Encoded Wazuh load priorities occupy a small, bounded key space.
        # The indices avoid testing every rule for every if_level selector.
        self.active_priority_index: dict[int, dict[str, None]] = defaultdict(dict)
        self.history_priority_index: dict[int, dict[str, None]] = defaultdict(dict)
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.graph_file: str = graph_file
        self.catalog: RuleCatalog = RuleCatalog()
        self.overwrite_rules: list[
            tuple[ET.Element, str, dict[str, str], list[str], Optional[str]]
        ] = []
        self.rule_relationships: dict[
            str,
            tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[int]],
        ] = {}
        self.rule_load_index: dict[str, int] = {}
        # Freeze each dependency at declaration time: later overwrites must
        # not rewrite parents already attached by Wazuh's incremental loader.
        self.group_parent_snapshots: dict[
            str, tuple[tuple[str, str], ...]
        ] = {}
        self.level_parent_snapshots: dict[str, tuple[str, ...]] = {}
        self.temporal_group_parent_snapshots: dict[str, tuple[str, ...]] = {}

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
        load_order_candidate: Optional[bool] = None,
        synthesized_from: Optional[str] = None,
    ) -> None:
        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            logging.debug(
                f"Adding edge from {source} to {target} with type {relation_type}"
            )
        edge_data = {"relation_type": relation_type}
        if selector is not None:
            edge_data["selector"] = selector
        if load_order_candidate is not None:
            edge_data["load_order_candidate"] = load_order_candidate
        if synthesized_from is not None:
            edge_data["synthesized_from"] = synthesized_from

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
        if_level: Optional[int],
    ) -> None:
        resolved = resolve_structural_parent_selectors(
            if_sid=if_sid,
            if_level=if_level,
            if_group=if_group,
            if_matched_sid=if_matched_sid,
            if_matched_group=if_matched_group,
        )
        structural_sid = resolved.if_sid
        structural_group = resolved.if_group
        sid_origin = (
            "if_matched_sid"
            if resolved.sources.get("if_sid") == "if_matched_sid" else None
        )
        group_origin = (
            "if_matched_group"
            if resolved.sources.get("if_group") == "if_matched_group" else None
        )

        if structural_sid:
            for sid in re.split(r'[,\s]+', structural_sid.strip()):
                if sid:
                    parent = normalize_rule_id(sid) or sid
                    self.add_edge_with_type(
                        parent, rule_id, 'if_sid', selector=sid,
                        synthesized_from=sid_origin,
                    )

        if if_matched_sid:
            for sid in re.split(r'[,\s]+', if_matched_sid.strip()):
                if sid:
                    parent = normalize_rule_id(sid) or sid
                    self.add_edge_with_type(
                        parent, rule_id, 'if_matched_sid', selector=sid
                    )

        if structural_group:
            selector = structural_group.strip()
            if selector:
                candidates = set(
                    self.group_parent_snapshots.get(rule_id, ())
                )
                for parent_rule, matched in self._declared_group_rules(selector):
                    if parent_rule == rule_id:
                        continue
                    self.add_edge_with_type(
                        parent_rule, rule_id, "if_group", selector=matched,
                        load_order_candidate=(parent_rule, matched) in candidates,
                        synthesized_from=group_origin,
                    )

        if if_level is not None and if_level > 0:
            candidates = set(self.level_parent_snapshots.get(rule_id, ()))
            threshold = if_level * 100
            possible: set[str] = set()
            for priority, parents in self.history_priority_index.items():
                if priority >= threshold:
                    possible.update(parents)
            for parent in sorted(
                possible, key=self.rule_load_index.__getitem__
            ):
                if parent == rule_id:
                    continue
                self.add_edge_with_type(
                    parent, rule_id, "if_level", selector=str(if_level),
                    load_order_candidate=parent in candidates,
                )

        if if_matched_group:
            candidates = set(
                self.temporal_group_parent_snapshots.get(rule_id, ())
            )
            for parent, histories in self.runtime_group_history.items():
                if not any(
                    os_match(if_matched_group, value) for value in histories
                ):
                    continue
                self.add_edge_with_type(
                    parent, rule_id, 'if_matched_group',
                    selector=if_matched_group,
                    load_order_candidate=parent in candidates,
                )

    def _declared_group_rules(self, selector: str):
        """Find declarations matching any accepted runtime group assignment."""
        for parent, histories in self.runtime_group_history.items():
            if any(os_word_match(selector, value) for value in histories):
                yield parent, selector

    def _snapshot_group_parents(
        self, rule_id: str, selector: str
    ) -> None:
        """Record available group parents before inserting this rule."""
        selector = selector.strip()
        self.group_parent_snapshots[rule_id] = tuple(
            (parent, selector)
            for parent in self._matching_group_rules(selector)
            if parent != rule_id and parent in self.rule_load_index
        )

    def _matching_group_rules(self, selector: str):
        """Evaluate the Wazuh-style selector against active runtime groups."""
        return (
            rule_id for rule_id, groups in self.runtime_group_by_rule.items()
            if os_word_match(selector, groups)
        )

    def _record_priority(
        self, rule_id: str, priority: int
    ) -> None:
        previous = self.runtime_priority_by_rule.get(rule_id)
        if previous is not None:
            self.active_priority_index[previous].pop(rule_id, None)
        self.runtime_priority_by_rule[rule_id] = priority
        self.active_priority_index[priority][rule_id] = None
        self.history_priority_index[priority][rule_id] = None

    def _snapshot_level_parents(
        self, rule_id: str, level: int
    ) -> None:
        """Snapshot eligible existing rule priorities at declaration time."""
        threshold = level * 100
        parents: set[str] = set()
        for priority, rule_ids in self.active_priority_index.items():
            if priority >= threshold:
                parents.update(rule_ids)
        parents.discard(rule_id)
        self.level_parent_snapshots[rule_id] = tuple(parents)

    def _snapshot_temporal_group_parents(
        self, rule_id: str, selector: str
    ) -> None:
        """Wazuh registers historical sources after inserting the rule."""
        self.temporal_group_parent_snapshots[rule_id] = tuple(
            parent
            for parent, group in self.runtime_group_by_rule.items()
            if os_match(selector, group)
        )

    def _replace_visual_groups(
        self, rule_id: str, groups: list[str]
    ) -> None:
        """Update membership at overwrite time, not after the file scan."""
        node = self.G.nodes[rule_id]
        for group in node.get("groups", ()):
            self.group_membership[group] = [
                member for member in self.group_membership.get(group, ())
                if member != rule_id
            ]
        node["groups"] = list(groups)
        for group in groups:
            if rule_id not in self.group_membership[group]:
                self.group_membership[group].append(rule_id)

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

    def _concat_child_text(
        self,
        element: ET.Element,
        tag: str,
    ) -> Optional[str]:
        values = [
            child.text or ""
            for child in element
            if isinstance(child.tag, str) and child.tag.lower() == tag
        ]
        return "".join(values) if values else None

    def _concat_int_child(
        self,
        element: ET.Element,
        tag: str,
    ) -> Optional[int]:
        value = self._concat_child_text(element, tag)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _invalid_matched_sid(element: ET.Element) -> Optional[str]:
        """Wazuh OS_StrIsNum rejects every nondecimal if_matched_sid tag."""
        for child in element:
            if (
                isinstance(child.tag, str)
                and child.tag.lower() == "if_matched_sid"
            ):
                value = child.text or ""
                if re.fullmatch(r"[0-9]+", value) is None:
                    return value
        return None

    @staticmethod
    def _invalid_if_level(element: ET.Element) -> Optional[str]:
        """Wazuh skips declarations with nondecimal if_level content."""
        for child in element:
            if (
                isinstance(child.tag, str)
                and child.tag.lower() == "if_level"
            ):
                value = child.text or ""
                if re.fullmatch(r"[0-9]+", value) is None:
                    return value
        return None

    def _last_int_child(
        self,
        element: ET.Element,
        tag: str,
    ) -> Optional[int]:
        values = [
            child.text
            for child in element
            if (
                isinstance(child.tag, str)
                and child.tag.lower() == tag
                and child.text is not None
            )
        ]
        if not values:
            return None
        try:
            return int(values[-1])
        except ValueError:
            return None

    def _record_catalog_declaration(
        self,
        element: ET.Element,
        inherited_groups: list[str],
        runtime_group: str,
        xml_file: str,
        regex_values: dict[str, str],
    ) -> Optional[str]:
        rule_id = element.get("id")
        level = element.get("level")
        if rule_id is None or level is None:
            return

        try:
            source_level = int(level)
            accuracy = int(element.get("accuracy", "1"))
        except ValueError:
            return

        runtime_group_value = runtime_group
        for child in element:
            if (
                isinstance(child.tag, str)
                and child.tag.lower() == "group"
                and child.text
            ):
                runtime_group_value += child.text.replace("\n", "")

        attrs = [(child.tag, child.text) for child in element]
        category = self._concat_child_text(element, "category")
        display_groups = self.extract_rule_groups(
            inherited_groups,
            attrs,
        )

        self.catalog.append(
            rule_id=rule_id,
            file=os.path.basename(xml_file),
            source_level=source_level,
            accuracy=accuracy,
            noalert=element.get("noalert", "0") == "1",
            overwrite=element.get("overwrite", "").lower() == "yes",
            runtime_group=runtime_group_value,
            display_groups=display_groups,
            category=category if category else None,
            if_sid=self._concat_child_text(element, "if_sid"),
            if_level=self._concat_int_child(element, "if_level"),
            if_group=self._concat_child_text(element, "if_group"),
            if_matched_sid=self._last_int_child(
                element,
                "if_matched_sid",
            ),
            invalid_if_matched_sid=self._invalid_matched_sid(element),
            invalid_if_level=self._invalid_if_level(element),
            if_matched_group=self._concat_child_text(
                element,
                "if_matched_group",
            ),
            conditions=self.extract_atomic_conditions(
                element,
                regex_values,
            ),
            temporal_conditions=self.extract_temporal_conditions(
                element,
                regex_values,
            ),
        )
        return runtime_group_value

    def parse_groups_and_rules(
        self,
        element: ET.Element,
        inherited_groups: list[str],
        xml_file: str,
        regex_values: dict[str, str],
        runtime_group: str = "",
    ) -> None:
        if element.tag == 'rule':
            declared_runtime_group = self._record_catalog_declaration(
                element,
                inherited_groups,
                runtime_group,
                xml_file,
                regex_values,
            )

            # Keep invalid declarations in the catalog for assessment, but
            # do not turn them into visual rule nodes or group parents.
            raw_rule_id = element.get("id")
            rule_id = normalize_rule_id(raw_rule_id or "")
            if declared_runtime_group is None or rule_id is None:
                logging.warning(
                    "Skipping invalid visual rule in %s: id=%r, level=%r",
                    xml_file, raw_rule_id, element.get("level"),
                )
                return

            if not valid_if_sid(self.catalog.declarations[-1].if_sid):
                logging.warning(
                    "Skipping rule %s in %s: invalid if_sid characters",
                    rule_id, xml_file,
                )
                return

            invalid_if_level = self.catalog.declarations[-1].invalid_if_level
            if invalid_if_level is not None:
                logging.warning(
                    "Skipping rule %s in %s: invalid if_level %r",
                    rule_id, xml_file, invalid_if_level,
                )
                return

            invalid_matched_sid = (
                self.catalog.declarations[-1].invalid_if_matched_sid
            )
            if invalid_matched_sid is not None:
                logging.warning(
                    "Skipping rule %s in %s: invalid if_matched_sid %r; "
                    "Wazuh requires one decimal SID per element.",
                    rule_id, xml_file, invalid_matched_sid,
                )
                return

            priority = self.catalog.declarations[-1].load_priority
            if element.get("overwrite", "").lower() == "yes":
                if rule_id in self.G.nodes:
                    self._record_priority(rule_id, priority)
                    self.runtime_group_by_rule[rule_id] = declared_runtime_group
                    self.runtime_group_history[rule_id].append(
                        declared_runtime_group
                    )
                    overwrite_groups = self.extract_rule_groups(
                        inherited_groups,
                        [(child.tag, child.text) for child in element],
                    )
                    self._replace_visual_groups(rule_id, overwrite_groups)
                    self.overwrite_rules.append(
                        (
                            element,
                            xml_file,
                            regex_values,
                            list(inherited_groups),
                            declared_runtime_group,
                        )
                    )
                    return
                # analysisd treats an overwrite with no existing rule as an
                # ordinary new declaration. A later base is a duplicate.
                logging.warning(
                    "Overwrite rule %s has no existing base in %s; "
                    "loading it as the first declaration.",
                    rule_id, xml_file,
                )

            rule_level = element.get('level')
            if_sid = self._concat_child_text(element, "if_sid")
            matched_sid = self._last_int_child(element, "if_matched_sid")
            if_matched_sid = (
                str(matched_sid) if matched_sid is not None else None
            )
            if_group = self._concat_child_text(element, "if_group")
            if_matched_group = self._concat_child_text(
                element, "if_matched_group"
            )
            if_level = self._concat_int_child(element, "if_level")
            raw_if_level = self._concat_child_text(element, "if_level")

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
                resolved = resolve_structural_parent_selectors(
                    if_sid=if_sid,
                    if_level=if_level,
                    if_group=if_group,
                    if_matched_sid=if_matched_sid,
                    if_matched_group=if_matched_group,
                )
                if resolved.if_group:
                    self._snapshot_group_parents(
                        rule_id, resolved.if_group
                    )
                if if_level is not None and if_level > 0:
                    self._snapshot_level_parents(rule_id, if_level)
                self._record_priority(rule_id, priority)
                if declared_runtime_group is not None:
                    self.runtime_group_by_rule[rule_id] = declared_runtime_group
                    self.runtime_group_history[rule_id].append(
                        declared_runtime_group
                    )
                if if_matched_group:
                    self._snapshot_temporal_group_parents(
                        rule_id, if_matched_group
                    )
                self.G.add_node(
                    rule_id,
                    groups=all_groups,
                    description=rule_description,
                    level=rule_level,
                    if_level=raw_if_level,
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

                # Resolve source relationships after parsing; group and level
                # candidates were captured before this rule was inserted.
                # Overwrites do not introduce another logical rule node.
                self.rule_load_index[rule_id] = len(self.rule_load_index)
                self.rule_relationships[rule_id] = (
                    if_sid,
                    if_matched_sid,
                    if_group,
                    if_matched_group,
                    if_level,
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
                    runtime_group + group_attribute,
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

        # Apply condition and display metadata for overwrites whose bases
        # already existed when scanned. Wazuh retains original parent
        # selectors while replacing non-parent predicates and rule properties.
        for (
            element,
            ow_file,
            regex_values,
            inherited_groups,
            declared_runtime_group,
        ) in self.overwrite_rules:
            rule_id = normalize_rule_id(element.get("id") or "")
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
                self._replace_visual_groups(rule_id, effective_groups)
                # The base was already accepted when this overwrite was scanned.
                # Preserve the recorded group history for source-level analysis.
                if (
                    declared_runtime_group is not None
                    and declared_runtime_group
                    not in self.runtime_group_history[rule_id]
                ):
                    self.runtime_group_history[rule_id].append(
                        declared_runtime_group
                    )
                existing["mitre"] = self.extract_mitre_ids(element)

                for attr in ("level", "maxsize"):
                    if element.get(attr):
                        existing[attr] = element.get(attr)

                existing["file"] = os.path.basename(ow_file)
                # Deferred application never rewrites original parent
                # selectors; Wazuh preserves those relationships on overwrite.

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
        logging.info("Resolving rule relationships...")
        for rule_id, relationships in self.rule_relationships.items():
            if_sid, if_matched_sid, if_group, if_matched_group, if_level = relationships
            resolved = resolve_structural_parent_selectors(
                if_sid=if_sid,
                if_level=if_level,
                if_group=if_group,
                if_matched_sid=if_matched_sid,
                if_matched_group=if_matched_group,
            )
            self.G.nodes[rule_id]["selector_precedence"] = resolved.metadata()
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
