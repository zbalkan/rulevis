"""GDB Python probe for a compiled, debug-symbol Wazuh 4.14.10 analysisd.

Run *inside GDB* with RULEVIS_NATIVE_SCENARIO,\nRULEVIS_NATIVE_SCENARIO_ID and RULEVIS_NATIVE_OUTPUT.
Break at the first top-level _setlevels() call (after rules load), inspect
actual RuleInfo/RuleNode pointers, and export a read-only observation.

This script does not import RuleVis, its prediction code, or its XML parser.
The structural relation label comes from the supplied scenario manifest;
physical parent/child identity and all registrations come from native memory.
"""
import hashlib
import json
import os
import pathlib
import sys

import gdb


def _address(value):
    return int(value)


def _text(value):
    if _address(value) == 0:
        return ""
    return value.string(errors="replace")


def _relation(rule):
    """The label is fixture-derived; native code supplies the attachment."""
    if rule is None:
        return "unknown"
    if rule.get("if_sid") is not None:
        return "if_sid"
    if rule.get("if_level") is not None:
        return "if_level"
    if rule.get("if_group"):
        return "if_group"
    if rule.get("if_matched_group") and not rule.get("overwrite"):
        return "if_group"
    if rule.get("if_matched_sid") and not rule.get("overwrite"):
        return "if_sid"
    return "category"


def _read_tree(head, cap=150000):
    """Enumerate the entire native sibling/child tree in preorder."""
    occurrences = []
    accepted = {}
    stack = [(head, None)]
    visited = set()
    while stack:
        node, parent = stack.pop()
        while _address(node) != 0:
            ptr = _address(node)
            if ptr in visited:
                raise RuntimeError("Cycle or repeated native RuleNode pointer")
            visited.add(ptr)
            if len(visited) > cap:
                raise RuntimeError("Native RuleNode limit exceeded")
            info = node.dereference()["ruleinfo"]
            if _address(info) == 0:
                raise RuntimeError("Null RuleInfo in native occurrence")
            rule_id = str(int(info.dereference()["sigid"]))
            occurrences.append((rule_id, parent, ptr))
            accepted[_address(info)] = (rule_id, info)
            child = node.dereference()["child"]
            next_node = node.dereference()["next"]
            if _address(child) != 0:
                stack.append((next_node, parent))
                node, parent = child, rule_id
            else:
                node = next_node
    return occurrences, accepted


def _capture(head, scenario):
    occurrences, accepted = _read_tree(head)
    wanted = {str(rule["id"]) for rule in scenario["rules"]}
    definitions = {}
    for rule in scenario["rules"]:
        definitions.setdefault(str(rule["id"]), rule)
    all_ids = {rule_id for rule_id, _, _ in occurrences}
    accepted_ids = sorted(all_ids & wanted)
    unexpected_ids = sorted(all_ids - wanted)
    links = {}
    for rule_id, parent_id, _ in occurrences:
        if parent_id is None or rule_id not in wanted or parent_id not in wanted:
            continue
        key = (parent_id, rule_id, _relation(definitions.get(rule_id)))
        links[key] = links.get(key, 0) + 1

    # Native identity: the SID search pointer aliases the source's
    # sid_prev_matched list, regardless of how many physical nodes share it.
    # For groups, OS_MarkGroup appends once per matching physical node to the
    # source RuleInfo's group_prev_matched pointer array.
    sid_owners = {}
    group_search_owners = {}
    sources = {}
    for rule_id, info in accepted.values():
        if rule_id not in wanted:
            continue
        fields = info.dereference()
        sid = _address(fields["sid_prev_matched"])
        if sid:
            sid_owners[sid] = rule_id
        search = _address(fields["group_search"])
        if search:
            group_search_owners[search] = rule_id
        sources[rule_id] = fields

    counts = {}
    for rule_id, fields in sources.items():
        sid_search = _address(fields["sid_search"])
        if sid_search and sid_search in sid_owners:
            key = (sid_owners[sid_search], rule_id, "if_matched_sid")
            counts[key] = 1
        ptr = fields["group_prev_matched"]
        count = int(fields["group_prev_matched_sz"])
        if count < 0 or count > 150000:
            raise RuntimeError("Unexpected native group history array size")
        if not count:
            continue
        if _address(ptr) == 0:
            raise RuntimeError("Null group history pointer with nonzero size")
        for index in range(count):
            consumer = group_search_owners.get(_address(ptr[index]))
            if consumer is None:
                continue
            key = (rule_id, consumer, "if_matched_group")
            counts[key] = counts.get(key, 0) + 1

    def rows(counter, fields):
        return [dict(zip(fields, key), count=count)
                for key, count in sorted(counter.items())]

    return {
        "accepted_rules": accepted_ids,
        "unexpected_rule_ids": unexpected_ids,
        "native_occurrence_count": len(occurrences),
        "attachments": rows(
            links, ("parent_rule_id", "child_rule_id", "relation_type")
        ),
        "registrations": rows(
            counts, ("source_rule_id", "consumer_rule_id", "relation_type")
        ),
    }


def _loaded_rule_files(config_includes, *, cap=100):
    """Hash every rules file named in analysisd's effective Config.includes.

    This comes from native memory, not a copied ossec.conf or a model input.
    Reading a path is only meaningful in the same filesystem namespace as
    the debugged inferior. Fail closed when it cannot be inspected.
    """
    if _address(config_includes) == 0:
        raise RuntimeError("analysisd has no configured rules files")
    result = []
    for index in range(cap):
        item = config_includes[index]
        if _address(item) == 0:
            if not result:
                raise RuntimeError("Empty native rules include list")
            return result
        path = pathlib.Path(item.string(errors="strict"))
        if not path.is_file():
            raise RuntimeError("Native rules include cannot be read: " + str(path))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result.append({"path": str(path.resolve()), "sha256": digest})
    raise RuntimeError("Native rule include count exceeds capture limit")


class CaptureOnce(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_setlevels", internal=False)
        self.silent = True
        self.captured = False

    def stop(self):
        if self.captured:
            return False
        try:
            depth = int(gdb.parse_and_eval("nnode"))
            if depth:
                return False
            scenario_path = pathlib.Path(os.environ["RULEVIS_NATIVE_SCENARIO"])
            output = pathlib.Path(os.environ["RULEVIS_NATIVE_OUTPUT"])
            payload = json.loads(scenario_path.read_text(encoding="utf-8"))
            scenario_id = os.environ["RULEVIS_NATIVE_SCENARIO_ID"]
            if "scenarios" in payload:
                matching = [
                    item for item in payload["scenarios"]
                    if item.get("id") == scenario_id
                ]
                if len(matching) != 1:
                    raise ValueError("Scenario is missing or duplicated in fixture")
                scenario = matching[0]
            else:
                scenario = payload
                if scenario.get("id") != scenario_id:
                    raise ValueError("Scenario ID differs from supplied fixture")
            head = gdb.parse_and_eval("node")
            snapshot = _capture(head, scenario)
            included = gdb.parse_and_eval("Config.includes")
            loaded_files = _loaded_rule_files(included)
            artifact = {
                "capture_format": "gdb_wazuh_41410_v2",
                "scenario_id": scenario["id"],
                "snapshot": snapshot,
                "loaded_rule_files": loaded_files,
            }
            # No output is written unless native traversal fully succeeds.
            temp = output.with_suffix(output.suffix + ".tmp")
            temp.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            temp.replace(output)
            self.captured = True
            gdb.write("RuleVis native snapshot: " + str(output) + "\n")
            return True
        except Exception as exc:
            gdb.write("RuleVis native capture failed: " + str(exc) + "\n",
                      gdb.STDERR)
            return True


CaptureOnce()
