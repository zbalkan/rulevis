from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final, Optional

def valid_if_sid(value: Optional[str]) -> bool:
    """Match Wazuh 4.14.10's allowed if_sid characters (not its lookup)."""
    return value is None or (
        bool(value) and all(char in "0123456789, " for char in value)
    )


def active_temporal_sid(value: Optional[int | str]) -> bool:
    """Wazuh's integer if_matched_sid field activates only when nonzero.

    Decimal strings are accepted because the graph generator preserves a
    normalized textual representation of the parsed integer.
    """
    return value is not None and bool(str(value).lstrip("0"))


DEFAULT_CATEGORY: Final[str] = "syslog"
MAX_RULE_ID_DIGITS: Final[int] = 6


def normalize_rule_id(value: str) -> Optional[str]:
    """Return Wazuh's canonical numeric rule ID, or None if invalid."""
    if (
        not value
        or not value.isascii()
        or not value.isdigit()
        or len(value) > MAX_RULE_ID_DIGITS
    ):
        return None
    return str(int(value))


def wazuh_load_priority(level: int, accuracy: int = 1) -> int:
    """Return the level value used while Wazuh builds RuleNode lists."""
    priority = 99 if level == 0 else level
    if accuracy:
        priority *= 100
    return priority


def wazuh_runtime_level(load_priority: int) -> int:
    """Mirror Wazuh 4.14.10 _setlevels() normalization."""
    if load_priority == 9900:
        return 0
    if load_priority >= 100:
        return load_priority // 100
    return load_priority


def ascii_fold(data: bytes) -> bytes:
    """Mirror the ASCII case folding used by Wazuh's charmap."""
    return bytes(
        byte + 32 if 65 <= byte <= 90 else byte
        for byte in data
    )


def os_word_match(pattern: str, value: str) -> bool:
    """Mirror OS_WordMatch semantics used by Wazuh 4.14.10 if_group."""
    if not pattern:
        return False

    raw_value = ascii_fold(value.encode("utf-8"))

    for alternative in pattern.encode("utf-8").split(b"|"):
        if not alternative:
            continue

        anchored = alternative.startswith(b"^")
        candidate = alternative[1:] if anchored else alternative
        candidate = ascii_fold(candidate)

        if anchored:
            if raw_value.startswith(candidate):
                return True
        elif candidate in raw_value:
            return True

    return False


def os_match(pattern: str, value: str) -> bool:
    """Mirror Wazuh 4.14.10 OSMatch_Compile/Execute for group matching.

    Unlike OS_WordMatch, OSMatch accepts negation, suffix and exact
    anchors. All alternatives are case-insensitive by default.
    """
    if pattern is None:
        return False

    negate = pattern.startswith("!")
    if negate:
        pattern = pattern[1:]

    data = ascii_fold(value.encode("utf-8"))
    for raw in pattern.encode("utf-8").split(b"|"):
        anchored_start = raw.startswith(b"^")
        anchored_end = raw.endswith(b"$")
        term = raw[1:] if anchored_start else raw
        term = term[:-1] if anchored_end else term
        term = ascii_fold(term)

        if anchored_start and anchored_end:
            matches = data == term
        elif anchored_start:
            matches = data.startswith(term)
        elif anchored_end:
            matches = data.endswith(term)
        else:
            matches = term in data

        if matches:
            return not negate
    return negate


@dataclass(frozen=True)
class StructuralParentSelection:
    """Wazuh structural-parent synthesis and OS_AddChild branch selection.

    Declarative relationships are retained even if a branch is shadowed or
    its selected attachment is rejected. Attachment success is separate.
    """

    if_sid: Optional[str]
    if_level: Optional[int]
    if_group: Optional[str]
    sources: dict[str, str]
    effective: str
    shadowed: tuple[str, ...]
    rejected: bool = False
    rejection_reason: Optional[str] = None

    def metadata(self) -> dict[str, object]:
        return {
            "effective": self.effective,
            "shadowed": list(self.shadowed),
            "shadowed_sources": {
                key: self.sources[key] for key in self.shadowed
                if key in self.sources
            },
            "sources": dict(self.sources),
            "rejected": self.rejected,
            **(
                {"invalid": "if_level", "rejection_reason": self.rejection_reason}
                if self.rejected else {}
            ),
        }


def resolve_structural_parent_selectors(
    *,
    if_sid: Optional[str],
    if_level: Optional[int],
    if_group: Optional[str],
    if_matched_sid: Optional[int | str],
    if_matched_group: Optional[str],
) -> StructuralParentSelection:
    """Resolve Wazuh 4.14.10 parent synthesis and precedence once.

    rules.c synthesizes group before SID, only when no structural parent
    selector is already set. rules_list.c then selects if_sid, if_level,
    if_group, or category in that order. A zero if_level selects the level
    branch but rejects the rule; there is no if_group fallback.
    """
    sid = if_sid
    group = if_group
    sources: dict[str, str] = {}
    if sid:
        sources["if_sid"] = "if_sid"
    if group:
        sources["if_group"] = "if_group"
    if not sid and not group and if_matched_group:
        group = if_matched_group
        sources["if_group"] = "if_matched_group"
    if not sid and not group and active_temporal_sid(if_matched_sid):
        sid = str(if_matched_sid)
        sources["if_sid"] = "if_matched_sid"

    rejected = not sid and if_level == 0
    effective = (
        "if_sid" if sid
        else "invalid_if_level" if rejected
        else "if_level" if if_level is not None
        else "if_group" if group
        else "category"
    )
    shadowed: list[str] = []
    if if_level is not None and effective == "if_sid":
        shadowed.append("if_level")
    if group and effective in {"if_sid", "if_level"}:
        shadowed.append("if_group")
    if if_level is not None:
        sources["if_level"] = "if_level"
    return StructuralParentSelection(
        if_sid=sid,
        if_level=if_level,
        if_group=group,
        sources=sources,
        effective=effective,
        shadowed=tuple(shadowed),
        rejected=rejected,
        rejection_reason="invalid_if_level" if rejected else None,
    )


@dataclass(frozen=True)
class RuleDeclaration:
    """One rule declaration in Wazuh load order."""

    sequence: int
    rule_id: str
    file: str

    source_level: int
    load_priority: int
    accuracy: int
    noalert: bool
    overwrite: bool

    runtime_group: str
    display_groups: tuple[str, ...]
    category: str

    if_sid: Optional[str] = None
    if_level: Optional[int] = None
    if_group: Optional[str] = None
    if_matched_sid: Optional[int] = None
    if_matched_group: Optional[str] = None
    invalid_if_matched_sid: Optional[str] = None
    invalid_if_level: Optional[str] = None

    conditions: tuple[dict[str, object], ...] = ()
    temporal_conditions: tuple[dict[str, object], ...] = ()


@dataclass
class RuleCatalog:
    """Ordered rule declarations preserved independently of the graph."""

    declarations: list[RuleDeclaration] = field(default_factory=list)

    def append(
        self,
        *,
        rule_id: str,
        file: str,
        source_level: int,
        accuracy: int,
        noalert: bool,
        overwrite: bool,
        runtime_group: str,
        display_groups: list[str],
        category: Optional[str],
        if_sid: Optional[str],
        if_level: Optional[int],
        if_group: Optional[str],
        if_matched_sid: Optional[int],
        if_matched_group: Optional[str],
        conditions: list[dict[str, object]],
        temporal_conditions: list[dict[str, object]],
        invalid_if_matched_sid: Optional[str] = None,
        invalid_if_level: Optional[str] = None,
    ) -> RuleDeclaration:
        normalized_rule_id = normalize_rule_id(rule_id)

        declaration = RuleDeclaration(
            sequence=len(self.declarations),
            rule_id=(
                normalized_rule_id
                if normalized_rule_id is not None
                else rule_id
            ),
            file=file,
            source_level=source_level,
            load_priority=wazuh_load_priority(source_level, accuracy),
            accuracy=accuracy,
            noalert=noalert,
            overwrite=overwrite,
            runtime_group=runtime_group,
            display_groups=tuple(display_groups),
            category=(
                DEFAULT_CATEGORY
                if category is None
                else category
            ),
            if_sid=if_sid,
            if_level=if_level,
            if_group=if_group,
            if_matched_sid=if_matched_sid,
            if_matched_group=if_matched_group,
            invalid_if_matched_sid=invalid_if_matched_sid,
            invalid_if_level=invalid_if_level,
            conditions=tuple(dict(condition) for condition in conditions),
            temporal_conditions=tuple(
                dict(condition) for condition in temporal_conditions
            ),
        )
        self.declarations.append(declaration)
        return declaration
