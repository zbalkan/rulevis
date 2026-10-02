from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


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


def _ascii_fold(data: bytes) -> bytes:
    """Mirror the ASCII case folding used by Wazuh's charmap."""
    return bytes(
        byte + 32 if 65 <= byte <= 90 else byte
        for byte in data
    )


def os_word_match(pattern: str, value: str) -> bool:
    """Mirror OS_WordMatch semantics used by Wazuh 4.14.10 if_group."""
    if not pattern:
        return False

    raw_value = _ascii_fold(value.encode("utf-8"))

    for alternative in pattern.encode("utf-8").split(b"|"):
        if not alternative:
            continue

        anchored = alternative.startswith(b"^")
        candidate = alternative[1:] if anchored else alternative
        candidate = _ascii_fold(candidate)

        if anchored:
            if raw_value.startswith(candidate):
                return True
        elif candidate in raw_value:
            return True

    return False


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

    if_sid: Optional[str] = None
    if_level: Optional[int] = None
    if_group: Optional[str] = None
    if_matched_sid: Optional[int] = None
    if_matched_group: Optional[str] = None

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
        if_sid: Optional[str],
        if_level: Optional[int],
        if_group: Optional[str],
        if_matched_sid: Optional[int],
        if_matched_group: Optional[str],
        conditions: list[dict[str, object]],
        temporal_conditions: list[dict[str, object]],
    ) -> RuleDeclaration:
        declaration = RuleDeclaration(
            sequence=len(self.declarations),
            rule_id=rule_id,
            file=file,
            source_level=source_level,
            load_priority=wazuh_load_priority(source_level, accuracy),
            accuracy=accuracy,
            noalert=noalert,
            overwrite=overwrite,
            runtime_group=runtime_group,
            display_groups=tuple(display_groups),
            if_sid=if_sid,
            if_level=if_level,
            if_group=if_group,
            if_matched_sid=if_matched_sid,
            if_matched_group=if_matched_group,
            conditions=tuple(dict(condition) for condition in conditions),
            temporal_conditions=tuple(
                dict(condition) for condition in temporal_conditions
            ),
        )
        self.declarations.append(declaration)
        return declaration
