from __future__ import annotations

from collections.abc import Iterator
from typing import Optional


class _PriorityNode:
    __slots__ = (
        "item",
        "priority",
        "left",
        "right",
        "parent",
        "height",
        "size",
        "min_priority",
    )

    def __init__(self, item: int, priority: int) -> None:
        self.item = item
        self.priority = priority
        self.left: Optional[_PriorityNode] = None
        self.right: Optional[_PriorityNode] = None
        self.parent: Optional[_PriorityNode] = None
        self.height = 1
        self.size = 1
        self.min_priority = priority


def _height(node: Optional[_PriorityNode]) -> int:
    return node.height if node is not None else 0


def _size(node: Optional[_PriorityNode]) -> int:
    return node.size if node is not None else 0


def _minimum(node: Optional[_PriorityNode]) -> int:
    return node.min_priority if node is not None else 2**31 - 1


def _recalculate(node: _PriorityNode) -> None:
    node.height = 1 + max(_height(node.left), _height(node.right))
    node.size = 1 + _size(node.left) + _size(node.right)
    node.min_priority = min(
        node.priority,
        _minimum(node.left),
        _minimum(node.right),
    )


def _rotate_left(node: _PriorityNode) -> _PriorityNode:
    pivot = node.right
    if pivot is None:
        return node

    old_parent = node.parent
    middle = pivot.left

    pivot.left = node
    pivot.parent = old_parent

    node.parent = pivot
    node.right = middle
    if middle is not None:
        middle.parent = node

    _recalculate(node)
    _recalculate(pivot)
    return pivot


def _rotate_right(node: _PriorityNode) -> _PriorityNode:
    pivot = node.left
    if pivot is None:
        return node

    old_parent = node.parent
    middle = pivot.right

    pivot.right = node
    pivot.parent = old_parent

    node.parent = pivot
    node.left = middle
    if middle is not None:
        middle.parent = node

    _recalculate(node)
    _recalculate(pivot)
    return pivot


def _balance(node: _PriorityNode) -> _PriorityNode:
    _recalculate(node)
    balance = _height(node.left) - _height(node.right)

    if balance > 1:
        if (
            node.left is not None
            and _height(node.left.left) < _height(node.left.right)
        ):
            node.left = _rotate_left(node.left)
            node.left.parent = node
        return _rotate_right(node)

    if balance < -1:
        if (
            node.right is not None
            and _height(node.right.right) < _height(node.right.left)
        ):
            node.right = _rotate_right(node.right)
            node.right.parent = node
        return _rotate_left(node)

    return node


def _insert_at(
    node: Optional[_PriorityNode],
    index: int,
    new_node: _PriorityNode,
) -> _PriorityNode:
    if node is None:
        return new_node

    left_size = _size(node.left)
    if index <= left_size:
        node.left = _insert_at(node.left, index, new_node)
        node.left.parent = node
    else:
        node.right = _insert_at(
            node.right,
            index - left_size - 1,
            new_node,
        )
        node.right.parent = node

    return _balance(node)


class PrioritySequence:
    """Ordered Wazuh siblings with logarithmic insertion.

    Physical sequence order is independent from priority.  This matters after
    an overwrite: Wazuh mutates RuleInfo.level but does not reposition the
    existing RuleNode.  A new rule is inserted before the first existing node
    whose *current* priority is lower.
    """

    def __init__(self) -> None:
        self._root: Optional[_PriorityNode] = None
        self._nodes: dict[int, _PriorityNode] = {}

    def __len__(self) -> int:
        return _size(self._root)

    @property
    def height(self) -> int:
        return _height(self._root)

    def _first_lower_index(self, priority: int) -> Optional[int]:
        node = self._root
        offset = 0

        while node is not None:
            if (
                node.left is not None
                and node.left.min_priority < priority
            ):
                node = node.left
                continue

            left_size = _size(node.left)
            if node.priority < priority:
                return offset + left_size

            offset += left_size + 1
            if (
                node.right is None
                or node.right.min_priority >= priority
            ):
                return None

            node = node.right

        return None

    def insert(self, item: int, priority: int) -> int:
        """Insert using Wazuh's first-lower-priority rule.

        Returns the physical sequence index used for the insertion.
        """
        if item in self._nodes:
            raise ValueError(f"Duplicate sequence item: {item}")

        index = self._first_lower_index(priority)
        if index is None:
            index = len(self)

        new_node = _PriorityNode(item, priority)
        self._root = _insert_at(self._root, index, new_node)
        self._root.parent = None
        self._nodes[item] = new_node
        return index

    def update_priority(self, item: int, priority: int) -> None:
        """Update current priority without changing physical order."""
        node = self._nodes[item]
        node.priority = priority

        current: Optional[_PriorityNode] = node
        while current is not None:
            _recalculate(current)
            current = current.parent

    def rank(self, item: int) -> int:
        """Return the current zero-based physical sequence index."""
        node = self._nodes[item]
        result = _size(node.left)

        while node.parent is not None:
            parent = node.parent
            if node is parent.right:
                result += _size(parent.left) + 1
            node = parent

        return result

    def __iter__(self) -> Iterator[int]:
        stack: list[_PriorityNode] = []
        node = self._root

        while stack or node is not None:
            while node is not None:
                stack.append(node)
                node = node.left

            node = stack.pop()
            yield node.item
            node = node.right
