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


def _recalculate(node: _PriorityNode) -> None:
    node.height = 1 + max(_height(node.left), _height(node.right))
    node.size = 1 + _size(node.left) + _size(node.right)

    minimum = node.priority
    if node.left is not None:
        minimum = min(minimum, node.left.min_priority)
    if node.right is not None:
        minimum = min(minimum, node.right.min_priority)
    node.min_priority = minimum


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

    def item_at(self, index: int) -> int:
        """Return the item at a zero-based physical sequence index."""
        if index < 0 or index >= len(self):
            raise IndexError(index)

        node = self._root
        current = index
        while node is not None:
            left_size = _size(node.left)
            if current < left_size:
                node = node.left
            elif current == left_size:
                return node.item
            else:
                current -= left_size + 1
                node = node.right

        raise IndexError(index)

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



class _MaskNode:
    __slots__ = (
        "item",
        "category_bit",
        "left",
        "right",
        "parent",
        "height",
        "size",
        "category_mask",
    )

    def __init__(self, item: int, category_bit: int) -> None:
        self.item = item
        self.category_bit = category_bit
        self.left: Optional[_MaskNode] = None
        self.right: Optional[_MaskNode] = None
        self.parent: Optional[_MaskNode] = None
        self.height = 1
        self.size = 1
        self.category_mask = category_bit


def _mask_height(node: Optional[_MaskNode]) -> int:
    return node.height if node is not None else 0


def _mask_size(node: Optional[_MaskNode]) -> int:
    return node.size if node is not None else 0


def _mask_value(node: Optional[_MaskNode]) -> int:
    return node.category_mask if node is not None else 0


def _mask_recalculate(node: _MaskNode) -> None:
    node.height = 1 + max(
        _mask_height(node.left),
        _mask_height(node.right),
    )
    node.size = 1 + _mask_size(node.left) + _mask_size(node.right)
    node.category_mask = (
        node.category_bit
        | _mask_value(node.left)
        | _mask_value(node.right)
    )


def _mask_rotate_left(node: _MaskNode) -> _MaskNode:
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
    _mask_recalculate(node)
    _mask_recalculate(pivot)
    return pivot


def _mask_rotate_right(node: _MaskNode) -> _MaskNode:
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
    _mask_recalculate(node)
    _mask_recalculate(pivot)
    return pivot


def _mask_balance(node: _MaskNode) -> _MaskNode:
    _mask_recalculate(node)
    balance = _mask_height(node.left) - _mask_height(node.right)

    if balance > 1:
        if (
            node.left is not None
            and _mask_height(node.left.left)
            < _mask_height(node.left.right)
        ):
            node.left = _mask_rotate_left(node.left)
            node.left.parent = node
        return _mask_rotate_right(node)

    if balance < -1:
        if (
            node.right is not None
            and _mask_height(node.right.right)
            < _mask_height(node.right.left)
        ):
            node.right = _mask_rotate_right(node.right)
            node.right.parent = node
        return _mask_rotate_left(node)

    return node


def _mask_insert_at(
    node: Optional[_MaskNode],
    index: int,
    new_node: _MaskNode,
) -> _MaskNode:
    if node is None:
        return new_node

    left_size = _mask_size(node.left)
    if index <= left_size:
        node.left = _mask_insert_at(node.left, index, new_node)
        node.left.parent = node
    else:
        node.right = _mask_insert_at(
            node.right,
            index - left_size - 1,
            new_node,
        )
        node.right.parent = node

    return _mask_balance(node)


class CategoryOrder:
    """Dynamic preorder tokens indexed by category bit."""

    def __init__(self) -> None:
        self._root: Optional[_MaskNode] = None
        self._nodes: dict[int, _MaskNode] = {}

    def __len__(self) -> int:
        return _mask_size(self._root)

    @property
    def height(self) -> int:
        return _mask_height(self._root)

    def _insert_at(
        self,
        index: int,
        item: int,
        category_bit: int,
    ) -> None:
        if item in self._nodes:
            raise ValueError(f"Duplicate order item: {item}")
        if index < 0 or index > len(self):
            raise IndexError(index)

        node = _MaskNode(item, category_bit)
        self._root = _mask_insert_at(self._root, index, node)
        self._root.parent = None
        self._nodes[item] = node

    def append(self, item: int, category_bit: int = 0) -> None:
        self._insert_at(len(self), item, category_bit)

    def insert_before(
        self,
        reference: int,
        item: int,
        category_bit: int = 0,
    ) -> None:
        self._insert_at(self.rank(reference), item, category_bit)

    def update_category(self, item: int, category_bit: int) -> None:
        node = self._nodes[item]
        node.category_bit = category_bit

        current: Optional[_MaskNode] = node
        while current is not None:
            _mask_recalculate(current)
            current = current.parent

    def first_with_category(self, category_bit: int) -> Optional[int]:
        node = self._root
        if node is None or not (node.category_mask & category_bit):
            return None

        while node is not None:
            if (
                node.left is not None
                and node.left.category_mask & category_bit
            ):
                node = node.left
                continue
            if node.category_bit & category_bit:
                return node.item
            node = node.right

        return None

    def rank(self, item: int) -> int:
        node = self._nodes[item]
        result = _mask_size(node.left)

        while node.parent is not None:
            parent = node.parent
            if node is parent.right:
                result += _mask_size(parent.left) + 1
            node = parent

        return result

    def __iter__(self) -> Iterator[int]:
        stack: list[_MaskNode] = []
        node = self._root

        while stack or node is not None:
            while node is not None:
                stack.append(node)
                node = node.left

            node = stack.pop()
            yield node.item
            node = node.right
