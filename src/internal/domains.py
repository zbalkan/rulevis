from __future__ import annotations


class BitsetDomain:
    """Exact finite event-set algebra backed by Python integers."""

    def __init__(self, event_count: int) -> None:
        if event_count < 0:
            raise ValueError("event_count must be non-negative")
        self.event_count = event_count
        self.universe = (1 << event_count) - 1

    def normalize(self, value: int) -> int:
        return value & self.universe

    def top(self) -> int:
        return self.universe

    def bottom(self) -> int:
        return 0

    def intersect(self, left: int, right: int) -> int:
        return left & right

    def union(self, left: int, right: int) -> int:
        return left | right

    def difference(self, left: int, right: int) -> int:
        return left & ~right & self.universe

    def is_empty(self, value: int) -> bool:
        return value == 0

    def subset(self, left: int, right: int) -> bool:
        return self.difference(left, right) == 0

    def cardinality(self, value: int) -> int:
        """Return the number of events in a region on Python 3.9+."""
        return bin(self.normalize(value)).count("1")
