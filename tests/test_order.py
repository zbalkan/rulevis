import math

import pytest

from internal.order import PrioritySequence


def test_priority_sequence_matches_wazuh_insertion_order():
    sequence = PrioritySequence()

    sequence.insert(1, 12)
    sequence.insert(2, 8)
    sequence.insert(3, 8)
    sequence.insert(4, 3)
    sequence.insert(5, 10)

    assert list(sequence) == [1, 5, 2, 3, 4]


def test_equal_priority_preserves_insertion_order():
    sequence = PrioritySequence()

    for item in range(10):
        sequence.insert(item, 500)

    assert list(sequence) == list(range(10))


def test_priority_update_does_not_reposition_existing_item():
    sequence = PrioritySequence()

    sequence.insert(1, 12)
    sequence.insert(2, 10)
    sequence.insert(3, 8)
    sequence.insert(4, 3)

    sequence.update_priority(2, 2)

    assert list(sequence) == [1, 2, 3, 4]

    # A new level-9 rule sees the updated priority of item 2 and is therefore
    # inserted before it, while item 2 itself remains in place.
    sequence.insert(5, 9)

    assert list(sequence) == [1, 5, 2, 3, 4]


def test_rank_tracks_insertions_and_rotations():
    sequence = PrioritySequence()

    for item, priority in [
        (10, 10),
        (20, 20),
        (30, 30),
        (40, 40),
        (50, 25),
    ]:
        sequence.insert(item, priority)

    values = list(sequence)
    for expected_rank, item in enumerate(values):
        assert sequence.rank(item) == expected_rank


@pytest.mark.parametrize("count", [32, 256, 2048])
def test_adversarial_insertions_keep_logarithmic_height(count):
    sequence = PrioritySequence()

    # Every new item is inserted at the front.  A list implementation would
    # repeatedly shift all existing elements.
    for item in range(count):
        sequence.insert(item, item)

    maximum_reasonable_height = 2 * math.ceil(math.log2(count + 1))
    assert sequence.height <= maximum_reasonable_height
    assert len(sequence) == count
