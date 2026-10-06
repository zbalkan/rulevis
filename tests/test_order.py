import math

import pytest

from internal.order import CategoryOrder, PrioritySequence


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



def test_category_order_finds_first_matching_preorder_token():
    order = CategoryOrder()
    order.append(0, 1)
    order.append(2, 2)
    order.append(3)
    order.append(1)
    order.append(4, 2)
    order.append(5)

    assert order.first_with_category(1) == 0
    assert order.first_with_category(2) == 2

    order.update_category(2, 4)

    assert order.first_with_category(2) == 4
    assert order.first_with_category(4) == 2


def test_category_order_insert_before_preserves_preorder():
    order = CategoryOrder()
    order.append(0, 1)
    order.append(1)
    order.insert_before(1, 2, 2)
    order.insert_before(1, 3)

    assert list(order) == [0, 2, 3, 1]
    assert order.rank(2) == 1
    assert order.first_with_category(2) == 2



def test_priority_sequence_has_no_finite_empty_subtree_sentinel():
    sequence = PrioritySequence()
    low = 2**40
    middle = low + 100
    high = low + 200

    sequence.insert(1, low)
    sequence.insert(2, high)
    sequence.insert(3, middle)

    assert list(sequence) == [2, 3, 1]
