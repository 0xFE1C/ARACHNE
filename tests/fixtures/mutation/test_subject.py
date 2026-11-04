"""The covering test for ``tests/fixtures/mutation/subject.py`` (a mutation-gate fixture).

It asserts the behaviour the mutation gate expects to be *noticed*: flipping the switch,
moving the boundary or inverting the comparison must fail here. ``unused_helper`` is asserted
on purpose in only one direction, which leaves one live site the gate should report as a
survivor.
"""

from __future__ import annotations

from tests.fixtures.mutation.subject import ENABLED, describe, threshold


def test_the_switch_is_on() -> None:
    assert ENABLED is True


def test_the_limit_is_inclusive() -> None:
    assert threshold(10) is True
    assert threshold(11) is False


def test_describe_splits_at_one_hundred() -> None:
    assert describe(99) == "small"
    assert describe(100) == "large"
