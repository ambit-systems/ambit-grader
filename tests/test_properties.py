# Copyright (c) 2026 Ambit Systems Pty Ltd. All rights reserved.
# Proprietary and confidential. See LICENSE for terms.

"""Tests for the per-record property checks and value predicates."""

from __future__ import annotations

import pytest

from ambit_grader.models import Sufficiency
from ambit_grader.properties import (
    action_boundary,
    actor_identity,
    data_touch,
    lifecycle_context,
    policy_basis,
)
from ambit_grader.sufficiency import dig, interpretable, is_genesis


def test_placeholder_digests_are_not_interpretable():
    assert not interpretable("aaaaaaaaaaaaaaaa")
    assert not interpretable("0000000000000000")
    assert interpretable("9f2c41ab7de05513")


def test_empty_containers_are_not_interpretable_but_false_is():
    assert not interpretable({})
    assert not interpretable([])
    assert not interpretable("")
    assert not interpretable(None)
    assert interpretable(False)
    assert interpretable(0)


def test_genesis_marker_is_recognised():
    assert is_genesis("0" * 64)
    assert not is_genesis("h1")
    assert not is_genesis(None)


def test_dig():
    record = {"a": {"b": {"c": 1}}, "x": "", "y": "real"}
    assert dig(record, "a.b.c") == 1
    assert dig(record, "a.b.missing") is None
    assert dig(record, "a.b.c.d") is None


def test_actor_identity_conflict_is_worse_than_absence():
    assert actor_identity({"actor_id": "a", "actor": {"id": "b"}})[0] is Sufficiency.CONFLICTING
    assert actor_identity({"actor_id": "a", "actor": {"id": "a"}})[0] is Sufficiency.FULLY_FILLABLE
    assert actor_identity({"actor_id": "a"})[0] is Sufficiency.FULLY_FILLABLE
    assert actor_identity({})[0] is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_action_boundary_needs_all_three_parts():
    full = {"action": {"type": "read", "boundary": "tool_execution"}, "tool_name": "t"}
    assert action_boundary(full)[0] is Sufficiency.FULLY_FILLABLE
    assert action_boundary({"tool_name": "t"})[0] is Sufficiency.PARTIALLY_FILLABLE
    assert action_boundary({})[0] is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_placeholder_hash_is_unfillable_not_opaque():
    """Opaque is the ML-opacity boundary (3.4), never a stub digest."""
    assert policy_basis({"policy_hash": "a" * 32})[0] is Sufficiency.STRUCTURALLY_UNFILLABLE
    assert policy_basis({"policy_hash": "9f2c41ab"})[0] is Sufficiency.PARTIALLY_FILLABLE
    full = {"policy_hash": "9f2c41ab", "matched_rule_id": "r"}
    assert policy_basis(full)[0] is Sufficiency.FULLY_FILLABLE


def test_policy_basis_detects_disagreeing_copies():
    record = {"policy_hash": "aaa111", "evidence": {"hashes": {"policy_hash": "bbb222"}}}
    assert policy_basis(record)[0] is Sufficiency.CONFLICTING


def test_data_touch_and_lifecycle_context():
    assert (
        data_touch({"object": {"kind": "f", "id": "i", "domain": "d"}})[0]
        is Sufficiency.FULLY_FILLABLE
    )
    assert data_touch({"object": {"kind": "f"}})[0] is Sufficiency.PARTIALLY_FILLABLE
    assert data_touch({})[0] is Sufficiency.STRUCTURALLY_UNFILLABLE

    full = {"ts": "2026-01-01T00:00:00Z", "seq": 0, "governance_mode": "enforcement"}
    assert lifecycle_context(full)[0] is Sufficiency.FULLY_FILLABLE
    assert lifecycle_context({"ts": "2026-01-01T00:00:00Z"})[0] is Sufficiency.PARTIALLY_FILLABLE
    assert lifecycle_context({})[0] is Sufficiency.STRUCTURALLY_UNFILLABLE


def test_checks_report_the_within_record_fill_fraction():
    """Two parts of three is not the same evidence as one of three.

    Collapsing both to the category's flat 0.5 is the blindness 3.5's
    "confidence in [0, 1]" exists to avoid, one level below the corpus.
    """
    two_of_three = {"action": {"type": "write", "boundary": "tool_execution"}}
    one_of_three = {"tool_name": "t"}

    cat_a, frac_a = action_boundary(two_of_three)
    cat_b, frac_b = action_boundary(one_of_three)

    assert cat_a is cat_b is Sufficiency.PARTIALLY_FILLABLE
    assert frac_a == pytest.approx(2 / 3)
    assert frac_b == pytest.approx(1 / 3)
    assert frac_a > frac_b


def test_conflict_carries_zero_confidence():
    _cat, fraction = actor_identity({"actor_id": "a", "actor": {"id": "b"}})
    assert fraction == 0.0
