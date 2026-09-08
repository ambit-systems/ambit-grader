# Copyright (c) 2026 Ambit Systems Pty Ltd.
# SPDX-License-Identifier: Apache-2.0

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
from ambit_grader.sufficiency import (
    dig,
    interpretable,
    is_genesis,
    is_timestamp,
    is_unix_nanoseconds,
)


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


def test_policy_basis_detects_disagreeing_rule_aliases():
    record = {
        "policy_hash": "policy-1",
        "matched_rule_id": "rule-flat",
        "evidence": {"naming": {"matched_rule_id": "rule-nested"}},
    }
    assert policy_basis(record) == (Sufficiency.CONFLICTING, 0.0)


def test_policy_basis_accepts_matching_rule_aliases():
    record = {
        "policy_hash": "policy-1",
        "matched_rule_id": "rule-1",
        "evidence": {"naming": {"matched_rule_id": "rule-1"}},
    }
    assert policy_basis(record)[0] is Sufficiency.FULLY_FILLABLE


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


def test_policy_basis_is_capped_by_validated_source_confidence():
    record = {
        "policy_hash": "policy-A",
        "matched_rule_id": "rule-1",
        "_policy_confidence": 0.4,
    }
    assert policy_basis(record) == (Sufficiency.PARTIALLY_FILLABLE, 0.4)


@pytest.mark.parametrize(
    "timestamp",
    (
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.123456789Z",
        "2026-01-01T00:00:00+00:00",
    ),
)
def test_timestamp_accepts_semantically_valid_utc_instants(timestamp):
    assert is_timestamp(timestamp)
    assert (
        lifecycle_context({"ts": timestamp, "seq": 0, "governance_mode": "enforcement"})[0]
        is Sufficiency.FULLY_FILLABLE
    )


@pytest.mark.parametrize(
    "timestamp",
    (
        "not-a-time",
        " 2026-01-01T00:00:00Z ",
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:00+01:00",
        "2026-01-01 00:00:00Z",
        0,
        1.0,
    ),
)
def test_timestamp_rejects_non_utc_junk_and_ambiguous_numeric_values(timestamp):
    assert not is_timestamp(timestamp)
    sufficiency, confidence = lifecycle_context(
        {"ts": timestamp, "seq": 0, "governance_mode": "enforcement"}
    )
    assert sufficiency is Sufficiency.PARTIALLY_FILLABLE
    assert confidence == pytest.approx(2 / 3)


def test_lifecycle_context_detects_distinct_timestamp_aliases():
    record = {
        "ts": "2026-01-01T00:00:00Z",
        "timestamp_utc": "2026-01-01T00:00:01+00:00",
        "seq": 0,
        "governance_mode": "enforcement",
    }
    assert lifecycle_context(record) == (Sufficiency.CONFLICTING, 0.0)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "malformed",
    ["not-a-time", True, {"instant": "2026-01-01T00:00:00Z"}, ["2026-01-01"]],
)
def test_lifecycle_context_quarantines_valid_and_malformed_timestamp_aliases(reverse, malformed):
    valid = "2026-01-01T00:00:00Z"
    record = (
        {"ts": malformed, "timestamp_utc": valid}
        if reverse
        else {"ts": valid, "timestamp_utc": malformed}
    )
    record.update(seq=0, governance_mode="enforcement")
    assert lifecycle_context(record) == (Sufficiency.CONFLICTING, 0.0)


@pytest.mark.parametrize("empty", [None, "", [], {}])
def test_lifecycle_context_treats_empty_timestamp_alias_as_absent(empty):
    record = {
        "ts": "2026-01-01T00:00:00Z",
        "timestamp_utc": empty,
        "seq": 0,
        "governance_mode": "enforcement",
    }
    assert lifecycle_context(record)[0] is Sufficiency.FULLY_FILLABLE


@pytest.mark.parametrize(
    ("flat", "nested"),
    [
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00"),
        ("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.100000000+00:00"),
        ("2026-01-01T00:00:00.123Z", "2026-01-01T00:00:00.123000000Z"),
    ],
)
def test_lifecycle_context_accepts_equivalent_timestamp_spellings(flat, nested):
    record = {
        "ts": flat,
        "timestamp_utc": nested,
        "seq": 0,
        "governance_mode": "enforcement",
    }
    assert lifecycle_context(record)[0] is Sufficiency.FULLY_FILLABLE


def test_explicit_unix_nanosecond_instants_are_bounded():
    assert is_unix_nanoseconds("1785148029563000000")
    assert is_unix_nanoseconds(1_785_148_029_563_000_000)
    assert not is_unix_nanoseconds("not-a-time")
    assert not is_unix_nanoseconds("999999999999999999999")


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


@pytest.mark.parametrize(
    "junk", [True, ["value"], {"value": 1}, "\x1b", "\u2028", "\u202e", "\ud800"]
)
def test_semantic_fields_reject_non_scalar_or_control_text(junk):
    assert actor_identity({"actor_id": junk, "actor": {"id": junk}})[0] is (
        Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert (
        action_boundary({"action": {"type": junk, "boundary": junk}, "tool_name": junk})[0]
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert (
        policy_basis(
            {
                "policy_hash": junk,
                "evidence": {"hashes": {"policy_hash": junk}},
                "matched_rule_id": junk,
            }
        )[0]
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert (
        data_touch({"object": {"kind": junk, "id": junk, "domain": junk}})[0]
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
    assert (
        lifecycle_context({"ts": junk, "seq": junk, "governance_mode": junk})[0]
        is Sufficiency.STRUCTURALLY_UNFILLABLE
    )
