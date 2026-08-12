"""False-positive suppression model (Phase 4 Part 9/13): suppression,
justification, expiry, reviewer, evidence - "never simply delete a
finding."""
from __future__ import annotations

import pytest

from aep.security.suppressions import (
    is_suppressed, list_suppressions, revoke_suppression, suppress_finding,
)
from aep.state_store import StateStore, now_iso


@pytest.fixture()
def store(tmp_path):
    return StateStore(str(tmp_path / "state.db"))


def test_suppression_requires_all_five_fields(store):
    with pytest.raises(ValueError):
        suppress_finding(store, "p1", "f1", justification="", reviewer="kparmar", evidence="e")
    with pytest.raises(ValueError):
        suppress_finding(store, "p1", "f1", justification="j", reviewer="", evidence="e")
    with pytest.raises(ValueError):
        suppress_finding(store, "p1", "f1", justification="j", reviewer="kparmar", evidence="")


def test_suppress_and_list_round_trip(store):
    suppress_finding(store, "p1", "gitleaks:aws-access-token:tests/conftest.py:63",
                      justification="test fixture placeholder credential, not real",
                      reviewer="kparmar", evidence="reviewed tests/conftest.py:63 manually")
    suppressions = list_suppressions(store, "p1")
    assert len(suppressions) == 1
    s = suppressions[0]
    assert s.finding_id == "gitleaks:aws-access-token:tests/conftest.py:63"
    assert s.reviewer == "kparmar"
    assert s.revoked is False
    assert s.is_active() is True


def test_is_suppressed_filters_only_active_suppressions(store):
    suppress_finding(store, "p1", "f1", justification="j", reviewer="r", evidence="e")
    suppressions = list_suppressions(store, "p1")
    assert is_suppressed(suppressions, "f1") is not None
    assert is_suppressed(suppressions, "f2") is None


def test_expired_suppression_is_not_active_but_still_listed(store):
    past = "2000-01-01T00:00:00+00:00"
    suppress_finding(store, "p1", "f1", justification="j", reviewer="r", evidence="e", expiry=past)
    suppressions = list_suppressions(store, "p1")
    assert len(suppressions) == 1  # never deleted
    assert suppressions[0].is_active() is False
    assert is_suppressed(suppressions, "f1") is None  # correctly treated as open again


def test_revocation_never_deletes_the_original_record(store):
    suppress_finding(store, "p1", "f1", justification="j", reviewer="r", evidence="e")
    revoke_suppression(store, "p1", "f1", revoked_by="lead-reviewer",
                        reason="finding was re-triaged as a real issue")
    suppressions = list_suppressions(store, "p1")
    assert len(suppressions) == 1
    s = suppressions[0]
    assert s.revoked is True
    assert s.revoked_by == "lead-reviewer"
    assert s.justification == "j"  # original justification still visible
    assert is_suppressed(suppressions, "f1") is None


def test_suppressions_are_scoped_per_project(store):
    suppress_finding(store, "p1", "f1", justification="j", reviewer="r", evidence="e")
    assert list_suppressions(store, "p2") == []


def test_no_expiry_means_suppression_never_lapses(store):
    suppress_finding(store, "p1", "f1", justification="j", reviewer="r", evidence="e", expiry=None)
    suppressions = list_suppressions(store, "p1")
    assert suppressions[0].is_active(now=now_iso()) is True
