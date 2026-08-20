import tempfile
import os

from aep.operations.memory import IncidentMemoryRecord, find_similar, list_incidents, record_incident
from aep.state_store import StateStore


def _store():
    d = tempfile.mkdtemp()
    return StateStore(os.path.join(d, "state.db"))


def test_record_and_list_incidents_survives_a_fresh_store_instance():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "state.db")
    store = StateStore(path)
    record_incident(store, "proj1", IncidentMemoryRecord(
        fingerprint="fp1", incident_id="i1", root_cause="BAD_DEPLOYMENT",
        confidence="HIGH_CONFIDENCE", remediation_used="rollback_nonprod",
        remediation_succeeded=True, environment="development",
    ))
    store.close()

    reopened = StateStore(path)
    records = list_incidents(reopened, "proj1")
    assert len(records) == 1
    assert records[0].fingerprint == "fp1"
    assert records[0].remediation_succeeded


def test_find_similar_matches_only_the_same_fingerprint():
    store = _store()
    record_incident(store, "proj1", IncidentMemoryRecord(
        fingerprint="fp1", incident_id="i1", root_cause="x", confidence="LIKELY",
        remediation_used="restart_workload_nonprod", remediation_succeeded=True, environment="dev",
    ))
    record_incident(store, "proj1", IncidentMemoryRecord(
        fingerprint="fp2", incident_id="i2", root_cause="x", confidence="LIKELY",
        remediation_used="restart_workload_nonprod", remediation_succeeded=False, environment="dev",
    ))
    matches = find_similar(store, "proj1", "fp1")
    assert len(matches) == 1
    assert matches[0].incident_id == "i1"


def test_incidents_are_scoped_per_project():
    store = _store()
    record_incident(store, "proj1", IncidentMemoryRecord(
        fingerprint="fp1", incident_id="i1", root_cause="x", confidence="LIKELY",
        remediation_used="a", remediation_succeeded=True, environment="dev",
    ))
    assert list_incidents(store, "proj2") == []
