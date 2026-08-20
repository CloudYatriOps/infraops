from aep.operations.dependency_graph import ServiceDependencyGraph


def _graph():
    g = ServiceDependencyGraph()
    g.add_dependency("service-a", "database")
    g.add_dependency("database", "cache")
    g.add_dependency("cache", "message-queue")
    g.add_dependency("message-queue", "external-api")
    g.add_dependency("service-b", "service-a")
    g.deployments = {"service-a": "v2", "service-b": "v5"}
    return g


def test_upstream_is_transitive():
    g = _graph()
    assert g.upstream("service-a") == ["database", "cache", "message-queue", "external-api"]


def test_downstream_is_transitive():
    g = _graph()
    assert g.downstream("database") == ["service-a", "service-b"]


def test_blast_radius_includes_downstream_deployments():
    g = _graph()
    blast = g.blast_radius("database")
    assert blast.directly_affected == ["database"]
    assert "service-a" in blast.downstream_services
    assert "service-b" in blast.downstream_services
    assert blast.potentially_affected_deployments == ["v2", "v5"]


def test_leaf_service_has_no_upstream():
    g = _graph()
    assert g.upstream("external-api") == []
    assert g.downstream("external-api") == ["message-queue", "cache", "database", "service-a", "service-b"]
