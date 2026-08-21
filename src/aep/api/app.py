"""Stage D Wave 1 product API: a THIN Flask layer over the existing AEP
engine. Every handler below calls into the same underlying
Orchestrator/SkillRegistry/PolicyEngine/repository code the CLI
(`src/aep/cli.py`) already uses - no business logic is duplicated here.
See docs/API.md for the full route list, auth model, and guarantees.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from flask import Flask, g, jsonify, request, send_from_directory

from ..db.factory import build_state_store
from ..db.postgres import ConnectionPool, PostgresFindingRepository, PostgresProjectRepository
from ..db.state_store_postgres import dsn_from_env
from ..db.models import ProjectRecord
from ..models import ProjectConfig, Task, TaskStatus
from ..policy import PolicyEngine
from ..skills.factory import build_skill_registry
from ..skills.definitions import seed_canonical_skills
from ..deployment.evidence import list_deployment_evidence
from ..operations.memory import list_incidents
from ..runtime.status import build_runtime_status_payload
from ..cli import _build_providers_payload
from .. import scan_lifecycle
from . import auth

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_POLICY_PATH = str(Path(__file__).resolve().parent.parent / "config" / "policy.yaml")


def create_app(db_backend: Optional[str] = None) -> Flask:
    app = Flask(__name__)

    # One shared durable store + skill registry + connection pool for the
    # whole process - the SAME pattern `build_orchestrator` uses per
    # call, just constructed once here instead of once per request, since
    # a request-scoped Postgres connection pool would defeat the point of
    # pooling. `store` is a `PostgresStateStore`/legacy `StateStore` (see
    # db/factory.py); `pool` is a raw `ConnectionPool` for the repository
    # classes (projects/findings/api_keys) that aren't already wrapped by
    # `store`'s facade.
    app.config["AEP_STORE"] = build_state_store("aep_platform.db", db_backend=db_backend)
    app.config["AEP_POOL"] = ConnectionPool(dsn_from_env())
    app.config["AEP_SKILL_REGISTRY"] = build_skill_registry(backend="postgres")
    seed_canonical_skills(app.config["AEP_SKILL_REGISTRY"])
    app.config["AEP_DB_BACKEND"] = db_backend

    # `events.project_id` is a NOT NULL foreign key to `projects` (see
    # src/aep/migrations_sql/0001_initial_schema.sql) - there is no "no
    # project" event. Org-wide/system requests (no project_scope) are
    # audit-logged against one fixed, auto-provisioned sentinel project
    # row instead of inventing a nullable-FK schema change for this.
    SENTINEL_PROJECT_ID = "00000000-0000-0000-0000-000000000000"
    app.config["AEP_SENTINEL_PROJECT_ID"] = SENTINEL_PROJECT_ID
    app.config["AEP_STORE"].ensure_project(SENTINEL_PROJECT_ID, name="(api-org-wide)")

    if auth.dev_mode_enabled():
        print("*** AEP_API_DEV_MODE=1: API AUTHENTICATION IS DISABLED. "
              "Never run this way outside local development. ***")

    @app.before_request
    def _authenticate():
        if request.path == "/health":
            return None
        if auth.dev_mode_enabled():
            g.project_scope = None
            g.api_key_label = "(dev-mode, unauthenticated)"
            return None
        header = request.headers.get("Authorization", "")
        raw_key = header[len("Bearer "):] if header.startswith("Bearer ") else None
        result = auth.verify_key(app.config["AEP_POOL"], raw_key)
        if not result.ok:
            return jsonify({"error": result.reason}), 401
        g.project_scope = result.project_scope
        g.api_key_label = raw_key[:8] + "..."

    @app.after_request
    def _audit_log(response):
        # BUG-0007: the Stage D UI (Vite dev server, a different origin/port
        # than this Flask API) has never actually been able to fetch from
        # this API in a browser - no CORS header was ever added, so every
        # request was silently blocked by the browser's CORS preflight
        # check (discovered via real Playwright browser inspection during
        # the Phase 10 UI validation batch). Only add the header in the
        # same AEP_API_DEV_MODE=1 local-dev posture that already disables
        # auth above - never in a real deployment, where the UI should be
        # served from the same origin or through a configured reverse
        # proxy rather than a blanket wildcard CORS header.
        if auth.dev_mode_enabled():
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        # Every authenticated request is logged to the SAME event-logging
        # mechanism the rest of the platform uses (EventLogger.log via
        # store.append_event) - no second audit log.
        if request.path != "/health":
            store = app.config["AEP_STORE"]
            from ..events import EventLogger
            EventLogger(store).log(
                actor=getattr(g, "api_key_label", "unknown"),
                action="api_request",
                project_id=getattr(g, "project_scope", None) or app.config["AEP_SENTINEL_PROJECT_ID"],
                details={"method": request.method, "path": request.path,
                         "status": response.status_code},
            )
        return response

    def _get_project_or_none(project_id: str) -> Optional[ProjectRecord]:
        """`projects.id` is a native Postgres uuid column - a non-uuid
        lookup key is simply "not found", not a 500. Guards every lookup
        site rather than relying on callers to validate first."""
        import uuid as _uuid
        try:
            _uuid.UUID(str(project_id))
        except (ValueError, AttributeError, TypeError):
            return None
        return PostgresProjectRepository(app.config["AEP_POOL"]).get(project_id)

    def _project_config(record: ProjectRecord) -> ProjectConfig:
        return ProjectConfig(id=record.id, name=record.name, repo_path=record.repo_path,
                              policy_path=record.policy_path, default_posture=record.default_posture,
                              protected_branches=record.protected_branches,
                              token_budget=record.token_budget)

    def _orchestrator_for_project(record: ProjectRecord):
        """Constructs an Orchestrator wired against the SAME shared store/
        skill registry as every other request, scoped to one project's
        policy - this is the identical `Orchestrator` class/gates
        (`_apply_generic_policy_gate`, `_apply_skill_gate`) the CLI's
        `build_orchestrator` wires up, not a reimplementation."""
        project = _project_config(record)
        policy = PolicyEngine.from_yaml(record.policy_path)
        from ..orchestrator import Orchestrator
        from ..bootstrap import build_tool_registry, build_router, build_default_agents
        store = app.config["AEP_STORE"]
        tool_registry = build_tool_registry(store=store)
        router = build_router()
        agents = build_default_agents()
        return Orchestrator(store=store, tool_registry=tool_registry, router=router,
                             agents=agents, policies={project.id: policy},
                             projects={project.id: project},
                             skill_registry=app.config["AEP_SKILL_REGISTRY"])

    def _require_project_scope(project_id: str):
        scope = getattr(g, "project_scope", None)
        if scope is not None and scope != project_id:
            return jsonify({"error": f"API key is scoped to a different project"}), 403
        return None

    # ---- health --------------------------------------------------------
    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    # ---- projects (item 1) ----------------------------------------------
    @app.get("/projects")
    def list_projects():
        pool = app.config["AEP_POOL"]
        store = app.config["AEP_STORE"]
        records = PostgresProjectRepository(pool).list()
        return jsonify([
            _project_to_dict(r, scan_lifecycle.latest_scan_run(pool, store, r.id))
            for r in records
        ])

    @app.post("/projects")
    def create_project():
        body = request.get_json(force=True) or {}
        for field_name in ("name", "repo_path"):
            if not body.get(field_name):
                return jsonify({"error": f"missing required field '{field_name}'"}), 400
        # `projects.id` is a native Postgres `uuid` column (see
        # src/aep/migrations_sql/0001_initial_schema.sql) - always
        # server-generated, same convention Task/Event ids already use
        # (orchestrator.new_task_id()); a caller-chosen short slug is
        # carried as `name` instead, never forced into the uuid column.
        import uuid as _uuid
        record = ProjectRecord(
            id=str(_uuid.uuid4()), name=body["name"], repo_path=body["repo_path"],
            policy_path=body.get("policy_path") or DEFAULT_POLICY_PATH,
            default_posture=body.get("default_posture", "deny"),
            protected_branches=body.get("protected_branches", ["main", "master"]),
            token_budget=body.get("token_budget"),
        )
        PostgresProjectRepository(app.config["AEP_POOL"]).save(record)
        return jsonify(_project_to_dict(record)), 201

    @app.get("/projects/<project_id>")
    def get_project(project_id: str):
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        pool, store = app.config["AEP_POOL"], app.config["AEP_STORE"]
        return jsonify(_project_to_dict(record, scan_lifecycle.latest_scan_run(pool, store, project_id)))

    @app.delete("/projects/<project_id>")
    def delete_project(project_id: str):
        """Archives, never hard-deletes (migration 0008 / BUG-0026's
        sibling design decision) - repository files, Git history, and
        every scan/finding/event record for this project are untouched;
        the project only disappears from the active `/projects` list."""
        check = _require_project_scope(project_id)
        if check is not None:
            return check
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        archived = PostgresProjectRepository(app.config["AEP_POOL"]).archive(project_id)
        if not archived:
            return jsonify({"error": "already archived"}), 409
        from ..events import EventLogger
        EventLogger(app.config["AEP_STORE"]).log(
            actor=getattr(g, "api_key_label", "unknown"), action="project.archived",
            project_id=project_id, details={"repo_path": record.repo_path})
        return jsonify({"id": project_id, "archived": True,
                        "note": "project registration removed from AEP; repository files and "
                                "scan history are untouched"})

    # ---- repositories (item 2) ------------------------------------------
    # Thin abstraction over a project's existing repo_path (local checkout)
    # plus whatever git remote it already has - no new table, no live
    # GitHub API dependency for local demo use. If a live GitHub call is
    # requested and unreachable, this reports BLOCKED explicitly.
    @app.get("/repositories/<project_id>")
    def get_repository(project_id: str):
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        import subprocess
        remote = None
        try:
            out = subprocess.run(["git", "-C", record.repo_path, "remote", "get-url", "origin"],
                                  capture_output=True, text=True, timeout=5)
            remote = out.stdout.strip() or None
        except Exception:
            remote = None
        github_status = "unavailable" if "github.com" in (remote or "") else "not_github"
        return jsonify({
            "project_id": project_id, "local_path": record.repo_path, "git_remote": remote,
            "github": {"status": github_status,
                       "detail": "live GitHub API calls are not made by this endpoint; "
                                 "reported BLOCKED/UNAVAILABLE honestly rather than faked"},
        })

    # ---- scan lifecycle: UI-facing "Scan Now" / history / rerun / report --
    # Every route below calls `aep.scan_lifecycle`, which itself calls the
    # SAME read-only, capability-routed `aep.scan.scan_project()` the CLI's
    # `aep scan` uses - no orchestrator, no approval gate, no second
    # scanning implementation, and (like the CLI) it never writes to,
    # installs into, or executes anything in the target repository.
    def _validated_repo_path(record: ProjectRecord):
        """Validated here, not at project-creation time: a stored
        repo_path can go stale (moved/deleted) between when a project was
        registered and when it's actually scanned, and this is the point
        where AEP is about to touch the filesystem for real."""
        path = Path(record.repo_path).resolve()
        if not path.exists():
            return None, jsonify({"error": f"path does not exist: {path}"}), 400
        if not path.is_dir():
            return None, jsonify({"error": f"path is not a directory: {path}"}), 400
        return str(path), None, None

    @app.post("/projects/<project_id>/scan")
    def scan_project_now(project_id: str):
        check = _require_project_scope(project_id)
        if check is not None:
            return check
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        path, err_body, err_code = _validated_repo_path(record)
        if path is None:
            return err_body, err_code
        result = scan_lifecycle.run_scan(app.config["AEP_POOL"], app.config["AEP_STORE"],
                                          project_id, path,
                                          triggered_by=getattr(g, "api_key_label", "ui"))
        return jsonify(result), (201 if result["status"] == "SUCCEEDED" else 500)

    @app.get("/projects/<project_id>/scans")
    def list_project_scans(project_id: str):
        if _get_project_or_none(project_id) is None:
            return jsonify({"error": "not found"}), 404
        runs = scan_lifecycle.list_scan_runs(app.config["AEP_POOL"], app.config["AEP_STORE"], project_id)
        comparison = scan_lifecycle.compare_scan_runs(app.config["AEP_POOL"], app.config["AEP_STORE"], project_id)
        return jsonify({"scans": runs, "comparison": comparison})

    @app.get("/projects/<project_id>/scans/<scan_id>")
    def get_project_scan(project_id: str, scan_id: str):
        if _get_project_or_none(project_id) is None:
            return jsonify({"error": "not found"}), 404
        detail = scan_lifecycle.get_scan_run(app.config["AEP_POOL"], app.config["AEP_STORE"],
                                              project_id, scan_id)
        if detail is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(detail)

    @app.get("/projects/<project_id>/report")
    def get_project_report(project_id: str):
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        latest = scan_lifecycle.latest_scan_run(app.config["AEP_POOL"], app.config["AEP_STORE"], project_id)
        if latest is None:
            return jsonify({"error": "NOT_YET_SCANNED", "project": record.name}), 404
        if request.args.get("format") == "markdown":
            md = scan_lifecycle.render_markdown_report(record.name, record.repo_path, latest)
            return app.response_class(md, mimetype="text/markdown")
        return jsonify(latest)

    # ---- agents (item 6, read-only) -------------------------------------
    @app.get("/agents")
    def list_agents():
        from ..bootstrap import build_default_agents
        agents = build_default_agents()
        return jsonify({"agents": sorted(agents.keys())})

    # ---- skills (item 7) --------------------------------------------------
    @app.get("/skills")
    def list_skills():
        registry = app.config["AEP_SKILL_REGISTRY"]
        out = []
        for skill in sorted(registry.list_skills(), key=lambda s: s.skill_id):
            versions = registry.list_versions(skill.skill_id)
            published = [v for v in versions if v.lifecycle_state.value == "published"]
            out.append({"skill_id": skill.skill_id, "name": skill.name,
                        "latest_published_version": published[-1].version if published else None,
                        "version_count": len(versions)})
        return jsonify({"skills": out})

    @app.get("/skills/<skill_id>")
    def show_skill(skill_id: str):
        registry = app.config["AEP_SKILL_REGISTRY"]
        version = registry.latest_version(skill_id)
        return jsonify({"skill_id": version.skill_id, "version": version.version,
                        "lifecycle_state": version.lifecycle_state.value,
                        "risk_level": version.risk_level.value,
                        "description": version.description, "purpose": version.purpose})

    @app.get("/skills/<skill_id>/versions")
    def skill_versions(skill_id: str):
        registry = app.config["AEP_SKILL_REGISTRY"]
        versions = registry.list_versions(skill_id)
        return jsonify({"skill_id": skill_id,
                        "versions": [{"version": v.version, "lifecycle_state": v.lifecycle_state.value}
                                     for v in versions]})

    # ---- providers (item 8) - NEVER leaks AI_CREDENTIAL ------------------
    @app.get("/providers")
    def providers():
        payload = _build_providers_payload(None)
        return jsonify(payload)

    # ---- findings ----------------------------------------------------
    @app.get("/findings")
    def findings():
        project_id = request.args.get("project_id")
        severity = request.args.get("severity")
        scope = getattr(g, "project_scope", None)
        # BUGFIX (project-isolation gap found in Wave 2 review): a
        # project-scoped key calling /findings with NO project_id filter
        # must never fall through to an unfiltered cross-project list -
        # it is pinned to its own scope, never allowed to widen it.
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        records = PostgresFindingRepository(app.config["AEP_POOL"]).list(project_id, severity)
        return jsonify([{
            "id": r.id, "project_id": r.project_id, "category": r.category, "severity": r.severity,
            "status": r.status, "resource": r.resource, "description": r.description,
            "false_positive": r.false_positive,
        } for r in records])

    # ---- intelligence: cross-project prioritization (Phase 10 Wave 1) ---
    @app.get("/intelligence/prioritization")
    def intelligence_prioritization():
        from ..intelligence.prioritization import prioritized_finding_to_dict, rank_findings

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        ranked = rank_findings(finding_repo, project_repo, project_ids=project_ids)
        return jsonify({"count": len(ranked), "items": [prioritized_finding_to_dict(r) for r in ranked]})

    def _patterns_and_signals(project_id: Optional[str]):
        """Shared by both /intelligence/patterns and /intelligence/health -
        calls the SAME `detect_patterns()`/`compute_health_signals()` the
        CLI's `aep intelligence patterns` calls; no logic duplicated."""
        from ..intelligence.incident_patterns import compute_health_signals, detect_patterns

        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo_local = PostgresProjectRepository(app.config["AEP_POOL"])
        store = app.config["AEP_STORE"]
        projects = project_repo_local.list()
        project_ids = [project_id] if project_id else None
        wanted = [p for p in projects if project_ids is None or p.id in project_ids]
        deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted}
        incidents_by_project = {p.id: list_incidents(store, p.id) for p in wanted}
        patterns = detect_patterns(finding_repo, project_ids=project_ids,
                                    deployment_evidence_by_project=deployment_evidence_by_project)
        signals = compute_health_signals(
            finding_repo, project_repo_local,
            deployment_evidence_by_project=deployment_evidence_by_project,
            incidents_by_project=incidents_by_project, project_ids=project_ids,
        )
        return patterns, signals

    # ---- intelligence: cross-project incident patterns (Phase 10 Wave 2)
    @app.get("/intelligence/patterns")
    def intelligence_patterns():
        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        patterns, _signals = _patterns_and_signals(project_id)
        return jsonify({"count": len(patterns), "patterns": [p.to_dict() for p in patterns]})

    # ---- intelligence: engineering health signals (Phase 10 Wave 2) ----
    @app.get("/intelligence/health")
    def intelligence_health():
        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        _patterns, signals = _patterns_and_signals(project_id)
        return jsonify({"count": len(signals), "signals": [s.to_dict() for s in signals]})

    # ---- intelligence: predictive risk (Phase 10 Wave 3) ---------------
    @app.get("/intelligence/risk")
    def intelligence_risk():
        from ..intelligence.risk_prediction import predict_risk, risk_prediction_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        store = app.config["AEP_STORE"]
        projects = project_repo.list()
        wanted = [p for p in projects if project_ids is None or p.id in project_ids]
        deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted}
        incidents_by_project = {p.id: list_incidents(store, p.id) for p in wanted}
        predictions = predict_risk(
            finding_repo, project_repo, project_ids=project_ids,
            deployment_evidence_by_project=deployment_evidence_by_project,
            incidents_by_project=incidents_by_project,
        )
        return jsonify({"count": len(predictions), "items": [risk_prediction_to_dict(p) for p in predictions]})

    # ---- intelligence: architecture intelligence (Phase 10 Wave 4) -----
    @app.get("/intelligence/architecture")
    def intelligence_architecture():
        from ..intelligence.architecture import analyze_architecture, architectural_risk_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        risks = analyze_architecture(finding_repo, project_repo, project_ids=project_ids)
        return jsonify({"count": len(risks), "items": [architectural_risk_to_dict(r) for r in risks]})

    # ---- intelligence: security posture trends (Phase 10 Wave 6) ------
    @app.get("/intelligence/security-trends")
    def intelligence_security_trends():
        from ..intelligence.security_trends import analyze_security_trends, security_trend_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        trends = analyze_security_trends(finding_repo, project_ids=project_ids)
        return jsonify({"count": len(trends), "items": [security_trend_to_dict(t) for t in trends]})

    # ---- intelligence: dependency/deployment risk forecast (Phase 10 Wave 7)
    @app.get("/intelligence/dependency-risk")
    def intelligence_dependency_risk():
        from ..intelligence.deployment_risk import deployment_risk_forecast_to_dict, forecast_deployment_risk

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        store = app.config["AEP_STORE"]
        projects = project_repo.list()
        wanted = [p for p in projects if project_ids is None or p.id in project_ids]
        deployment_evidence_by_project = {p.id: list_deployment_evidence(store, p.id) for p in wanted}
        forecasts = forecast_deployment_risk(
            finding_repo, project_repo, project_ids=project_ids,
            deployment_evidence_by_project=deployment_evidence_by_project,
        )
        return jsonify({"count": len(forecasts), "items": [deployment_risk_forecast_to_dict(f) for f in forecasts]})

    # ---- intelligence: technical debt (Phase 10 Wave 8) ----------------
    @app.get("/intelligence/technical-debt")
    def intelligence_technical_debt():
        from ..intelligence.technical_debt import analyze_technical_debt, debt_signal_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        signals = analyze_technical_debt(finding_repo, project_repo, project_ids=project_ids)
        return jsonify({"count": len(signals), "items": [debt_signal_to_dict(s) for s in signals]})

    # ---- intelligence: cross-project learning (Phase 10 Wave 9) -------
    @app.get("/intelligence/cross-project")
    def intelligence_cross_project():
        from ..db.postgres import PostgresMemoryRepository
        from ..intelligence.cross_project_learning import (
            cross_project_insight_to_dict,
            find_cross_project_insights,
        )

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        memory_repo = PostgresMemoryRepository(app.config["AEP_POOL"])
        insights = find_cross_project_insights(
            finding_repo, project_repo, memory_repo=memory_repo, project_ids=project_ids,
        )
        return jsonify({"count": len(insights), "items": [cross_project_insight_to_dict(i) for i in insights]})

    # ---- intelligence: CI failure clustering (Phase 10 Wave 11) -------
    @app.get("/intelligence/ci-clusters")
    def intelligence_ci_clusters():
        from ..intelligence.ci_clustering import analyze_ci_clusters, ci_cluster_result_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        result = analyze_ci_clusters(project_ids=project_ids)
        return jsonify(ci_cluster_result_to_dict(result))

    # ---- intelligence: cost intelligence (Phase 10 Wave 5) -------------
    @app.get("/intelligence/cost")
    def intelligence_cost():
        from ..intelligence.cost_intelligence import analyze_cost_intelligence, cost_intelligence_result_to_dict

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        result = analyze_cost_intelligence(finding_repo, project_ids=project_ids)
        return jsonify(cost_intelligence_result_to_dict(result))

    # ---- intelligence: predictive remediation decision (Phase 10 Wave 10)
    @app.get("/intelligence/remediation-decision")
    def intelligence_remediation_decision():
        from ..intelligence.predictive_remediation import (
            classify_remediation_batch,
            remediation_decision_to_dict,
        )
        from ..policy import PolicyEngine

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        all_findings = finding_repo.list(None, None)
        if project_ids is not None:
            wanted = set(project_ids)
            all_findings = [f for f in all_findings if f.project_id in wanted]
        try:
            policy = PolicyEngine.from_yaml(DEFAULT_POLICY_PATH)
        except Exception:
            policy = None
        decisions = classify_remediation_batch(all_findings, finding_repo, policy=policy)
        return jsonify({"count": len(decisions), "items": [remediation_decision_to_dict(d) for d in decisions]})

    # ---- intelligence: engineering health score (Phase 10 Wave 12) -----
    @app.get("/intelligence/health-score")
    def intelligence_health_score():
        from ..intelligence.engineering_health_score import (
            compute_engineering_health,
            engineering_health_summary_to_dict,
        )

        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        project_ids = [project_id] if project_id else None
        finding_repo = PostgresFindingRepository(app.config["AEP_POOL"])
        project_repo = PostgresProjectRepository(app.config["AEP_POOL"])
        summaries = compute_engineering_health(finding_repo, project_repo, project_ids=project_ids)
        return jsonify({"count": len(summaries),
                         "items": [engineering_health_summary_to_dict(s) for s in summaries]})

    # ---- incidents (Phase 7) ------------------------------------------
    @app.get("/incidents/<project_id>")
    def incidents(project_id: str):
        scope_check = _require_project_scope(project_id)
        if scope_check:
            return scope_check
        records = list_incidents(app.config["AEP_STORE"], project_id)
        return jsonify({"project": project_id, "incidents": [r.to_dict() for r in records]})

    # ---- deployments (Phase 6) -----------------------------------------
    @app.get("/deployments/<project_id>")
    def deployments(project_id: str):
        scope_check = _require_project_scope(project_id)
        if scope_check:
            return scope_check
        records = list_deployment_evidence(app.config["AEP_STORE"], project_id)
        return jsonify({"project": project_id, "deployments": [r.to_dict() for r in records]})

    # ---- tasks (items 3/4) ----------------------------------------------
    @app.post("/tasks")
    def create_task():
        body = request.get_json(force=True) or {}
        for field_name in ("project_id", "type"):
            if not body.get(field_name):
                return jsonify({"error": f"missing required field '{field_name}'"}), 400
        project_id = body["project_id"]
        scope_check = _require_project_scope(project_id)
        if scope_check:
            return scope_check
        record = _get_project_or_none(project_id)
        if record is None:
            return jsonify({"error": f"unknown project '{project_id}'"}), 404
        orch = _orchestrator_for_project(record)
        import uuid as _uuid
        task = Task(id=str(_uuid.uuid4()), type=body["type"], project_id=project_id,
                    owner_agent=body.get("owner_agent", "recon"),
                    payload=body.get("payload", {}), priority=body.get("priority", 5))
        orch.submit_graph(project_id, [task])
        # Same execution path the CLI's run_to_completion loop drives:
        # policy gate -> skill gate -> agent.run(). Executed synchronously
        # here (one task, no dependencies) rather than reimplementing any
        # of that logic.
        orch.run_task(task)
        saved = orch.store.get_task(task.id)
        return jsonify(json.loads(saved.to_json())), 201

    @app.get("/tasks/<task_id>")
    def get_task(task_id: str):
        task = app.config["AEP_STORE"].get_task(task_id)
        if task is None:
            return jsonify({"error": "not found"}), 404
        scope_check = _require_project_scope(task.project_id)
        if scope_check:
            return scope_check
        return jsonify(json.loads(task.to_json()))

    @app.get("/tasks/<task_id>/evidence")
    def task_evidence(task_id: str):
        task = app.config["AEP_STORE"].get_task(task_id)
        if task is None:
            return jsonify({"error": "not found"}), 404
        scope_check = _require_project_scope(task.project_id)
        if scope_check:
            return scope_check
        return jsonify({"task_id": task_id, "evidence": [e.to_dict() for e in task.evidence]})

    # ---- approvals (item 9) --------------------------------------------
    @app.get("/approvals")
    def approvals():
        project_id = request.args.get("project_id")
        scope = getattr(g, "project_scope", None)
        # BUGFIX (same project-isolation gap as /findings): a
        # project-scoped key omitting ?project_id must be pinned to its
        # own scope, never see other projects' approvals.
        if project_id:
            scope_check = _require_project_scope(project_id)
            if scope_check:
                return scope_check
        elif scope is not None:
            project_id = scope
        store = app.config["AEP_STORE"]
        tasks = store.list_tasks(project_id, statuses=[TaskStatus.BLOCKED_ON_APPROVAL]) \
            if project_id else store.non_terminal_tasks()
        blocked = [t for t in tasks if t.status == TaskStatus.BLOCKED_ON_APPROVAL]
        return jsonify([json.loads(t.to_json()) for t in blocked])

    def _project_record_for_task(task_id: str) -> Optional[ProjectRecord]:
        task = app.config["AEP_STORE"].get_task(task_id)
        if task is None:
            return None, None
        record = PostgresProjectRepository(app.config["AEP_POOL"]).get(task.project_id)
        return task, record

    @app.post("/approvals/<task_id>/approve")
    def approve_task(task_id: str):
        task, record = _project_record_for_task(task_id)
        if task is None:
            return jsonify({"error": "not found"}), 404
        scope_check = _require_project_scope(task.project_id)
        if scope_check:
            return scope_check
        orch = _orchestrator_for_project(record)
        try:
            orch.approve(task_id, decided_by=getattr(g, "api_key_label", "api"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(json.loads(orch.store.get_task(task_id).to_json()))

    @app.post("/approvals/<task_id>/reject")
    def reject_task(task_id: str):
        task, record = _project_record_for_task(task_id)
        if task is None:
            return jsonify({"error": "not found"}), 404
        scope_check = _require_project_scope(task.project_id)
        if scope_check:
            return scope_check
        body = request.get_json(silent=True) or {}
        orch = _orchestrator_for_project(record)
        try:
            orch.reject(task_id, decided_by=getattr(g, "api_key_label", "api"),
                        reason=body.get("reason", ""))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify(json.loads(orch.store.get_task(task_id).to_json()))

    @app.post("/approvals/<task_id>/pause")
    def pause_task(task_id: str):
        # "Pause" = leave it BLOCKED_ON_APPROVAL (a no-op transition) but
        # record the intent as an audited event - there is no separate
        # PAUSED state in the existing TaskStatus enum, and inventing one
        # here would be a second, parallel state machine. Documented as a
        # limitation in docs/API.md.
        task, record = _project_record_for_task(task_id)
        if task is None:
            return jsonify({"error": "not found"}), 404
        scope_check = _require_project_scope(task.project_id)
        if scope_check:
            return scope_check
        from ..events import EventLogger
        EventLogger(app.config["AEP_STORE"]).log(
            actor=getattr(g, "api_key_label", "api"), action="approval_pause_requested",
            project_id=task.project_id, task_id=task_id)
        return jsonify(json.loads(task.to_json()))

    # ---- runtime (item, Phase 8) ----------------------------------------
    @app.get("/runtime/status")
    def runtime_status():
        payload = build_runtime_status_payload(app.config["AEP_STORE"])
        return jsonify(payload)

    # ---- system status (Phase 3/9 progress engine) ----------------------
    @app.get("/system/status")
    def system_status():
        # compute_progress()/compute_deployability() run a REAL pytest
        # invocation (see progress/calculator.py) - ~9-11 minutes, same as
        # the full suite. Never faked/short-circuited here. Callers must
        # pass ?confirm=true to actually trigger it; otherwise this
        # documents the cost up front instead of hanging the request.
        if request.args.get("confirm") != "true":
            return jsonify({
                "status": "not_computed",
                "reason": "computing live progress/deployability runs the full roadmap "
                          "test suite (~9-11 minutes) - this is not a fast status endpoint. "
                          "Pass ?confirm=true to actually run it.",
            }), 202
        from ..progress.calculator import compute_progress
        from ..progress.deployability import compute_deployability
        progress = compute_progress(str(REPO_ROOT))
        deployability = compute_deployability(progress)
        return jsonify({"overall_percent": progress.overall_percent,
                        "deployability": deployability.state.value})

    # ---- packaged UI -------------------------------------------------
    # The production Vite build lives in `src/aep/ui_dist/` (package data,
    # shipped in the wheel) so a normal `pip install` + `aep start` needs
    # no Node/npm. Registered LAST so it can never shadow an API route:
    # Flask matches in registration order, and `_serve_ui`'s catch-all
    # only sees paths no API route above claimed. `ui/npm run dev` is
    # unaffected (it talks to this same API cross-origin, as before).
    ui_dist = Path(__file__).resolve().parent.parent / "ui_dist"

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def _serve_ui(path: str):
        if not ui_dist.is_dir():
            return jsonify({"error": "packaged UI not built into this install "
                                     "(src/aep/ui_dist missing)"}), 404
        # Only ever serve a real file that resolves INSIDE ui_dist -
        # never let a `..` path escape the asset directory.
        if path:
            candidate = (ui_dist / path).resolve()
            if candidate.is_file() and candidate.is_relative_to(ui_dist):
                return send_from_directory(ui_dist, path)
            # A MISSING asset must 404, not silently fall through to
            # index.html: a broken/mis-based build would otherwise serve
            # HTML with a 200 for every .js/.css and look healthy to any
            # status check (exactly how a real mis-built base path slipped
            # through once during this release). Only non-asset routes get
            # the SPA fallback.
            if "." in Path(path).name:
                return jsonify({"error": f"asset not found: {path}"}), 404
        return send_from_directory(ui_dist, "index.html")

    return app


def _detected_capabilities(repo_path: str) -> list[str]:
    """Cheap, read-only capability detection (no analyzers run) - lets the
    UI show "Repository detected: Terraform, CI/CD, Git" immediately on
    project creation and in the NOT_YET_SCANNED empty state, before any
    full `aep scan` has ever run (product spec Parts 1/12). Never fails
    the caller - an unreadable path just detects as nothing."""
    try:
        from ..capabilities import detect_project
        return detect_project(repo_path).sorted_capabilities()
    except Exception:  # noqa: BLE001 - detection is advisory here, never fatal
        return []


def _project_to_dict(record: ProjectRecord, latest_scan: Optional[dict] = None) -> dict:
    return {"id": record.id, "name": record.name, "repo_path": record.repo_path,
            "policy_path": record.policy_path, "default_posture": record.default_posture,
            "protected_branches": record.protected_branches, "token_budget": record.token_budget,
            "archived_at": record.archived_at.isoformat() if record.archived_at else None,
            # Part 2/12: a project's ANALYSIS state (has it ever been scanned,
            # and what happened) is surfaced right on the project row so the
            # UI never has to guess or show a stale "no open findings" for a
            # project that was never scanned at all.
            "analysis_state": (latest_scan or {}).get("analysis_state", "NEVER_SCANNED"),
            "last_scan_at": (latest_scan or {}).get("completed_at"),
            "last_scan_finding_count": (latest_scan or {}).get("finding_count"),
            "detected_capabilities": _detected_capabilities(record.repo_path),
            }
