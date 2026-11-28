"""Run object-layer RLS tests against a disposable PostgreSQL service."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from uuid import UUID, uuid4

import pytest

from riswan_app.postgres_objects import PostgresObjects, migrate
from riswan_platform.core.context import PlatformContext, bind_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.data_protection import ProtectionDenied


@pytest.fixture(scope="module")
def postgres_pool():
    if os.getenv("RISWAN_POSTGRES_INTEGRATION") != "1":
        pytest.skip("Requires the disposable PostgreSQL integration service.")
    psycopg = pytest.importorskip("psycopg")
    pool_module = pytest.importorskip("psycopg_pool")
    connection = "host=127.0.0.1 port=5432 dbname=riswan"
    with psycopg.connect(connection + " user=postgres", autocommit=True) as admin:
        admin.execute("CREATE ROLE riswan_migration LOGIN NOSUPERUSER NOBYPASSRLS")
        admin.execute("CREATE ROLE riswan_runtime LOGIN NOSUPERUSER NOBYPASSRLS")
        admin.execute("CREATE ROLE riswan_identity_runtime LOGIN NOSUPERUSER NOBYPASSRLS")
        admin.execute("CREATE ROLE riswan_control_runtime LOGIN NOSUPERUSER NOBYPASSRLS")
        admin.execute("GRANT CREATE ON DATABASE riswan TO riswan_migration")
    from riswan_app import postgres_scope

    with psycopg.connect(connection + " user=riswan_migration") as owner:
        with pytest.MonkeyPatch.context() as patches:
            patches.setattr(postgres_scope, "MIGRATIONS", postgres_scope.MIGRATIONS[:15])
            migrate(owner)
        migrate(owner)
        migrate(owner)
        assert owner.execute(
            "SELECT version FROM riswan_data.schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, 17)]
    with pool_module.ConnectionPool(
        connection + " user=riswan_runtime",
        min_size=1,
        max_size=1,
        open=False,
    ) as pool:
        yield pool


@pytest.fixture(scope="module")
def postgres_identity_pool(postgres_pool):
    from psycopg_pool import ConnectionPool

    with ConnectionPool(
        "host=127.0.0.1 port=5432 dbname=riswan user=riswan_identity_runtime",
        min_size=1,
        max_size=1,
        open=False,
    ) as pool:
        yield pool


@pytest.fixture(scope="module")
def postgres_control_pool(postgres_pool):
    from psycopg_pool import ConnectionPool

    with ConnectionPool(
        "host=127.0.0.1 port=5432 dbname=riswan user=riswan_control_runtime",
        min_size=1,
        max_size=3,
        open=False,
    ) as pool:
        yield pool


def test_postgres_rls_pool_and_direct_sql(postgres_pool):
    import psycopg

    pool = postgres_pool
    objects = PostgresObjects(pool)
    obj = uuid4()
    a, b = uuid4(), uuid4()

    def context(tenant, product="ir"):
        return PlatformContext(tenant, str(uuid4()), "service", product, "request", "correlation")

    def key(tenant, product="ir"):
        return f"{tenant.hex}/{sha256(product.encode()).hexdigest()}/{obj.hex}"

    with pytest.raises(ContextRequiredError):
        objects.get(key(a))
    with bind_context(context(a)):
        with pytest.raises(ProtectionDenied):
            objects.get(key(b))
        objects.put(key(a), b"tenant-a")

    with pool.connection() as db:
        assert db.execute("SELECT count(*) FROM riswan_data.protected_objects").fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute(
                "INSERT INTO riswan_data.protected_objects VALUES (%s, 'ir', %s, %s)",
                (a, uuid4(), b"denied"),
            )
        with pytest.raises(RuntimeError), db.transaction():
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', 'ir', true)",
                (str(b),),
            )
            assert db.execute("SELECT count(*) FROM riswan_data.protected_objects").fetchone() == (
                0,
            )
            with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(
                    "INSERT INTO riswan_data.protected_objects VALUES (%s, 'ir', %s, %s)",
                    (a, uuid4(), b"denied"),
                )
            raise RuntimeError("rollback")

    def roundtrip(tenant, product, payload):
        with bind_context(context(tenant, product)):
            objects.put(key(tenant, product), payload)
            return objects.get(key(tenant, product))

    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = (
            executor.submit(roundtrip, b, "ir", b"tenant-b"),
            executor.submit(roundtrip, a, "different", b"product-b"),
        )
        assert [job.result(timeout=10) for job in jobs] == [b"tenant-b", b"product-b"]
    with bind_context(context(a)):
        assert objects.get(key(a)) == b"tenant-a"
        objects.delete(key(a))
        with pytest.raises(ProtectionDenied):
            objects.get(key(a))
    with pool.connection() as db:
        assert db.execute("SELECT count(*) FROM riswan_data.protected_objects").fetchone() == (0,)


def test_postgres_case_ownership_scopes_directory_and_sql(postgres_pool):
    from datetime import UTC, datetime

    import psycopg

    from riswan_app.postgres_case_ownership import PostgresCaseOwnership

    directory = PostgresCaseOwnership(postgres_pool)
    first, second, actor = uuid4(), uuid4(), uuid4()
    case = uuid4().hex
    utc = datetime.now(UTC)
    owner = PlatformContext(first, str(actor), "human", "ir", "req", "corr")
    with bind_context(owner):
        directory.register(case, utc)
        with pytest.raises(psycopg.errors.UniqueViolation):
            directory.register(case, utc)
        assert directory.owned_investigations(first) == {case: actor}
        with pytest.raises(ContextRequiredError):
            directory.owned_investigations(second)
    for tenant, product in ((second, "ir"), (first, "separate")):
        target = PlatformContext(tenant, str(actor), "human", product, "req", "corr")
        with bind_context(target):
            assert directory.owned_investigations(tenant) == {}
    with postgres_pool.connection() as db:
        assert db.execute(
            "SELECT count(*) FROM riswan_data.investigation_ownership"
        ).fetchone() == (0,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute(
                "INSERT INTO riswan_data.investigation_ownership VALUES (%s, 'ir', %s, %s, %s)",
                (first, uuid4().hex, actor, utc),
            )
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute("SELECT count(*) FROM riswan_data.schema_migrations")


@pytest.fixture
def hosted_postgres(
    postgres_pool, postgres_identity_pool, postgres_control_pool, tmp_path, monkeypatch
):
    from datetime import UTC, datetime

    from riswan_app import identity_runtime
    from riswan_platform.identity.configuration import OIDCSettings
    from tests.integration.test_identity_runtime import FixtureProvider, call, login

    configuration = OIDCSettings(
        issuer="https://issuer.example",
        jwks_url="https://issuer.example/jwks",
        authorization_url="https://login.example/authorize",
        token_url="https://login.example/token",
        redirect_uri="https://app.example/v1/auth/callback",
        client_id="browser",
        access_audience="riswan-api",
        invited_subjects={"alice", "bob"},
    )
    path = tmp_path / "oidc.json"
    path.write_text(configuration.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(identity_runtime, "OIDCProvider", FixtureProvider)
    monkeypatch.setenv("RISWAN_IR_ENV", "development")
    monkeypatch.setattr("riswan_ir.storage.sqlite.now", lambda: datetime.now(UTC).isoformat())
    app = identity_runtime.compose_identity(
        path,
        None,
        tmp_path / "workstation.sqlite3",
        postgres_control_pool=postgres_control_pool,
        postgres_case_pool=postgres_pool,
        enable_postgres_preview=True,
        postgres_identity_pool=postgres_identity_pool,
    )
    alice, _ = login(app, "alice")
    bob, _ = login(app, "bob")

    def send(path, method="GET", *, cookie=alice, tenant=None, payload=None, query=""):
        status, _, response = call(
            app,
            path,
            method,
            cookie=cookie,
            query=query,
            origin="https://app.example",
            tenant=tenant,
            payload=payload,
        )
        return status, response

    _, first = send("/v1/organizations", "POST", payload={"name": "First"})
    _, second = send("/v1/organizations", "POST", cookie=bob, payload={"name": "Second"})
    a, b = first["tenant_id"], second["tenant_id"]
    base = "/v1/investigations"
    assert send(base)[0] == 404
    return app, send, alice, bob, a, b


def test_hosted_postgres_case_preview(
    postgres_pool,
    postgres_identity_pool,
    postgres_control_pool,
    hosted_postgres,
    tmp_path,
    monkeypatch,
    request_payload,
):
    from urllib.parse import urlencode

    import psycopg
    from psycopg_pool import PoolClosed

    from riswan_app import identity_runtime
    from tests.integration.test_identity_runtime import call

    path = tmp_path / "oidc.json"
    app, send, alice, bob, a, b = hosted_postgres
    base = "/v1/investigations"
    status, report = send(base, "POST", tenant=a, payload=request_payload)
    assert status == 201
    case = report["id"]
    endpoint = f"{base}/{case}"
    assert send(endpoint, tenant=a)[1]["title"] == request_payload["title"]
    assert send(base, tenant=a)[1][0]["id"] == case
    assert send(endpoint, "PATCH", tenant=a, payload={"title": "Updated"})[1]["title"] == "Updated"
    assert send(endpoint, tenant=b, cookie=bob)[0] == 404
    assert send(endpoint, "PATCH", tenant=b, cookie=bob, payload={"title": "Denied"})[0] == 404
    assert send(base, tenant=b, cookie=bob) == (200, [])
    assert send(endpoint + "/memory", tenant=a)[0] in {200, 404}
    assert send(endpoint + "/risk", tenant=a)[0] == 200
    assert send(endpoint + "/knowledge-graph", tenant=a)[0] == 200
    assert send(endpoint + "/knowledge-graph/ontology", tenant=a)[0] == 200
    assert send(endpoint + "/knowledge-graph/ontology", tenant=b, cookie=bob)[0] == 404
    assert send(endpoint + "/temporal-correlation", tenant=a)[0] == 200
    assert send(endpoint + "/temporal-correlation/replay", tenant=a)[0] == 200
    assert send(endpoint + "/incidents", tenant=a)[0] == 200
    assert send(endpoint + "/incidents", tenant=b, cookie=bob)[0] == 404
    _, risk = send(endpoint + "/risk", tenant=a)
    for assessment in risk["assessments"]:
        detail = endpoint + "/risk/" + assessment["id"]
        assert send(detail, tenant=a) == (200, assessment)
        assert send(detail + "/replay", tenant=a) == (200, assessment)
        assert "confidence" in assessment
    if risk["assessments"]:
        assessment = risk["assessments"][0]
        assert (
            send(
                endpoint + "/risk/reassess",
                "POST",
                tenant=a,
                payload={
                    "subject_kind": assessment["subject_kind"],
                    "subject_id": assessment["subject_id"],
                },
            )[0]
            == 200
        )
        assert send(endpoint + "/risk/" + assessment["id"], tenant=a) == (200, assessment)
    original_evidence = send(endpoint + "/evidence", tenant=a)[1]
    assert original_evidence
    status, events = send(endpoint + "/events", tenant=a)
    assert status == 200 and events["events"]
    assert send(endpoint + "/events", tenant=b, cookie=bob)[0] == 404
    assert send(endpoint + "/evidence/provenance", tenant=b, cookie=bob)[0] == 404
    for suffix in ("/evidence/provenance", "/evidence/custody", "/findings"):
        assert send(endpoint + suffix, tenant=a)[0] == 200
    assert send(endpoint + "/evidence/verify", tenant=a)[1]["valid"]
    code, _, page = call(
        app,
        endpoint + "/events",
        cookie=alice,
        tenant=a,
        query="limit=1",
    )
    assert code == 200 and len(page["events"]) == 1 and page["next_offset"] == 1
    event_type = page["events"][0]["type_uid"]
    code, _, filtered = call(
        app,
        endpoint + "/events",
        cookie=alice,
        tenant=a,
        query=f"type_uid={event_type}&start=2020-01-01T00%3A00%3A00Z",
    )
    assert code == 200 and filtered["events"]
    assert all(item["type_uid"] == event_type for item in filtered["events"])
    assert send(endpoint + "/evidence", tenant=b, cookie=bob)[0] == 404
    assert send(endpoint, tenant=a)[1]["evidence"] == original_evidence
    status, hold = send(endpoint + "/legal-holds", "POST", tenant=a, payload={"reason": "Preserve"})
    assert status == 201
    restarted = identity_runtime.compose_identity(
        path,
        None,
        tmp_path / "workstation.sqlite3",
        postgres_control_pool=postgres_control_pool,
        postgres_case_pool=postgres_pool,
        enable_postgres_preview=True,
        postgres_identity_pool=postgres_identity_pool,
    )
    assert (
        call(
            restarted,
            endpoint + "/memory",
            "DELETE",
            cookie=alice,
            origin="https://app.example",
            tenant=a,
        )[0]
        == 409
    )
    assert (
        send(
            endpoint + "/legal-holds/" + hold["id"] + "/release",
            "POST",
            tenant=a,
            payload={"reason": "Released"},
        )[0]
        == 200
    )
    assert send(endpoint + "/memory", "DELETE", tenant=a)[0] == 204
    with postgres_pool.connection() as db:
        assert db.execute("SELECT count(*) FROM riswan_data.investigations").fetchone() == (0,)
        with db.transaction():
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', 'ir', true)",
                (a,),
            )
            row = db.execute(
                "SELECT report, artifacts FROM riswan_data.investigations WHERE investigation_id = %s",
                (case,),
            ).fetchone()
            assert row[0]["title"] == "Updated"
            assert db.execute(
                "SELECT count(*) FROM riswan_data.investigation_events WHERE investigation_id = %s",
                (case,),
            ).fetchone()[0] == len(events["events"])
            assert row[1]["graph_digest"] and row[1]["security_data_digest"]
            assert "security_graphs" not in row[1]
            assert "temporal_correlations" not in row[1] and "risk_assessments" not in row[1]
            assert (
                db.execute(
                    "SELECT count(*) FROM riswan_data.case_graph_nodes WHERE investigation_id = %s",
                    (case,),
                ).fetchone()[0]
                > 0
            )
            assert (
                db.execute(
                    "SELECT count(*) FROM riswan_data.case_graph_edges WHERE investigation_id = %s",
                    (case,),
                ).fetchone()[0]
                > 0
            )
            with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
                db.execute(
                    "INSERT INTO riswan_data.case_graph_edges VALUES (%s, 'ir', %s, 'missing', 999, 'foreign', 'foreign', '{}')",
                    (a, case),
                )
            assert "raw_evidence" not in row[1] and "evidence_receipts" not in row[1]
            for table in ("case_raw_evidence", "case_evidence_receipts", "case_custody"):
                from psycopg import sql

                assert db.execute(
                    sql.SQL(
                        "SELECT count(*) FROM riswan_data.{} WHERE investigation_id = %s"
                    ).format(sql.Identifier(table)),
                    (case,),
                ).fetchone()[0]
            db.execute("SET LOCAL enable_seqscan = off")
            plan = db.execute(
                """EXPLAIN SELECT event FROM riswan_data.investigation_events
                   WHERE tenant_id = %s AND product_id = 'ir' AND investigation_id = %s
                     AND event #>> '{classification,type_uid}' = %s
                   ORDER BY observed_at, ordinal LIMIT 50""",
                (a, case, str(event_type)),
            ).fetchall()
            assert any("Index" in row[0] for row in plan), plan
            with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
                orphan = uuid4().hex
                db.execute(
                    "INSERT INTO riswan_data.investigations VALUES (%s, 'ir', %s, jsonb_build_object('id', %s::text), '{}')",
                    (a, orphan, orphan),
                )
    hosted = app._authenticated_routes.product
    insert = hosted.store._directory.insert

    def aborted(db, scope, case_id, stamp):
        insert(db, scope, case_id, stamp)
        raise psycopg.OperationalError("simulated failure after ownership insert")

    with monkeypatch.context() as patches:
        patches.setattr(hosted.store._directory, "insert", aborted)
        assert send(base, "POST", tenant=a, payload=request_payload)[0] == 503
    with bind_context(PlatformContext(UUID(a), str(uuid4()), "human", "ir", "req", "corr")):
        assert list(hosted.store.owned_investigations(UUID(a))) == [case]
    with bind_context(PlatformContext(UUID(a), str(uuid4()), "human", "other", "req", "corr")):
        from riswan_platform.core.exceptions import NotFoundError

        with pytest.raises(NotFoundError):
            hosted.store.get(case)

    def unavailable():
        raise PoolClosed("simulated failure")

    with monkeypatch.context() as patches:
        patches.setattr(postgres_pool, "connection", unavailable)
        assert send(endpoint, tenant=a)[0] == 503
    extra = {**request_payload["records"]["Records"][-1], "eventID": "revision-extra"}
    status, revised = send(endpoint + "/revisions", "POST", tenant=a, payload={"records": [extra]})
    assert status == 201
    descendant = send(f"{base}/{revised['id']}", tenant=a)[1]
    assert descendant["previous_investigation_id"] == case
    assert send(endpoint + "/evidence", tenant=a)[1] == original_evidence
    assert {item["id"] for item in original_evidence} <= {
        item["id"] for item in descendant["evidence"]
    }
    # Normalized hashes include revision-specific references. The historical parent
    # is immutable, and inherited receipts preserve the original raw hashes.
    with bind_context(PlatformContext(UUID(a), str(uuid4()), "human", "ir", "req", "corr")):

        def receipts(case_id):
            return {
                (item["source_event_id"], item["evidence_id"], item["raw_integrity_hash"])
                for row in hosted.store.artifact(case_id, "evidence_receipts")
                for item in (json.loads(row["provenance"]),)
            }

        assert receipts(case) < receipts(revised["id"])
    with monkeypatch.context() as patches:
        patches.setattr(hosted.store._directory, "insert", aborted)
        assert (
            send(endpoint + "/revisions", "POST", tenant=a, payload={"records": [extra]})[0] == 503
        )
    assert {item["id"] for item in send(base, tenant=a)[1]} == {case, revised["id"]}
    from riswan_app import postgres_security_data

    append = postgres_security_data.append

    def failed_dependent_write(db, scope, report, data):
        append(db, scope, report, data)
        raise psycopg.OperationalError("simulated failure after evidence insert")

    with monkeypatch.context() as patches:
        patches.setattr(postgres_security_data, "append", failed_dependent_write)
        assert send(base, "POST", tenant=a, payload=request_payload)[0] == 503
    assert {item["id"] for item in send(base, tenant=a)[1]} == {case, revised["id"]}
    with postgres_pool.connection() as db, db.transaction():
        assert db.execute("SELECT count(*) FROM riswan_data.case_custody").fetchone() == (0,)
        db.execute(
            "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', 'ir', true)",
            (a,),
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute("DELETE FROM riswan_data.case_custody WHERE investigation_id = %s", (case,))
        with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
            db.execute(
                "INSERT INTO riswan_data.case_evidence_receipts VALUES (%s, 'ir', %s, 999, 'wrong', 'fixture', '{}')",
                (a, case),
            )
    from tests.integration.test_risk_assessment import restoration
    from tests.integration.test_temporal_correlation import ROOT, scenario

    status, assessed_case = send(
        base,
        "POST",
        tenant=a,
        payload={
            "title": "Historical risk",
            "principal": ROOT,
            "records": scenario(10) + [restoration()],
        },
    )
    assert status == 201
    risk_path = f"{base}/{assessed_case['id']}"
    assessment = next(
        item
        for item in send(risk_path + "/risk", tenant=a)[1]["assessments"]
        if item["subject_kind"] == "finding"
    )
    assert assessment["risk"]["score"] != assessment["confidence"]["score"]
    reference = next(
        item["reference"]["evidence_id"]
        for item in send(risk_path + "/evidence", tenant=a)[1]
        if item["id"] == "restore"
    )
    status, contained = send(
        risk_path + "/risk/reassess",
        "POST",
        tenant=a,
        payload={
            "subject_kind": "finding",
            "subject_id": assessment["subject_id"],
            "containment_evidence_id": reference,
        },
    )
    assert status == 200 and contained["id"] != assessment["id"]
    assert contained["original_assessment_id"] == assessment["id"]
    history = f"{risk_path}/risk/finding/{assessment['subject_id']}/history"
    assert send(history, tenant=a)[1]["assessments"] == [contained, assessment]
    assert send(risk_path + "/risk/" + contained["id"] + "/replay", tenant=a) == (200, contained)
    status, risk_revision = send(
        risk_path + "/revisions",
        "POST",
        tenant=a,
        payload={
            "records": [
                {
                    **scenario(10)[-1],
                    "eventID": "late-context",
                    "eventName": "GetBucketLocation",
                    "eventTime": "2021-01-22T00:00:00Z",
                }
            ]
        },
    )
    assert status == 201
    child_path = f"{base}/{risk_revision['id']}"
    child_risk = next(
        item
        for item in send(child_path + "/risk", tenant=a)[1]["assessments"]
        if item["subject_id"] == assessment["subject_id"]
    )
    status, replay = send(child_path + "/temporal-correlation/replay", tenant=a)
    assert status == 200
    assert replay["investigation_id"] == risk_revision["id"]
    _, correlation = send(child_path + "/temporal-correlation", tenant=a)
    assert correlation["rules"] == replay["rules"]
    assert correlation["partial_matches"] == replay["partial_matches"]
    assert send(child_path + "/incidents", tenant=a)[1]["incidents"] == replay["incidents"]
    child_request = {"subject_kind": "finding", "subject_id": assessment["subject_id"]}
    assert (
        send(child_path + "/risk/reassess", "POST", tenant=b, cookie=bob, payload=child_request)[0]
        == 404
    )
    from riswan_ir.risk.models import Reassessment
    from riswan_platform.core.exceptions import NotFoundError

    with bind_context(PlatformContext(UUID(a), str(uuid4()), "human", "ir", "req", "corr")):
        with pytest.raises(NotFoundError, match="Reassessment unavailable"):
            hosted.store.reassess(
                risk_revision["id"], Reassessment.model_validate(child_request), parent=case
            )
    status, reassessed = send(
        child_path + "/risk/reassess", "POST", tenant=a, payload=child_request
    )
    assert status == 200 and reassessed["investigation_id"] == risk_revision["id"]
    assert send(child_path + "/risk/" + child_risk["id"] + "/replay", tenant=a) == (200, child_risk)
    assert send(history, tenant=a)[1]["assessments"] == [contained, assessment]
    memory_path = risk_path + "/memory"
    assert send(memory_path, tenant=a)[0] == 200
    assert send(memory_path, tenant=b, cookie=bob)[0] == 404
    assert (
        send(
            risk_path + "/feedback",
            "POST",
            tenant=a,
            payload={"reviewer": "client-claim", "disposition": "benign"},
        )[0]
        == 201
    )
    assert send(risk_path, tenant=a)[1]["reviews"][0]["reviewer"] != "client-claim"
    assert any(
        item["trigger"] == "analyst_review" for item in send(history, tenant=a)[1]["assessments"]
    )

    assert (
        send(
            memory_path + "/feedback",
            "POST",
            tenant=b,
            cookie=bob,
            payload={"classification": "authorized_activity", "evidence_references": [reference]},
        )[0]
        == 404
    )
    assert (
        send(
            memory_path + "/feedback",
            "POST",
            tenant=a,
            payload={
                "classification": "authorized_activity",
                "evidence_references": [reference, reference],
            },
        )[0]
        == 400
    )
    independent = [
        {**event, "eventID": "independent-" + event["eventID"]}
        for event in scenario(10) + [restoration()]
    ]
    status, current_case = send(
        base,
        "POST",
        tenant=a,
        payload={"title": "Current case", "principal": ROOT, "records": independent},
    )
    assert status == 201
    current_memory = f"{base}/{current_case['id']}/memory"
    cutoff = urlencode({"as_of": current_case["created_at"]})
    assert send(
        memory_path + "/feedback",
        "POST",
        tenant=a,
        payload={"classification": "authorized_activity", "evidence_references": [reference]},
    ) == (201, {"recorded": True})
    assert send(
        memory_path + "/feedback",
        "POST",
        tenant=a,
        payload={"classification": "authorized_activity", "evidence_references": [reference]},
    ) == (201, {"recorded": True})
    with postgres_pool.connection() as db, db.transaction():
        assert db.execute("SELECT count(*) FROM riswan_data.case_memory_history").fetchone() == (0,)
        for tenant_id, product, count in ((a, "other", 0), (b, "ir", 0), (a, "ir", 2)):
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', %s, true)",
                (tenant_id, product),
            )
            assert db.execute(
                """SELECT count(*) FROM riswan_data.case_memory_history
                WHERE investigation_id = %s AND kind = 'feedback'""",
                (assessed_case["id"],),
            ).fetchone() == (count,)
    status, past = send(current_memory, tenant=a, query=cutoff)
    assert status == 200
    assert not any(
        item["classification"] == "authorized_activity" for item in past["similar_investigations"]
    )
    status, intelligence = send(f"{base}/{current_case['id']}/memory", tenant=a)
    assert status == 200
    assert any(
        match["investigation_id"] == assessed_case["id"]
        and match["classification"] == "authorized_activity"
        for match in intelligence["similar_investigations"]
    )
    from riswan_app import postgres_memory

    append_history = postgres_memory.append_history

    def journal_failure(*args):
        append_history(*args)
        raise psycopg.OperationalError("simulated failure after feedback journal insert")

    with monkeypatch.context() as patches:
        patches.setattr(postgres_memory, "append_history", journal_failure)
        assert (
            send(
                risk_path + "/feedback",
                "POST",
                tenant=a,
                payload={"disposition": "confirmed"},
            )[0]
            == 503
        )
    assert [review["disposition"] for review in send(risk_path, tenant=a)[1]["reviews"]] == [
        "benign"
    ]
    assert send(
        memory_path + "/feedback",
        "POST",
        tenant=a,
        payload={"classification": "successful_remediation", "evidence_references": [reference]},
    ) == (201, {"recorded": True})
    assert send(current_memory, tenant=a)[1]["response_history"][assessed_case["id"]] == [reference]
    assert send(memory_path, "DELETE", tenant=a)[0] == 204
    assert send(memory_path, tenant=a)[0] == 404
    assert all(
        match["investigation_id"] != assessed_case["id"]
        for match in send(current_memory, tenant=a)[1]["similar_investigations"]
    )
    assert sorted(file.name for file in tmp_path.glob("*.sqlite3")) == []


@pytest.mark.parametrize(
    "scope",
    ["authorized", "other-product", "other-tenant", "no-resource-grant", "expired", "removed"],
)
def test_postgres_memory_candidate_scope_and_plans(postgres_pool, scope, record_property):
    from riswan_app.postgres_memory import CANDIDATES_SQL, candidates

    tenant, foreign, actor = uuid4(), uuid4(), uuid4()
    account = "aws:111122223333"
    current = "2026-01-25T00:00:00.000000+00:00"
    after = "2026-01-02T00:00:00.000000+00:00"
    expires = (
        "2026-01-24T00:00:00.000000+00:00"
        if scope == "expired"
        else "2027-01-01T00:00:00.000000+00:00"
    )
    own_ids = [f"{i:032x}" for i in range(1, 513)]
    with postgres_pool.connection() as db, db.transaction():
        for owner, product in ((tenant, "ir"), (tenant, "other"), (foreign, "ir")):
            db.execute(
                "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', %s, true)",
                (str(owner), product),
            )
            db.execute(
                """INSERT INTO riswan_data.investigation_ownership
                   SELECT %s, %s, id, %s, now() FROM unnest(%s::text[]) ids(id)""",
                (owner, product, actor, own_ids),
            )
            db.execute(
                """INSERT INTO riswan_data.investigations
                   (tenant_id, product_id, investigation_id, report, artifacts, parent_id)
                   SELECT %s, %s, id, jsonb_build_object('id', id), '{}'::jsonb,
                          lag(id) OVER (ORDER BY id)
                   FROM unnest(%s::text[]) ids(id)""",
                (owner, product, own_ids),
            )
            db.execute(
                """INSERT INTO riswan_data.case_memory_snapshots
                   SELECT %s, %s, id, jsonb_build_object(
                     'memory_cases', jsonb_build_array(jsonb_build_object('indexed_at', %s::text)),
                     'memory_accounts', jsonb_build_array(jsonb_build_object('account', %s::text)),
                     'memory_records', jsonb_build_array(jsonb_build_object(
                       'category', 'episodic', 'expires_at', %s::text))
                   ) FROM unnest(%s::text[]) ids(id)""",
                (
                    owner,
                    product,
                    current,
                    account if (owner, product) == (tenant, "ir") else "aws:999900001111",
                    expires,
                    own_ids,
                ),
            )
        owner, product, authorized = {
            "authorized": (tenant, "ir", own_ids[:128]),
            "other-product": (tenant, "other", own_ids[:128]),
            "other-tenant": (foreign, "ir", own_ids[:128]),
            "no-resource-grant": (tenant, "ir", []),
            "expired": (tenant, "ir", own_ids[:128]),
            "removed": (tenant, "ir", own_ids[:1]),
        }[scope]
        db.execute(
            "SELECT set_config('riswan.tenant_id', %s, true), set_config('riswan.product_id', %s, true)",
            (str(owner), product),
        )
        context = PlatformContext(owner, str(actor), "human", product, "req", "corr")
        if scope == "removed":
            db.execute(
                "INSERT INTO riswan_data.investigation_memory_removals VALUES (%s, %s, %s)",
                (owner, product, own_ids[0]),
            )
        result = candidates(db, context, authorized, {account}, current, after, current)
        assert result == (tuple(own_ids[:101]) if scope == "authorized" else ())
        if scope == "authorized":
            plan = db.execute(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + CANDIDATES_SQL,
                (owner, product, authorized, after, current, current, [account], [account]),
            ).fetchone()[0][0]
            assert plan["Plan"]["Actual Rows"] == 101
            record_property("memory_candidate_query_plan", json.dumps(plan))
            _intelligence_read_plans(db, owner, actor, own_ids, current, record_property)


def _intelligence_read_plans(db, tenant, actor, ids, timestamp, record_property):
    db.execute(
        """INSERT INTO riswan_data.case_graph_snapshots
           SELECT %s, 'ir', id, '{}' FROM unnest(%s::text[]) ids(id)""",
        (tenant, ids),
    )
    db.execute(
        """INSERT INTO riswan_data.case_graph_nodes
           SELECT %s, 'ir', id, n::text, n, '{}'::jsonb
           FROM unnest(%s::text[]) ids(id) CROSS JOIN generate_series(1, 8) n""",
        (tenant, ids),
    )
    db.execute(
        """INSERT INTO riswan_data.case_graph_edges
           SELECT %s, 'ir', id, n::text, n, n::text, (n + 1)::text, '{}'::jsonb
           FROM unnest(%s::text[]) ids(id) CROSS JOIN generate_series(1, 7) n""",
        (tenant, ids),
    )
    db.execute(
        """INSERT INTO riswan_data.case_temporal_snapshots
           SELECT %s, 'ir', id, '{}' FROM unnest(%s::text[]) ids(id)""",
        (tenant, ids),
    )
    db.execute(
        """INSERT INTO riswan_data.case_risk_assessments
           SELECT %s, 'ir', id, n, n::text, 'finding', 'subject', '{}'
           FROM unnest(%s::text[]) ids(id) CROSS JOIN generate_series(1, 4) n""",
        (tenant, ids),
    )
    db.execute(
        """INSERT INTO riswan_data.case_memory_history
           SELECT %s, 'ir', id, gen_random_uuid(), %s, 'feedback', n, %s, '[]'::jsonb
           FROM unnest(%s::text[]) ids(id) CROSS JOIN generate_series(1, 4) n""",
        (tenant, str(actor), timestamp, ids),
    )
    target = ids[-1]
    patterns = (
        (
            "graph_nodes",
            "SELECT node FROM riswan_data.case_graph_nodes WHERE investigation_id = %s ORDER BY ordinal",
            (target,),
            8,
        ),
        (
            "graph_edges",
            "SELECT edge FROM riswan_data.case_graph_edges WHERE investigation_id = %s ORDER BY ordinal",
            (target,),
            7,
        ),
        (
            "temporal",
            "SELECT snapshot FROM riswan_data.case_temporal_snapshots WHERE investigation_id = %s",
            (target,),
            1,
        ),
        (
            "risk_history",
            """SELECT ordinal, id, kind, subject_id, archive FROM riswan_data.case_risk_assessments
                           WHERE investigation_id = %s ORDER BY ordinal""",
            (target,),
            4,
        ),
        (
            "revision_parent",
            "SELECT parent_id FROM riswan_data.investigations WHERE investigation_id = %s",
            (target,),
            1,
        ),
        (
            "baseline_feedback",
            """SELECT kind, ordinal, recorded_at, entry FROM riswan_data.case_memory_history
                                 WHERE investigation_id = %s AND kind = ANY(%s)
                                 AND (%s::text IS NULL OR recorded_at <= %s::text) ORDER BY kind, ordinal""",
            (target, ["feedback", "response"], timestamp, timestamp),
            4,
        ),
    )
    for name, query, params, row_count in patterns:
        plan = db.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, params).fetchone()[0][
            0
        ]
        assert plan["Plan"]["Actual Rows"] == row_count
        record_property(f"{name}_query_plan", json.dumps(plan))


def test_hosted_postgres_recurrence_and_point_in_time_baseline(hosted_postgres, monkeypatch):
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta
    from urllib.parse import urlencode

    from riswan_platform.authorization import Permission
    from tests.integration.test_historical_memory import records
    from tests.integration.test_temporal_correlation import ROOT

    app, send, _, bob, tenant, other = hosted_postgres
    base = "/v1/investigations"

    def create(label, days):
        observed = (datetime.now(UTC) - timedelta(days=days)).replace(
            hour=3, minute=0, second=0, microsecond=0
        )
        events = [
            {**event, "eventTime": (observed + timedelta(minutes=i)).isoformat()}
            for i, event in enumerate(records(1, label), 1)
        ]
        status, report = send(
            base,
            "POST",
            tenant=tenant,
            payload={"title": label, "principal": ROOT, "records": events},
        )
        assert status == 201
        return f"{base}/{report['id']}", report["created_at"]

    first, _ = create("first", 15)
    second, _ = create("second", 8)
    for case in (first, second):
        assert (
            send(case + "/feedback", "POST", tenant=tenant, payload={"disposition": "confirmed"})[0]
            == 201
        )
    present, as_of = create("current", 1)
    cutoff = urlencode({"as_of": as_of})
    status, history = send(present + "/memory", tenant=tenant, query=cutoff)
    assert status == 200
    assert history["historical_recurrence"]["SF-AWS-DATA-003"] == 50
    assert history["behavioral_baselines"]
    assert all(entry["state"] == "cold_start" for entry in history["behavioral_baselines"])
    for case in (first, second):
        assert (
            send(case + "/feedback", "POST", tenant=tenant, payload={"disposition": "benign"})[0]
            == 201
        )
        status, evidence = send(case + "/evidence", tenant=tenant)
        assert status == 200
        assert (
            send(
                case + "/memory/feedback",
                "POST",
                tenant=tenant,
                payload={
                    "classification": "authorized_activity",
                    "evidence_references": [item["reference"]["evidence_id"] for item in evidence],
                },
            )[0]
            == 201
        )
    assert send(present + "/memory", tenant=tenant, query=cutoff) == (200, history)
    status, latest = send(present + "/memory", tenant=tenant)
    assert status == 200
    assert any(entry["state"] == "established" for entry in latest["behavioral_baselines"])
    assert latest["historical_recurrence"] == {}
    assert send(present + "/memory", tenant=other, cookie=bob)[0] == 404
    evaluator = app._authenticated_routes.product.tenancy.evaluator
    evaluate = evaluator.evaluate

    def deny_first_memory(request):
        decision = evaluate(request)
        if (
            request.action == Permission.MEMORY
            and request.resource.scope.id == first.rsplit("/", 1)[-1]
        ):
            return replace(decision, effect="deny")
        return decision

    monkeypatch.setattr(evaluator, "evaluate", deny_first_memory)
    status, limited = send(present + "/memory", tenant=tenant)
    assert status == 200
    assert all(entry["state"] == "cold_start" for entry in limited["behavioral_baselines"])
    assert [item["investigation_id"] for item in limited["similar_investigations"]] == [
        second.rsplit("/", 1)[-1]
    ]


def test_hosted_postgres_temporal_late_event_and_duplicate_revision(hosted_postgres, monkeypatch):
    from urllib.parse import urlencode

    from tests.integration.test_temporal_correlation import ROOT, context, scenario

    app, send, _, bob, tenant, other = hosted_postgres
    app._authenticated_routes.product.store._compiler.detection_context = context()
    events = scenario(5)
    monkeypatch.setattr("riswan_ir.storage.sqlite.now", lambda: "2025-01-01T04:00:00+00:00")
    status, root = send(
        "/v1/investigations",
        "POST",
        tenant=tenant,
        payload={"title": "Late supplemental evidence", "principal": ROOT, "records": events[:1]},
    )
    assert status == 201
    root_path = f"/v1/investigations/{root['id']}"
    status, initial = send(root_path + "/temporal-correlation", tenant=tenant)
    assert status == 200 and initial["partial_matches"]
    assert send(root_path + "/incidents", tenant=tenant) == (200, {"incidents": []})

    monkeypatch.setattr("riswan_ir.storage.sqlite.now", lambda: "2025-02-01T04:00:00+00:00")
    status, completed = send(
        root_path + "/revisions", "POST", tenant=tenant, payload={"records": events[1:]}
    )
    assert status == 201
    child_path = f"/v1/investigations/{completed['id']}"
    status, result = send(child_path + "/incidents", tenant=tenant)
    assert status == 200
    (incident,) = result["incidents"]
    assert len({item["ingested_at"] for item in incident["timeline"]}) == 2
    assert {item["event_id"] for item in incident["timeline"]} == {e["eventID"] for e in events}
    assert send(child_path + f"/incidents/{incident['incident_id']}", tenant=tenant) == (
        200,
        incident,
    )
    assert send(child_path + "/incidents", tenant=other, cookie=bob)[0] == 404

    status, retry = send(
        child_path + "/revisions", "POST", tenant=tenant, payload={"records": events[1:]}
    )
    assert status == 201
    retry_path = f"/v1/investigations/{retry['id']}"
    status, replay = send(retry_path + "/temporal-correlation/replay", tenant=tenant)
    assert status == 200
    (replayed,) = replay["incidents"]
    assert replayed["incident_id"] == incident["incident_id"]
    assert replayed["version"] == incident["version"]
    assert [(row["event_id"], row["ingested_at"]) for row in replayed["timeline"]] == [
        (row["event_id"], row["ingested_at"]) for row in incident["timeline"]
    ]
    _, retry_evidence = send(retry_path + "/evidence", tenant=tenant)
    references = {row["reference"]["evidence_id"] for row in retry_evidence}
    assert {row["evidence_id"] for row in replayed["timeline"]} == references
    assert all(set(row["relationship_evidence_ids"]) <= references for row in replayed["timeline"])
    selected = urlencode(
        [("version", rule["id"] + "=" + rule["version"]) for rule in replay["rules"]]
    )
    assert send(retry_path + "/temporal-correlation/replay", tenant=tenant, query=selected) == (
        200,
        replay,
    )
    assert send(root_path + "/temporal-correlation", tenant=tenant) == (200, initial)


def test_postgres_identity_session_revocation_and_restart(
    hosted_postgres, postgres_identity_pool, monkeypatch
):
    from datetime import timedelta

    from riswan_app.postgres_identity import PostgresIdentityRepository
    from tests.integration.test_identity_runtime import call, login

    app, send, alice, _, tenant, _ = hosted_postgres
    assert send("/v1/investigations", tenant=tenant) == (200, [])
    status, _, profile = call(app, "/v1/identity/me", cookie=alice)
    assert status == 200
    again, _ = login(app, "alice", existing=alice)
    assert call(app, "/v1/identity/me", cookie=alice)[0] == 401
    assert call(app, "/v1/identity/me", cookie=again)[2] == profile
    monkeypatch.setattr(
        app.service, "repository", PostgresIdentityRepository(postgres_identity_pool)
    )
    assert call(app, "/v1/identity/me", cookie=again)[2] == profile
    status, _, workload = call(app, "/v1/identity/me", authorization="Bearer test-workload-token")
    assert status == 200 and workload["identity_type"] == "service"
    assert app.service.repository.is_active_workload(UUID(workload["identity_id"]))

    clock = app.service.clock
    monkeypatch.setattr(app.service, "clock", lambda: clock() + timedelta(days=2))
    assert call(app, "/v1/identity/me", cookie=again)[0] == 401
    monkeypatch.setattr(app.service, "clock", clock)
    assert call(app, "/v1/identity/me", cookie=again)[0] == 401


def test_postgres_identity_runtime_privileges(postgres_pool, postgres_identity_pool):
    import psycopg

    from riswan_app.postgres_identity import PostgresIdentityRepository

    with pytest.raises(ProtectionDenied):
        PostgresIdentityRepository(postgres_pool)
    with postgres_identity_pool.connection() as db:
        for statement in (
            "SELECT * FROM riswan_data.investigations",
            "SELECT * FROM riswan_auth.authentication_events",
            "DELETE FROM riswan_auth.authentication_events",
            "UPDATE riswan_auth.identity_provider_links SET identity_id = 'replacement'",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(statement)
    with postgres_pool.connection() as db:
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute("SELECT * FROM riswan_auth.identities")


def test_postgres_revocation_audit_failure_rolls_back(hosted_postgres, monkeypatch):
    import psycopg

    from riswan_app import identity_repository
    from tests.integration.test_identity_runtime import call

    app, _, alice, _, _, _ = hosted_postgres

    def fail_audit(db, event):
        raise psycopg.OperationalError("test audit outage")

    with monkeypatch.context() as failure:
        failure.setattr(identity_repository, "_audit", fail_audit)
        assert (
            call(app, "/v1/auth/logout", "POST", cookie=alice, origin="https://app.example")[0]
            == 503
        )
    assert call(app, "/v1/identity/me", cookie=alice)[0] == 200
    assert (
        call(app, "/v1/auth/logout", "POST", cookie=alice, origin="https://app.example")[0] == 204
    )
    assert call(app, "/v1/identity/me", cookie=alice)[0] == 401


def test_postgres_identity_failure_has_no_sqlite_fallback(hosted_postgres, tmp_path, monkeypatch):
    from psycopg_pool import PoolClosed

    from tests.integration.test_identity_runtime import call

    app, _, alice, _, _, _ = hosted_postgres

    def unavailable():
        raise PoolClosed("test authentication pool outage")

    monkeypatch.setattr(app.service.repository._pool, "connection", unavailable)
    assert call(app, "/v1/identity/me", cookie=alice)[0] == 503
    assert not (tmp_path / "identity.sqlite3").exists()


def test_postgres_identity_lookup_query_plans(postgres_identity_pool, record_property):
    with postgres_identity_pool.connection() as db, db.transaction(force_rollback=True):
        fixture_issuer = "https://plans.example"
        count = 1024
        db.execute(
            """INSERT INTO riswan_auth.identities
            SELECT md5('identity-plan-' || i)::uuid::text, 'human', 'Fixture', NULL, 'active', 0, 0
            FROM generate_series(1, %s) AS g(i)""",
            (count,),
        )
        db.execute(
            """INSERT INTO riswan_auth.identity_provider_links
            SELECT %s, 'subject-' || i, md5('identity-plan-' || i)::uuid::text
            FROM generate_series(1, %s) AS g(i)""",
            (fixture_issuer, count),
        )
        db.execute(
            """INSERT INTO riswan_auth.identity_sessions
            SELECT md5('session-plan-' || i)::uuid::text, md5('identity-plan-' || i)::uuid::text,
                   encode(sha256(convert_to('cookie-plan-' || i, 'UTF8')), 'hex'), 0, 0, 100, 1, NULL
            FROM generate_series(1, %s) AS g(i)""",
            (count,),
        )
        identity_lookup = db.execute(
            """EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            SELECT i.*, l.issuer, l.subject FROM riswan_auth.identities i
            JOIN riswan_auth.identity_provider_links l ON l.identity_id = i.id
            WHERE l.issuer = %s AND l.subject = %s""",
            (fixture_issuer, "subject-512"),
        ).fetchone()[0][0]
        session_lookup = db.execute(
            """EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
            SELECT i.*, l.issuer, l.subject, s.id AS sid, s.last_seen, s.expires, s.mfa, s.revoked
            FROM riswan_auth.identity_sessions s
            JOIN riswan_auth.identities i ON i.id = s.identity_id
            JOIN riswan_auth.identity_provider_links l ON l.identity_id = i.id
            WHERE s.digest = %s""",
            (sha256(b"cookie-plan-512").hexdigest(),),
        ).fetchone()[0][0]
        for name, plan in (
            ("identity_mapping", identity_lookup),
            ("session_digest", session_lookup),
        ):
            assert plan["Plan"]["Actual Rows"] == 1
            record_property(f"{name}_query_plan", json.dumps(plan))


@pytest.mark.parametrize(
    "mode", ["wrong-recipient", "revoked", "expired", "concurrent", "audit-failure"]
)
def test_postgres_invitation_atomicity(hosted_postgres, mode, monkeypatch):
    from datetime import datetime, timedelta
    from threading import Barrier

    import psycopg

    from riswan_app import tenancy

    app, send, _, bob, tenant, _ = hosted_postgres
    status, organizations = send("/v1/organizations")
    assert status == 200
    org = "/v1/organizations/" + next(
        item["id"] for item in organizations if item["tenant_id"] == tenant
    )
    _, identity = send("/v1/identity/me", cookie=bob)
    assert send(org, cookie=bob)[0] == 404
    assert send("/v1/investigations", cookie=bob, tenant=tenant)[0] == 404
    payload = {"identity_id": identity["identity_id"], "role": "analyst"}
    assert send(org + "/invitations", "POST", cookie=bob, payload=payload)[0] == 404
    status, invite = send(org + "/invitations", "POST", payload=payload)
    assert status == 201
    accept = "/v1/organizations/invitations/accept"
    token = {"token": invite["token"]}
    if mode == "wrong-recipient":
        assert send(accept, "POST", payload=token)[0] == 404
    elif mode == "revoked":
        assert send(org + "/invitations/" + invite["id"], "DELETE")[0] == 204
    elif mode == "expired":

        class Later(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=2)

        monkeypatch.setattr(tenancy, "datetime", Later)
    elif mode == "concurrent":
        barrier = Barrier(2)

        def accept_once():
            barrier.wait(timeout=10)
            return send(accept, "POST", cookie=bob, payload=token)[0]

        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(accept_once) for _ in range(2)]
            assert sorted(f.result(timeout=20) for f in futures) == [200, 404]
    else:
        service = app._authenticated_routes.tenancy
        audit = service._audit

        def fail_audit(*args):
            audit(*args)
            raise psycopg.OperationalError("simulated audit write failure")

        with monkeypatch.context() as patches:
            patches.setattr(service, "_audit", fail_audit)
            assert send(accept, "POST", cookie=bob, payload=token)[0] == 503
        assert send(org, cookie=bob)[0] == 404
        assert send("/v1/investigations", cookie=bob, tenant=tenant)[0] == 404
    if mode in {"wrong-recipient", "audit-failure"}:
        assert send(accept, "POST", cookie=bob, payload=token) == (200, {"tenant_id": tenant})
    else:
        assert send(accept, "POST", cookie=bob, payload=token)[0] == 404
    joined = mode not in {"revoked", "expired"}
    assert send(org, cookie=bob)[0] == (200 if joined else 404)
    assert send("/v1/investigations", cookie=bob, tenant=tenant)[0] == (200 if joined else 404)


def test_postgres_owner_transfer_and_lifecycle(hosted_postgres):
    from threading import Barrier

    _, send, alice, bob, tenant, other = hosted_postgres
    _, organizations = send("/v1/organizations")
    org = "/v1/organizations/" + next(
        item["id"] for item in organizations if item["tenant_id"] == tenant
    )
    _, actor = send("/v1/identity/me", cookie=alice)
    _, target = send("/v1/identity/me", cookie=bob)
    invite_body = {"identity_id": target["identity_id"], "role": "analyst"}
    assert send(org + "/members/role", "PUT", cookie=bob, payload=invite_body)[0] == 404
    assert send(org + "/members/" + actor["identity_id"], "DELETE")[0] == 404
    _, invite = send(org + "/invitations", "POST", payload=invite_body)
    assert (
        send(
            "/v1/organizations/invitations/accept",
            "POST",
            cookie=bob,
            payload={"token": invite["token"]},
        )[0]
        == 200
    )

    barrier = Barrier(2)

    def transfer():
        barrier.wait(timeout=10)
        return send(org + "/ownership", "POST", payload={"identity_id": target["identity_id"]})[0]

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(transfer) for _ in range(2)]
        assert sorted(f.result(timeout=20) for f in futures) == [204, 404]
    status, members = send(org + "/members", cookie=bob)
    assert status == 200
    assert [m["identity_id"] for m in members if m["role"] == "owner"] == [target["identity_id"]]
    assert send(org + "/members/" + target["identity_id"], "DELETE", cookie=bob)[0] == 404
    assert send(org + "/members/" + actor["identity_id"], "DELETE", cookie=bob)[0] == 204
    assert send("/v1/investigations", tenant=tenant, cookie=alice)[0] == 404
    assert send("/v1/investigations", tenant=other, cookie=bob)[0] == 200
    for lifecycle, expected in (("suspended", 404), ("active", 200), ("archived", 404)):
        assert send(org + "/lifecycle", "POST", cookie=bob, payload={"status": lifecycle})[0] == 200
        assert send("/v1/investigations", tenant=tenant, cookie=bob)[0] == expected
    assert send(org + "/lifecycle", "POST", cookie=bob, payload={"status": "active"})[0] == 404


def test_postgres_control_direct_sql_scope(hosted_postgres, postgres_control_pool):
    import psycopg

    from riswan_platform.identity.models import AuthenticationError

    app, send, _, _, tenant, other = hosted_postgres
    _, actor = send("/v1/identity/me")
    repo = app._authenticated_routes.tenancy.authorization
    with pytest.raises(AuthenticationError):
        repo.policy_for(UUID(actor["identity_id"]), UUID(tenant))
    with postgres_control_pool.connection() as db, db.transaction():
        assert db.execute(
            "SELECT count(*) FROM riswan_control.organization_memberships"
        ).fetchone() == (0,)
        assert db.execute(
            "SELECT count(*) FROM riswan_control.authorization_snapshots"
        ).fetchone() == (0,)
        db.execute("SELECT set_config('riswan.control_actor', %s, true)", (actor["identity_id"],))
        assert db.execute(
            "SELECT identity_id FROM riswan_control.organization_memberships WHERE tenant_id = %s",
            (tenant,),
        ).fetchall() == [(actor["identity_id"],)]
        assert (
            db.execute(
                "SELECT * FROM riswan_control.organization_memberships WHERE tenant_id = %s",
                (other,),
            ).fetchall()
            == []
        )
        for table in (
            "riswan_auth.identities",
            "riswan_data.investigations",
            "riswan_control.authorization_audit_events",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(
                    psycopg.sql.SQL("SELECT * FROM {}").format(
                        psycopg.sql.Identifier(*table.split("."))
                    )
                )
        db.execute("SELECT set_config('riswan.control_tenant', %s, true)", (tenant,))
        with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
            db.execute(
                "UPDATE riswan_control.organization_memberships SET role = 'viewer' WHERE tenant_id = %s",
                (tenant,),
            )
            db.execute("SET CONSTRAINTS ALL IMMEDIATE")
    with postgres_control_pool.connection() as db:
        assert db.execute(
            "SELECT count(*) FROM riswan_control.organization_memberships"
        ).fetchone() == (0,)


def test_postgres_control_outage_has_no_sqlite_fallback(hosted_postgres, tmp_path, monkeypatch):
    from psycopg_pool import PoolClosed

    app, send, _, _, tenant, _ = hosted_postgres

    def unavailable():
        raise PoolClosed("simulated control outage")

    repo = app._authenticated_routes.tenancy.authorization
    monkeypatch.setattr(repo._pool, "connection", unavailable)
    assert send("/v1/organizations")[0] == 503
    assert send("/v1/investigations", tenant=tenant)[0] == 503
    assert not (tmp_path / "control.sqlite3").exists()


def test_postgres_control_query_plans(hosted_postgres, record_property):
    import psycopg

    _, send, _, bob, tenant, _ = hosted_postgres
    _, actor = send("/v1/identity/me")
    _, other = send("/v1/identity/me", cookie=bob)
    actor_id, other_id = actor["identity_id"], other["identity_id"]
    with psycopg.connect("host=127.0.0.1 port=5432 dbname=riswan user=postgres") as db:
        with db.transaction(force_rollback=True):
            db.execute(
                """INSERT INTO riswan_control.organizations
                SELECT md5('org-plan-' || i)::uuid::text, 'Fixture', '{}', '2026-01-01'
                FROM generate_series(1, 512) AS g(i)"""
            )
            db.execute(
                """INSERT INTO riswan_control.tenants
                SELECT md5('tenant-plan-' || i)::uuid::text, md5('org-plan-' || i)::uuid::text, 'active'
                FROM generate_series(1, 512) AS g(i)"""
            )
            db.execute(
                """INSERT INTO riswan_control.organization_memberships
                SELECT md5('tenant-plan-' || i)::uuid::text, %s, 'owner', '2026-01-01', NULL
                FROM generate_series(1, 512) AS g(i)""",
                (other_id,),
            )
            db.execute(
                """INSERT INTO riswan_control.organization_invitations
                SELECT md5('invitation-plan-' || i)::uuid::text, md5('tenant-plan-' || i)::uuid::text,
                    %s, 'viewer', %s, md5('digest-plan-' || i), '2027-01-01', NULL
                FROM generate_series(1, 512) AS g(i)""",
                (
                    actor_id,
                    other_id,
                ),
            )
            db.execute("ANALYZE riswan_control.organization_memberships")
            db.execute("ANALYZE riswan_control.organization_invitations")
            db.execute("SET LOCAL ROLE riswan_control_runtime")
            db.execute("SELECT set_config('riswan.control_actor', %s, true)", (actor_id,))
            patterns = (
                (
                    "membership_discovery",
                    """SELECT m.tenant_id FROM riswan_control.organization_memberships m
                    WHERE m.identity_id = %s AND m.revoked_at IS NULL""",
                    (actor_id,),
                ),
                (
                    "active_membership",
                    """SELECT t.organization_id
                    FROM riswan_control.organization_memberships m JOIN riswan_control.tenants t ON t.id = m.tenant_id
                    WHERE m.tenant_id = %s AND m.identity_id = %s AND m.revoked_at IS NULL AND t.status = 'active'""",
                    (tenant, actor_id),
                ),
                (
                    "invitation_lookup",
                    """SELECT id FROM riswan_control.organization_invitations
                    WHERE digest = md5('digest-plan-256') AND identity_id = %s AND closed_at IS NULL
                    AND expires_at > '2026-01-01'""",
                    (actor_id,),
                ),
            )
            for name, query, params in patterns:
                plan = db.execute(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, params
                ).fetchone()[0][0]
                assert plan["Plan"]["Actual Rows"] >= 1
                record_property(f"{name}_query_plan", json.dumps(plan))
            db.execute("SELECT set_config('riswan.control_tenant', %s, true)", (tenant,))
            scoped = (
                (
                    "membership_list",
                    """SELECT identity_id, role, joined_at, revoked_at
                    FROM riswan_control.organization_memberships WHERE tenant_id = %s
                    ORDER BY joined_at, identity_id""",
                    (tenant,),
                ),
                (
                    "authorization_snapshot",
                    """SELECT policy FROM riswan_control.authorization_snapshots
                    WHERE actor_id = %s AND tenant_id = %s""",
                    (actor_id, tenant),
                ),
            )
            for name, query, params in scoped:
                plan = db.execute(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, params
                ).fetchone()[0][0]
                assert plan["Plan"]["Actual Rows"] >= 1
                record_property(f"{name}_query_plan", json.dumps(plan))


def test_postgres_role_scope_and_member_role_publication(hosted_postgres):
    from datetime import UTC, datetime

    from riswan_platform.authorization import (
        Assignment,
        AuthorizationRequest,
        Permission,
        Resource,
        Role,
        Scope,
        ScopeType,
    )
    from riswan_platform.authorization.enforcement import AccessDenied
    from riswan_platform.identity.principal import bind_principal

    app, send, alice, bob, tenant, _ = hosted_postgres
    _, organizations = send("/v1/organizations")
    org = "/v1/organizations/" + next(
        item["id"] for item in organizations if item["tenant_id"] == tenant
    )
    _, target = send("/v1/identity/me", cookie=bob)
    assignment = {"identity_id": target["identity_id"], "role": "viewer"}
    _, invite = send(org + "/invitations", "POST", payload=assignment)
    assert (
        send(
            "/v1/organizations/invitations/accept",
            "POST",
            cookie=bob,
            payload={"token": invite["token"]},
        )[0]
        == 200
    )
    assert send("/v1/investigations", "POST", cookie=bob, tenant=tenant, payload={})[0] == 404
    assert send(org + "/members/role", "PUT", payload={**assignment, "role": "owner"})[0] == 404
    assert send(org + "/members/role", "PUT", payload={**assignment, "role": "analyst"})[0] == 204
    assert send("/v1/investigations", "POST", cookie=bob, tenant=tenant, payload={})[0] == 400
    service = app._authenticated_routes.tenancy
    principal = app.service.authenticate("assignment-test", cookie=alice.split("=", 1)[1])
    with bind_principal(principal), service.authorization.transaction():
        context = service.context_for(principal, UUID(tenant), "platform", "assignment-test")
        assert context is not None
        resource = Resource(UUID(tenant), "platform", Scope(ScopeType.ORGANIZATION, tenant))
        request = AuthorizationRequest(principal, context, Permission.ROLES_ASSIGN, resource)
        with pytest.raises(AccessDenied):
            service.authorization.change_assignment(
                request,
                UUID(target["identity_id"]),
                Assignment(
                    Role.OPERATOR,
                    Scope(ScopeType.PLATFORM, "platform"),
                    principal.identity.identity_id,
                    datetime.now(UTC),
                ),
            )


@pytest.mark.parametrize(
    ("environment", "legacy", "enabled", "provider"),
    [
        (None, None, True, False),
        ("development", None, False, False),
        ("production", None, True, False),
        ("development", "production", True, False),
        ("development", None, True, True),
    ],
)
def test_postgres_preview_gate_precedes_config_and_database_access(
    environment, legacy, enabled, provider, tmp_path, monkeypatch
):
    from riswan_app.identity_runtime import compose_identity

    for name, value in (("RISWAN_IR_ENV", environment), ("SENTINELFORGE_ENV", legacy)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="explicit development opt-in"):
        compose_identity(
            tmp_path / "missing-oidc.json",
            tmp_path / "identity.sqlite3",
            tmp_path / "workstation.sqlite3",
            control_db=tmp_path / "control.sqlite3",
            postgres_case_pool=object(),
            enable_postgres_preview=enabled,
            secrets_providers=tmp_path / "providers.json" if provider else None,
        )
    assert list(tmp_path.iterdir()) == []


def test_postgres_case_report_honors_evidence_export_denial(
    hosted_postgres, request_payload, monkeypatch
):
    from dataclasses import replace

    from riswan_platform.authorization import Permission, ScopeType

    app, send, _, _, tenant, _ = hosted_postgres
    status, created = send("/v1/investigations", "POST", tenant=tenant, payload=request_payload)
    assert status == 201
    detail = f"/v1/investigations/{created['id']}"
    assert send(detail, tenant=tenant)[1]["canonical_events"]
    evaluator = app._authenticated_routes.tenancy.evaluator
    evaluate = evaluator.evaluate

    def deny_evidence_export(request):
        decision = evaluate(request)
        if (
            request.action == Permission.EXPORT
            and request.resource.scope.kind == ScopeType.EVIDENCE
        ):
            return replace(decision, effect="deny")
        return decision

    monkeypatch.setattr(evaluator, "evaluate", deny_evidence_export)
    status, report = send(detail, tenant=tenant)
    assert status == 200
    assert "canonical_events" not in report
    assert send(detail + "/events", tenant=tenant)[0] == 404


def test_postgres_secret_lifecycle_and_credential_leases(
    hosted_postgres,
    postgres_pool,
    postgres_identity_pool,
    postgres_control_pool,
    tmp_path,
    monkeypatch,
    record_property,
    caplog,
):
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta
    from unittest.mock import Mock

    import psycopg

    from riswan_app.identity_runtime import compose_identity
    from riswan_app.registered_credentials import CredentialRegistration, RegisteredCredentialBroker
    from riswan_app.secret_providers import MemoryProvider
    from riswan_app.secret_routing import SecretDestination, SecretRouting
    from riswan_platform.authorization.enforcement import AccessDenied
    from riswan_platform.core.context import bind_context
    from riswan_platform.identity.principal import bind_principal
    from riswan_platform.secrets import CredentialLease, ProviderUnavailable, SecretReference
    from riswan_platform.secrets.providers import (
        Binding,
        Capability,
        CredentialRequest,
        Entry,
        ExternalReference,
        GCPNamespace,
        Registry,
    )
    from tests.integration.test_identity_runtime import call

    _, _, alice, bob, tenant_id, other = hosted_postgres
    tenant = UUID(tenant_id)
    provider, instance = MemoryProvider(), uuid4()
    namespace = GCPNamespace(project="synthetic", location="global")
    binding = Binding(
        instance_id=instance,
        tenant_id=tenant,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.SECRET_READ, Capability.SECRET_WRITE, Capability.SECRET_DELETE},
        development_only=True,
    )
    routing = SecretRouting(
        Registry([Entry(binding, provider)], environment="test"),
        {(tenant, "ir"): SecretDestination(instance, namespace)},
    )

    def compose():
        return compose_identity(
            tmp_path / "oidc.json",
            None,
            tmp_path / "workstation.sqlite3",
            postgres_control_pool=postgres_control_pool,
            postgres_case_pool=postgres_pool,
            postgres_identity_pool=postgres_identity_pool,
            enable_postgres_preview=True,
            preview_secret_routing=routing,
        )

    app = compose()
    value = "synthetic-provider-only-marker"
    temporary = "synthetic-temporary-credential-marker"
    key, version = str(uuid4()), str(uuid4())
    base = "/v1/secrets"
    secret = f"{base}/{key}"

    def send(path, method="GET", payload=None, *, foreign=False):
        status, _, body = call(
            app,
            path,
            method,
            cookie=bob if foreign else alice,
            tenant=other if foreign else tenant_id,
            origin="https://app.example",
            payload=payload,
        )
        assert value not in json.dumps(body)
        return status, body

    assert (
        send(base, "POST", {"id": key, "kind": "api_key", "name": "Fixture", "value": value})[0]
        == 201
    )
    assert send(secret, foreign=True)[0] == 404
    app = compose()
    assert send(secret)[1]["current_version"] == key
    failed = str(uuid4())

    def fail_write(*args):
        raise RuntimeError(value)

    with monkeypatch.context() as patches:
        patches.setattr(provider, "put", fail_write)
        assert send(secret + "/rotate", "POST", {"operation_id": failed, "value": value})[0] == 503
    assert send(secret)[1]["current_version"] == key
    assert any(row["outcome"] == "failed" for row in send(secret + "/audit")[1])
    rotation = {"operation_id": version, "value": value}
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(
            pool.map(
                lambda _: send(secret + "/rotate", "POST", rotation)[1]["current_version"], range(2)
            )
        ) == [version, version]
    assert send(secret + "/rollback", "POST", {"version_id": key})[1]["current_version"] == key

    _, _, worker_data = call(app, "/v1/identity/me", authorization="Bearer test-workload-token")
    workload = UUID(worker_data["identity_id"])
    _, _, organizations = call(app, "/v1/organizations", cookie=alice)
    org = next(item for item in organizations if item["tenant_id"] == tenant_id)
    status, _, _ = call(
        app,
        f"/v1/organizations/{org['id']}/workloads",
        "POST",
        cookie=alice,
        origin="https://app.example",
        payload={"identity_id": str(workload)},
    )
    assert status == 204
    expires = datetime.now(UTC) + timedelta(hours=1)
    assert (
        send(
            secret + "/policy",
            "PUT",
            {"workload_id": str(workload), "purpose": "collect", "expires_at": expires.isoformat()},
        )[0]
        == 204
    )

    service = app._authenticated_routes.secrets.service
    worker = app.service.authenticate("work", bearer="test-workload-token")
    request = CredentialRequest(
        integration_id=uuid4(),
        resource=ExternalReference(namespace=namespace, native_id="fixture"),
        workload_id=workload,
        purpose="collect",
        audience="fixture",
    )
    credential = Mock()
    credential.execute.return_value = CredentialLease(id=uuid4(), expires_at=expires)
    registry = Registry(
        [
            Entry(
                binding.model_copy(update={"capabilities": {Capability.CREDENTIAL_ISSUE}}),
                credential,
            )
        ],
        environment="test",
    )
    with bind_principal(worker):
        repo = service.repository
        with repo.transaction():
            context = service.tenancy.context_for(worker, tenant, "ir", "work")
            with repo._connection() as conn:
                joined = conn.execute(
                    "SELECT joined_at FROM organization_memberships WHERE tenant_id = ? AND identity_id = ?",
                    (tenant_id, str(workload)),
                ).fetchone()[0]
        assert context is not None
        broker = RegisteredCredentialBroker(
            service,
            registry,
            {
                request.integration_id: CredentialRegistration(
                    instance, tenant, "ir", joined, request
                )
            },
        )
        with bind_context(context):
            assert service.use(
                SecretReference(id=UUID(key)),
                "collect",
                lambda item: item.value.get_secret_value() == value,
            )
            with pytest.raises(AccessDenied):
                broker.execute(request.integration_id, "unapproved")
            credential.execute.assert_not_called()
            credential.execute.side_effect = TimeoutError(temporary)
            with pytest.raises(ProviderUnavailable) as rejected:
                broker.execute(request.integration_id, "collect")
            assert temporary not in str(rejected.value)
            credential.execute.side_effect = None
            valid = credential.execute.return_value
            credential.execute.return_value = CredentialLease(
                id=uuid4(), expires_at=datetime.now(UTC) - timedelta(seconds=1)
            )
            with pytest.raises(AccessDenied):
                broker.execute(request.integration_id, "collect")
            credential.execute.return_value = valid
            credential.execute.reset_mock()

            assert (
                broker.execute(request.integration_id, "collect") == credential.execute.return_value
            )

        with bind_context(replace(context, product_id="other")):
            with pytest.raises(AccessDenied):
                broker.execute(request.integration_id, "collect")
            with pytest.raises(AccessDenied):
                service.use(SecretReference(id=UUID(key)), "collect", lambda _: True)

    from psycopg_pool import PoolClosed

    from riswan_platform.identity.models import ProviderUnavailable as StorageUnavailable

    def unavailable():
        raise PoolClosed("injected outage")

    with bind_principal(worker), bind_context(context):
        with monkeypatch.context() as patches:
            patches.setattr(service.repository._pool, "connection", unavailable)
            with pytest.raises(StorageUnavailable):
                broker.execute(request.integration_id, "collect")
    credential.execute.assert_called_once_with(request)
    assert (
        send(f"/v1/organizations/{org['id']}/lifecycle", "POST", {"status": "suspended"})[0] == 200
    )
    with bind_principal(worker), bind_context(context), pytest.raises(AccessDenied):
        broker.execute(request.integration_id, "collect")
    assert send(f"/v1/organizations/{org['id']}/lifecycle", "POST", {"status": "active"})[0] == 200

    with postgres_control_pool.connection() as db, db.transaction(force_rollback=True):
        assert db.execute("SELECT count(*) FROM riswan_control.secret_metadata").fetchone() == (0,)
        db.execute(
            """SELECT set_config('riswan.control_actor', %s, true),
            set_config('riswan.control_tenant', %s, true), set_config('riswan.secret_product', 'ir', true)""",
            (str(workload), tenant_id),
        )
        assert db.execute("SELECT id FROM riswan_control.credential_leases").fetchone() == (
            str(credential.execute.return_value.id),
        )
        for query in (
            "SELECT metadata FROM riswan_control.secret_metadata",
            "SELECT event FROM riswan_control.secret_access_events",
            "SELECT version FROM riswan_control.secret_versions",
            "SELECT operation FROM riswan_control.secret_rotations",
            "SELECT request FROM riswan_control.credential_bindings",
        ):
            rows = str(db.execute(query).fetchall())
            assert value not in rows and temporary not in rows
        db.execute(
            """INSERT INTO riswan_control.secret_versions(secret_id, id, version)
            SELECT %s, md5('plan-version-' || i)::uuid::text,
                   json_build_object('id', md5('plan-version-' || i)::uuid::text)::text
            FROM generate_series(1,256) g(i)""",
            (key,),
        )
        for name, query in (
            (
                "secret_metadata",
                "SELECT metadata FROM riswan_control.secret_metadata WHERE id = %s AND tenant_id = %s AND product = 'ir'",
            ),
            (
                "secret_versions",
                "SELECT version FROM riswan_control.secret_versions WHERE secret_id = %s AND tenant_id = %s AND product = 'ir' ORDER BY rowid DESC LIMIT 100",
            ),
            (
                "secret_audit",
                "SELECT event FROM riswan_control.secret_access_events WHERE secret_id = %s AND tenant_id = %s AND product = 'ir' ORDER BY sequence DESC LIMIT 100",
            ),
        ):
            plan = db.execute(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, (key, tenant_id)
            ).fetchone()[0][0]
            assert plan["Plan"]["Actual Rows"] > 0
            record_property(name + "_query_plan", json.dumps(plan))
        # Make the plan fixture disposable within the surrounding transaction.
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute("DELETE FROM riswan_control.secret_access_events")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction():
            db.execute("ALTER TABLE riswan_control.secret_metadata DISABLE ROW LEVEL SECURITY")
        with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
            db.execute(
                "UPDATE riswan_control.secret_metadata SET metadata = '{}' WHERE id = %s", (key,)
            )
        with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
            db.execute(
                """UPDATE riswan_control.secret_metadata
                SET metadata = jsonb_set(metadata::jsonb, '{current_version}', to_jsonb(%s::text))::text
                WHERE id = %s""",
                (str(uuid4()), key),
            )
    drift = GCPNamespace(project="different-fixture", location="global")
    drifted = SecretRouting(
        Registry(
            [Entry(binding.model_copy(update={"namespace": drift}), provider)], environment="test"
        ),
        {(tenant, "ir"): SecretDestination(instance, drift)},
    )
    with monkeypatch.context() as patches:
        patches.setattr(service, "routing", drifted)
        patches.setattr(provider, "put", Mock())
        assert (
            send(secret + "/rotate", "POST", {"operation_id": str(uuid4()), "value": value})[0]
            == 404
        )
        provider.put.assert_not_called()

    candidate = str(uuid4())
    save = service._save

    def fail_promotion(db, item):
        save(db, item)
        raise psycopg.OperationalError("simulated promotion failure")

    with monkeypatch.context() as patches:
        patches.setattr(service, "_save", fail_promotion)
        assert (
            send(secret + "/rotate", "POST", {"operation_id": candidate, "value": value})[0] == 503
        )
    assert send(secret)[1]["current_version"] == key
    assert (
        send(secret + "/rotate", "POST", {"operation_id": candidate, "value": value})[1][
            "current_version"
        ]
        == candidate
    )

    status, _, _ = call(
        app,
        f"/v1/organizations/{org['id']}/members/{workload}",
        "DELETE",
        cookie=alice,
        origin="https://app.example",
    )
    assert status == 204
    status, _, _ = call(
        app,
        f"/v1/organizations/{org['id']}/workloads",
        "POST",
        cookie=alice,
        origin="https://app.example",
        payload={"identity_id": str(workload)},
    )
    assert status == 204
    with bind_principal(worker), bind_context(context):
        with pytest.raises(AccessDenied):
            service.use(SecretReference(id=UUID(key)), "collect", lambda _: True)
        with pytest.raises(AccessDenied):
            broker.execute(request.integration_id, "collect")
    credential.execute.assert_called_once_with(request)
    assert send(secret + "/revoke", "POST")[1]["status"] == "revoked"
    audit = service._audit

    def fail_delete_completion(context, secret_id, action, outcome, reason, **kwargs):
        if action == "secret.deletion.scheduled" and outcome == "success":
            raise psycopg.OperationalError("simulated deletion audit failure")
        audit(context, secret_id, action, outcome, reason, **kwargs)

    with monkeypatch.context() as patches:
        patches.setattr(service, "_audit", fail_delete_completion)
        assert send(secret, "DELETE")[0] == 503
    assert send(secret)[1]["status"] == "pending_deletion"
    assert any(
        event["action"] == "secret.deletion.reserved" for event in send(secret + "/audit")[1]
    )
    assert send(secret, "DELETE")[1]["status"] == "pending_deletion"
    assert send(secret + "/confirm-deletion", "POST")[1]["status"] == "deleted"
    assert (
        send(f"/v1/organizations/{org['id']}/lifecycle", "POST", {"status": "archived"})[0] == 200
    )
    with bind_principal(worker), bind_context(context), pytest.raises(AccessDenied):
        broker.execute(request.integration_id, "collect")
    assert not list(tmp_path.glob("*.sqlite3"))
    assert value not in caplog.text and temporary not in caplog.text


def test_postgres_preview_rejects_live_adapter_before_config_io(tmp_path, monkeypatch):
    from riswan_app.identity_runtime import compose_identity
    from riswan_app.secret_providers import MemoryProvider
    from riswan_app.secret_routing import SecretDestination, SecretRouting
    from riswan_platform.secrets.providers import Binding, Capability, Entry, GCPNamespace, Registry

    class ProductionAdapter(MemoryProvider):
        development_only = False

    monkeypatch.setenv("RISWAN_IR_ENV", "development")
    monkeypatch.delenv("SENTINELFORGE_ENV", raising=False)
    tenant, instance = uuid4(), uuid4()
    namespace = GCPNamespace(project="fixture", location="global")
    binding = Binding(
        instance_id=instance,
        tenant_id=tenant,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.SECRET_WRITE},
    )
    routing = SecretRouting(
        Registry([Entry(binding, ProductionAdapter())], environment="test"),
        {(tenant, "ir"): SecretDestination(instance, namespace)},
    )
    with pytest.raises(ValueError, match="development-only secret adapters"):
        compose_identity(
            tmp_path / "missing-config.json",
            None,
            tmp_path / "workstation.sqlite3",
            postgres_case_pool=object(),
            postgres_control_pool=object(),
            postgres_identity_pool=object(),
            enable_postgres_preview=True,
            preview_secret_routing=routing,
        )
    assert list(tmp_path.iterdir()) == []


def test_postgres_collection_checkpoint_and_evidence_commit_together(
    hosted_postgres, postgres_pool, cloudtrail, monkeypatch, record_property
):
    from dataclasses import replace
    from datetime import UTC, datetime, timedelta
    from unittest.mock import Mock

    from riswan_app.hosted_collection import CollectionRegistration
    from riswan_app.postgres_collections import PostgresCollections
    from riswan_ir.connectors.base import CollectedBatch, CollectionFailure
    from riswan_ir.models.collection import CollectionRequest

    app, send, _, _, tenant, other = hosted_postgres
    collection = PostgresCollections(app._authenticated_routes.product.store, postgres_pool)
    source = cloudtrail["Records"][0]
    principal = source["userIdentity"]["arn"]
    account = principal.split(":")[4]
    workload = uuid4()
    now = datetime.now(UTC)
    entry = CollectionRegistration.model_validate(
        {
            "integration_id": uuid4(),
            "instance_id": uuid4(),
            "tenant_id": tenant,
            "workload_id": workload,
            "membership_joined": now,
            "namespace": {
                "cloud": "aws",
                "partition": "aws",
                "account": account,
                "region": "us-east-1",
            },
            "connector": {
                "kind": "cloudtrail",
                "principal": principal,
                "account": {
                    "account_id": account,
                    "region": "us-east-1",
                    "role_arn": f"arn:aws:iam::{account}:role/Synthetic",
                    "external_id": "synthetic-registration-only",
                },
            },
        }
    )
    first = CollectionRequest(start=now - timedelta(minutes=15), end=now)
    second = CollectionRequest(start=first.start, end=now + timedelta(minutes=1))
    context = PlatformContext(
        UUID(tenant), str(workload), "service", "ir", "request", "correlation"
    )
    batch = CollectedBatch("fixture/location", [source, source])
    connector = Mock()
    connector.collect.side_effect = lambda _: iter([batch])

    def partial(_):
        yield batch
        raise TimeoutError("synthetic provider detail")

    with bind_context(context):
        with pytest.raises(CollectionFailure, match="registration_conflict"):
            collection.confirm_registration(entry)
    with bind_context(context):
        assert collection.register(entry) is None
        advance = collection._advance

        def fail_after_checkpoint(*args):
            advance(*args)
            raise RuntimeError("injected checkpoint failure")

        with monkeypatch.context() as patches:
            patches.setattr(collection, "_advance", fail_after_checkpoint)
            with pytest.raises(RuntimeError, match="injected checkpoint failure"):
                collection.collect_and_publish(entry, first, None, connector)
        assert collection.register(entry) is None
        with monkeypatch.context() as patches:
            patches.setattr(connector.collect, "side_effect", partial)
            with pytest.raises(CollectionFailure, match="provider_failure"):
                collection.collect_and_publish(entry, first, None, connector)
        with collection._transaction(entry) as (db, _, _):
            assert db.execute(
                "SELECT healthy, watermark, failure_code FROM riswan_data.collection_progress"
            ).fetchone() == (False, None, "provider_failure")
    for denied in (
        replace(context, tenant_id=UUID(other)),
        replace(context, product_id="other"),
        replace(context, actor_id=str(uuid4())),
    ):
        with bind_context(denied), pytest.raises(CollectionFailure, match="scope_denied"):
            collection.register(entry)
    assert send("/v1/investigations", tenant=tenant) == (200, [])

    with bind_context(context):
        assert collection.collect_and_publish(entry, first, None, connector)[1] == 1
        with pytest.raises(CollectionFailure, match="stale_checkpoint"):
            collection.collect_and_publish(entry, second, None, connector)
        assert collection.collect_and_publish(entry, second, now, connector)[1] == 0
        assert not collection.record_failure(entry, second, now, provider_failed=False)
        future = CollectionRequest(start=second.end, end=second.end + timedelta(minutes=1))
        with pytest.raises(CollectionFailure, match="invalid_checkpoint_window"):
            collection.collect_and_publish(
                entry,
                future.model_copy(update={"incremental": False}),
                second.end,
                connector,
            )
        conflicting = Mock()
        altered = {**source, "userAgent": "different content"}
        conflicting.collect.return_value = iter([CollectedBatch(batch.location, [altered])])
        with pytest.raises(CollectionFailure, match="conflicting_event"):
            collection.collect_and_publish(entry, future, second.end, conflicting)
        newest = PostgresCollections(app._authenticated_routes.product.store, postgres_pool)
        assert newest.register(entry) == second.end
        with newest._transaction(entry) as (db, _, _):
            assert db.execute(
                "SELECT count(*) FROM riswan_data.collection_observations"
            ).fetchone() == (1,)
            assert db.execute("SELECT count(*) FROM riswan_data.collection_runs").fetchone() == (3,)
            assert "synthetic-registration-only" not in str(
                db.execute("SELECT connector FROM riswan_data.collection_integrations").fetchall()
            )
    status, reports = send("/v1/investigations", tenant=tenant)
    assert status == 200 and len(reports) == 1
    report = reports[0]["id"]
    assert send(f"/v1/investigations/{report}/evidence/verify", tenant=tenant)[1]["valid"]

    def concurrent():
        with bind_context(context):
            try:
                return collection.collect_and_publish(
                    entry,
                    CollectionRequest(start=now, end=second.end + timedelta(minutes=1)),
                    second.end,
                    connector,
                )[1]
            except CollectionFailure as exc:
                return exc.error.code

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: concurrent(), range(2)))
    assert 0 in results and "stale_checkpoint" in results

    with bind_context(context), collection._transaction(entry) as (db, _, scope):
        with db.transaction(force_rollback=True):
            db.execute(
                """INSERT INTO riswan_data.collection_observations
                SELECT %s,%s,%s,%s,'fixture-' || i,'fixture/location','fixture',%s
                FROM generate_series(1,256) g(i)""",
                (*scope, report),
            )
            db.execute(
                """INSERT INTO riswan_data.collection_runs
                (tenant_id,product_id,integration_id,source_scope,run_id,actor_id,start_at,end_at,received,persisted)
                SELECT %s,%s,%s,%s,gen_random_uuid(),%s,%s,%s,0,0
                FROM generate_series(1,256)""",
                (*scope, workload, first.start, first.end),
            )
            for name, query, params in (
                (
                    "collection_registration",
                    """SELECT connector FROM riswan_data.collection_integrations
                    WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
                    scope,
                ),
                (
                    "collection_receipt",
                    """SELECT digest FROM riswan_data.collection_observations
                    WHERE (tenant_id,product_id,integration_id,source_scope,event_id)=(%s,%s,%s,%s,%s)""",
                    (*scope, "fixture-128"),
                ),
                (
                    "collection_progress",
                    """SELECT watermark,healthy FROM riswan_data.collection_progress
                    WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)""",
                    scope,
                ),
                (
                    "collection_history",
                    """SELECT run_id FROM riswan_data.collection_runs
                    WHERE (tenant_id,product_id,integration_id,source_scope)=(%s,%s,%s,%s)
                    ORDER BY completed_at DESC LIMIT 100""",
                    scope,
                ),
            ):
                plan = db.execute(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, params
                ).fetchone()[0][0]
                assert plan["Plan"]["Actual Rows"] > 0
                record_property(name + "_query_plan", json.dumps(plan))


@pytest.mark.parametrize(
    "outcome",
    [
        "success",
        "timeout",
        "cycle",
        "revoked",
        "suspended",
        "reenrolled",
        "disabled_identity",
        "disabled_integration",
        "provider_drift",
        "interrupted",
        "outage",
        "outage_before",
        "ambiguous",
        "expired",
        "ordered_disable",
        "write_failure",
    ],
)
def test_authenticated_postgres_collection_handoff(
    hosted_postgres,
    postgres_pool,
    postgres_identity_pool,
    postgres_control_pool,
    tmp_path,
    cloudtrail,
    monkeypatch,
    caplog,
    outcome,
):
    from datetime import UTC, datetime, timedelta
    from threading import Event
    from unittest.mock import Mock

    import psycopg

    from riswan_app.credential_broker import AWSSTS
    from riswan_app.hosted_collection import CollectionRegistration, PreviewCollection
    from riswan_app.identity_runtime import compose_identity
    from riswan_ir.storage.sqlite import Store
    from riswan_platform.identity.models import IdentityStatus
    from riswan_platform.secrets import CredentialLease
    from tests.integration.test_identity_runtime import call

    original, send, alice, bob, tenant, other = hosted_postgres
    _, organizations = send("/v1/organizations")
    org = next(item for item in organizations if item["tenant_id"] == tenant)
    org_path = f"/v1/organizations/{org['id']}"
    _, _, identity = call(original, "/v1/identity/me", authorization="Bearer test-workload-token")
    workload = identity["identity_id"]
    worker = original.service.authenticate("fixture", bearer="test-workload-token")
    enrollment = {"identity_id": workload}
    assert send(org_path + "/workloads", "POST", payload=enrollment)[0] == 204
    _, members = send(org_path + "/members")
    joined = next(item["joined_at"] for item in members if item["identity_id"] == workload)

    event = dict(cloudtrail["Records"][0])
    principal = event["userIdentity"]["arn"]
    account = principal.split(":")[4]
    event.update(recipientAccountId=account, awsRegion="us-east-1")
    credential_canary = "synthetic-temporary-collection-canary"
    session = Mock()
    leases = []
    client = Mock()
    session.client.return_value = client

    class DevelopmentSTS(AWSSTS):
        development_only = True

        def session(self, config, now):
            lease = CredentialLease(id=uuid4(), expires_at=now + timedelta(minutes=5))
            leases.append(lease)
            return session, lease

    entry = CollectionRegistration.model_validate(
        {
            "integration_id": uuid4(),
            "instance_id": uuid4(),
            "tenant_id": tenant,
            "workload_id": workload,
            "membership_joined": joined,
            "namespace": {
                "cloud": "aws",
                "partition": "aws",
                "account": account,
                "region": "us-east-1",
            },
            "connector": {
                "kind": "cloudtrail",
                "principal": principal,
                "account": {
                    "account_id": account,
                    "region": "us-east-1",
                    "role_arn": f"arn:aws:iam::{account}:role/Fixture",
                    "external_id": credential_canary,
                },
            },
        }
    )

    def compose():
        return compose_identity(
            tmp_path / "oidc.json",
            None,
            tmp_path / "workstation.sqlite3",
            postgres_control_pool=postgres_control_pool,
            postgres_case_pool=postgres_pool,
            postgres_identity_pool=postgres_identity_pool,
            enable_postgres_preview=True,
            preview_collections=(PreviewCollection(entry, DevelopmentSTS()),),
        )

    app = compose()
    route = f"/v1/integrations/{entry.integration_id}/collect"
    collection = app._authenticated_routes.collections
    repository = collection.service.repository
    collected = {"Events": [{"CloudTrailEvent": json.dumps(event)}]}

    def request(**headers):
        return call(app, route, "POST", origin="https://app.example", **headers)

    assert request(cookie=alice, tenant=tenant)[0] == 404
    assert request(cookie=bob, tenant=other)[0] == 404
    client.lookup_events.assert_not_called()
    monkeypatch.setattr(Store, "create", Mock(side_effect=AssertionError("legacy sink invoked")))

    def page(**params):
        assert repository._control.get() is None
        # The product pool has one connection. Checkout succeeds only if no product transaction is held.
        with postgres_pool.connection(timeout=1):
            pass
        if params.get("NextToken"):
            if outcome == "timeout":
                raise TimeoutError(credential_canary)
            assert outcome == "cycle"
            return {**collected, "NextToken": "fixture"}
        if outcome in {"revoked", "suspended", "reenrolled"}:

            def change():
                if outcome == "suspended":
                    return (
                        send(org_path + "/lifecycle", "POST", payload={"status": "suspended"})[0]
                        == 200
                    )
                revoked = send(org_path + f"/members/{workload}", "DELETE")[0] == 204
                if outcome == "reenrolled":
                    return (
                        revoked
                        and send(org_path + "/workloads", "POST", payload=enrollment)[0] == 204
                    )
                return revoked

            with ThreadPoolExecutor(max_workers=1) as workers:
                assert workers.submit(change).result(timeout=10)
        if outcome == "expired":
            object.__setattr__(leases[-1], "expires_at", datetime.now(UTC) - timedelta(seconds=1))
        if outcome == "disabled_identity":
            original.service.set_status(worker.identity, IdentityStatus.DISABLED, "fixture")
        if outcome in {"disabled_integration", "provider_drift"}:
            with psycopg.connect("host=127.0.0.1 port=5432 dbname=riswan user=postgres") as admin:
                if outcome == "disabled_integration":
                    admin.execute(
                        "UPDATE riswan_data.collection_integrations SET enabled=false WHERE integration_id=%s",
                        (entry.integration_id,),
                    )
                else:
                    admin.execute(
                        "UPDATE riswan_control.secret_provider_bindings SET binding='{}' WHERE instance_id=%s",
                        (entry.instance_id,),
                    )
        if outcome == "interrupted":
            raise SystemExit()
        if outcome == "outage":
            from psycopg_pool import PoolClosed

            def offline(*args, **kwargs):
                raise PoolClosed("fixture")

            run_patches.setattr(postgres_pool, "connection", offline)
        if outcome in {"timeout", "cycle"}:
            return {**collected, "NextToken": "fixture"}
        return collected

    monkeypatch.setattr("riswan_ir.connectors.aws.requests.LAST_REGIONAL_CALL", {})
    client.lookup_events.side_effect = page

    def offline(*args, **kwargs):
        from psycopg_pool import PoolClosed

        raise PoolClosed("fixture")

    publish = collection._repository._publish
    persist_batch = collection._repository._publish_batch

    def fail_receipts(*args):
        persist_batch(*args)
        raise psycopg.OperationalError("fixture failure after receipt insertion")

    disable_started = Event()
    executor = ThreadPoolExecutor(max_workers=1)
    disable_futures = []

    def disable():
        disable_started.set()
        original.service.set_status(worker.identity, IdentityStatus.DISABLED, "fixture")

    def publish_with_fault(*args):
        if outcome == "ordered_disable":
            disable_futures.append(executor.submit(disable))
            assert disable_started.wait(timeout=5)
            with psycopg.connect("host=127.0.0.1 port=5432 dbname=riswan user=postgres") as admin:
                assert admin.execute("SELECT pg_try_advisory_xact_lock(947061)").fetchone() == (
                    False,
                )
            assert not disable_futures[-1].done()
        result = publish(*args)
        if outcome == "ambiguous":
            raise psycopg.OperationalError("fixture reply lost after commit")
        return result

    with monkeypatch.context() as run_patches:
        try:
            if outcome == "outage_before":
                run_patches.setattr(postgres_pool, "connection", offline)
            if outcome in {"ambiguous", "ordered_disable"}:
                run_patches.setattr(collection._repository, "_publish", publish_with_fault)
            if outcome == "write_failure":
                run_patches.setattr(collection._repository, "_publish_batch", fail_receipts)
            if outcome == "interrupted":
                with pytest.raises(SystemExit):
                    request(authorization="Bearer test-workload-token", tenant=tenant)
            else:
                status, _, response = request(
                    authorization="Bearer test-workload-token", tenant=tenant
                )
                expected = (
                    204
                    if outcome in {"success", "ordered_disable"}
                    else 503
                    if outcome
                    in {
                        "timeout",
                        "cycle",
                        "outage",
                        "outage_before",
                        "ambiguous",
                        "expired",
                        "write_failure",
                    }
                    else 404
                )
                assert status == expected
                assert credential_canary not in json.dumps(response)
        finally:
            executor.shutdown(wait=True)
            if outcome in {"disabled_identity", "ordered_disable"}:
                original.service.set_status(worker.identity, IdentityStatus.ACTIVE, "fixture")
    assert credential_canary not in caplog.text
    if outcome == "suspended":
        assert send(org_path + "/lifecycle", "POST", payload={"status": "active"})[0] == 200
    reports = send("/v1/investigations", tenant=tenant)[1]
    assert len(reports) == (1 if outcome in {"success", "ambiguous", "ordered_disable"} else 0)
    if outcome == "outage_before":
        assert not leases
        client.lookup_events.assert_not_called()
    if outcome == "success":
        assert send(f"/v1/investigations/{reports[0]['id']}/evidence/verify", tenant=tenant)[1][
            "valid"
        ]
        app = compose()
        assert request(authorization="Bearer test-workload-token", tenant=tenant)[0] == 204
        assert len(send("/v1/investigations", tenant=tenant)[1]) == 1
    if outcome == "ambiguous":
        app = compose()
        assert request(authorization="Bearer test-workload-token", tenant=tenant)[0] == 204
        assert len(send("/v1/investigations", tenant=tenant)[1]) == 1
    if outcome in {"interrupted", "outage", "timeout", "write_failure"}:
        first_start = client.lookup_events.call_args_list[0].kwargs["StartTime"]
        client.lookup_events.side_effect = None
        client.lookup_events.return_value = collected
        app = compose()
        assert request(authorization="Bearer test-workload-token", tenant=tenant)[0] == 204
        assert client.lookup_events.call_args.kwargs["StartTime"] == first_start
        assert len(send("/v1/investigations", tenant=tenant)[1]) == 1
    assert not list(tmp_path.glob("*.sqlite3"))
