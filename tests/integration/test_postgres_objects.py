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
        admin.execute("GRANT CREATE ON DATABASE riswan TO riswan_migration")
    with psycopg.connect(connection + " user=riswan_migration") as owner:
        migrate(owner)
        migrate(owner)
        assert owner.execute(
            "SELECT version FROM riswan_data.schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, 14)]
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
def hosted_postgres(postgres_pool, postgres_identity_pool, tmp_path, monkeypatch):
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
    monkeypatch.setattr("riswan_ir.storage.sqlite.now", lambda: datetime.now(UTC).isoformat())
    app = identity_runtime.compose_identity(
        path,
        None,
        tmp_path / "workstation.sqlite3",
        control_db=tmp_path / "control.sqlite3",
        postgres_case_pool=postgres_pool,
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
    postgres_pool, postgres_identity_pool, hosted_postgres, tmp_path, monkeypatch, request_payload
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
        control_db=tmp_path / "control.sqlite3",
        postgres_case_pool=postgres_pool,
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
    assert sorted(file.name for file in tmp_path.glob("*.sqlite3")) == [
        "control.sqlite3",
    ]


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
