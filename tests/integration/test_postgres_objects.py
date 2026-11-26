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
        admin.execute("GRANT CREATE ON DATABASE riswan TO riswan_migration")
    with psycopg.connect(connection + " user=riswan_migration") as owner:
        migrate(owner)
        migrate(owner)
        assert owner.execute(
            "SELECT version FROM riswan_data.schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,), (7,)]
    with pool_module.ConnectionPool(
        connection + " user=riswan_runtime",
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


def test_hosted_postgres_case_preview(postgres_pool, tmp_path, monkeypatch, request_payload):
    import psycopg
    from psycopg_pool import PoolClosed

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
    app = identity_runtime.compose_identity(
        path,
        tmp_path / "identity.sqlite3",
        tmp_path / "workstation.sqlite3",
        control_db=tmp_path / "control.sqlite3",
        postgres_case_pool=postgres_pool,
    )
    alice, _ = login(app, "alice")
    bob, _ = login(app, "bob")

    def send(path, method="GET", *, cookie=alice, tenant=None, payload=None):
        status, _, response = call(
            app,
            path,
            method,
            cookie=cookie,
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
    assert send(endpoint + "/memory", tenant=a)[0] == 501
    assert send(endpoint + "/risk", tenant=a)[0] == 200
    assert send(endpoint + "/knowledge-graph", tenant=a)[0] == 200
    assert send(endpoint + "/temporal-correlation", tenant=a)[0] == 200
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
        tmp_path / "identity.sqlite3",
        tmp_path / "workstation.sqlite3",
        control_db=tmp_path / "control.sqlite3",
        postgres_case_pool=postgres_pool,
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
            assert row[1]["security_graphs"] and row[1]["security_data_digest"]
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
                   WHERE investigation_id = %s AND event #>> '{classification,type_uid}' = %s
                   ORDER BY observed_at, ordinal LIMIT 50""",
                (case, str(event_type)),
            ).fetchall()
            assert any("scoped_event_type_timeline" in row[0] for row in plan)
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
    assert sorted(file.name for file in tmp_path.glob("*.sqlite3")) == [
        "control.sqlite3",
        "identity.sqlite3",
    ]
