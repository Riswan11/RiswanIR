"""Run object-layer RLS tests against a disposable PostgreSQL service."""

import os
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from uuid import uuid4

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
        ).fetchall() == [(1,), (2,)]
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
