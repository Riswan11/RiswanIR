"""Persistence isolation and authenticated protection regression tests."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from riswan_app.protected_objects import LocalObjects
from riswan_ir.core.errors import NotFoundError
from riswan_ir.storage.sqlite import Store
from riswan_platform.core.context import PlatformContext, bind_context
from riswan_platform.core.exceptions import ContextRequiredError
from riswan_platform.data_protection import (
    Classification,
    DataPolicy,
    Ownership,
    ProtectionDenied,
    Residency,
    Retention,
)
from riswan_platform.data_protection.envelope import DataIdentity, EnvelopeProtector, KeyBinding
from riswan_platform.data_protection.objects import Destinations, ObjectReference, ProtectedObjects
from riswan_platform.secrets.providers import (
    Binding,
    Capability,
    Entry,
    ExternalReference,
    GCPNamespace,
    KeyAlgorithm,
    Registry,
)


def context():
    return PlatformContext(uuid4(), str(uuid4()), "human", "ir", "request", "correlation")


def test_hosted_store_enforces_case_and_product_boundary(tmp_path, investigation_request):
    store = Store(tmp_path / "hosted.sqlite3", hosted=True)
    first, second = context(), context()
    with bind_context(first):
        case = store.create(investigation_request)
        assert store.verify_evidence(case.id).valid
    with pytest.raises(ContextRequiredError):
        store.get(case.id)
    with bind_context(replace(first, product_id="other")), pytest.raises(ContextRequiredError):
        store.get(case.id)
    with bind_context(second):
        other = store.create(investigation_request)
        assert [item.id for item in store.list_scoped((case.id, other.id))] == [other.id]
        for lookup in (
            store.get,
            store.get_summary,
            store.evidence_ids,
            store.security_graph,
            store.temporal_result,
            store.verify_evidence,
            store.export_evidence,
            store.memory_remove,
        ):
            with pytest.raises(NotFoundError, match="Investigation not found"):
                lookup(case.id)
        with pytest.raises(ContextRequiredError):
            store.memory_expire()
        assert store.verify_evidence(other.id).valid


def test_protected_object_cannot_be_read_under_another_owner_or_resource(tmp_path):
    aes = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead").AESGCM
    from secrets import token_bytes

    first, second = context(), context()
    namespace = GCPNamespace(project="fixture", location="us-central1")
    resource = ExternalReference(namespace=namespace, native_id="fixture-key")
    instance = uuid4()
    wrapping = aes(aes.generate_key(bit_length=256))

    class ManagedFixture:
        def encrypt(self, request):
            nonce = token_bytes(12)
            return nonce + wrapping.encrypt(nonce, request.payload, b"test-key")

        def decrypt(self, request):
            return wrapping.decrypt(request.payload[:12], request.payload[12:], b"test-key")

    binding = Binding(
        instance_id=instance,
        tenant_id=first.tenant_id,
        product_id="ir",
        namespace=namespace,
        capabilities={Capability.KEY_ENCRYPT, Capability.KEY_DECRYPT},
    )
    protector = EnvelopeProtector(
        Registry([Entry(binding, ManagedFixture())], environment="test"),
        {(first.tenant_id, "ir"): instance},
        {
            instance: KeyBinding(
                instance_id=instance, resource=resource, algorithm=KeyAlgorithm.MANAGED_SYMMETRIC
            )
        },
    )
    policy = DataPolicy(
        classification=Classification.RESTRICTED,
        residency=Residency(regions={"us-central1"}),
        retention=Retention(days=1),
    )
    ref = ObjectReference(id=uuid4())
    identity = DataIdentity(
        owner=Ownership(tenant_id=first.tenant_id, product_id="ir"),
        resource_id=str(ref.id),
        resource_type="evidence",
        classification=policy.classification,
    )
    path = tmp_path / "objects.sqlite3"
    objects = ProtectedObjects(
        LocalObjects(path),
        protector,
        Destinations(
            storage="us-central1", processing="us-central1", key="us-central1", backup="us-central1"
        ),
        lambda _, __, operation: operation in {"get", "put"},
    )
    payload = b"synthetic-restricted-record"
    with bind_context(first):
        objects.put(identity, ref, policy, payload)
        assert objects.get(identity, ref, policy) == payload
        assert payload not in path.read_bytes()
        sealed = protector.seal(identity, payload)
        assert protector.open(identity, protector.rewrap(identity, sealed)) == payload
        with pytest.raises(ProtectionDenied):
            protector.open(identity.model_copy(update={"resource_type": "graph"}), sealed)
        with pytest.raises(ProtectionDenied):
            protector.open(identity, sealed.model_copy(update={"key_instance_id": uuid4()}))
        with pytest.raises(ProtectionDenied):
            protector.open(identity, sealed.model_copy(update={"ciphertext": "AAAA"}))
        with pytest.raises(ProtectionDenied):
            objects.get(identity, ObjectReference(id=uuid4()), policy)
        with pytest.raises(ProtectionDenied):
            objects.get(
                identity,
                ref,
                policy.model_copy(update={"residency": Residency(regions={"global"})}),
            )
    with bind_context(second), pytest.raises(ProtectionDenied):
        objects.get(identity, ref, policy)
    assert policy.encrypted
    now = datetime.now(UTC)
    assert policy.retention.eligible(now - timedelta(days=2), now, legal_hold=False)
    assert not policy.retention.eligible(now - timedelta(days=2), now, legal_hold=True)


@pytest.mark.parametrize("cloud", ["s3", "azure", "google"])
def test_object_adapters_use_create_only_and_reject_invalid_keys(cloud):
    from io import BytesIO
    from unittest.mock import Mock

    from riswan_app.protected_objects import AzureObjects, GoogleObjects, S3Objects

    sdk = Mock()
    payload = b"opaque-encrypted-fixture"
    key = "1" * 32 + "/" + "2" * 64 + "/" + "3" * 32
    if cloud == "s3":
        backend = S3Objects(sdk, "approved-bucket", "123456789012")
        sdk.get_object.return_value = {"Body": BytesIO(payload)}
    elif cloud == "azure":
        backend = AzureObjects(sdk)
        sdk.get_blob_client.return_value.download_blob.return_value.readall.return_value = payload
    else:
        backend = GoogleObjects(sdk)
        sdk.blob.return_value.download_as_bytes.return_value = payload
    with pytest.raises(ProtectionDenied):
        backend.get("../foreign")
    assert not sdk.mock_calls
    backend.put(key, payload)
    assert backend.get(key) == payload
    if cloud == "s3":
        assert sdk.put_object.call_args.kwargs["IfNoneMatch"] == "*"
        assert sdk.get_object.call_args.kwargs["ExpectedBucketOwner"] == "123456789012"
    elif cloud == "azure":
        assert sdk.get_blob_client.return_value.upload_blob.call_args.kwargs["overwrite"] is False
    else:
        assert sdk.blob.return_value.upload_from_string.call_args.kwargs["if_generation_match"] == 0


def test_raw_payload_migration_preserves_hashes_and_separates_shared_evidence(
    tmp_path, investigation_request
):
    store = Store(tmp_path / "hosted.sqlite3", hosted=True)
    first, second = context(), context()
    with bind_context(first):
        a = store.create(investigation_request)
    with bind_context(second):
        b = store.create(investigation_request)
    with store.connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO raw_evidence_payloads SELECT raw_id, payload FROM tenant_raw_evidence_payloads"
        )
        db.execute("DELETE FROM tenant_raw_evidence_payloads")
        db.execute("DELETE FROM evidence_schema_migrations")
    migrated = Store(store.path, hosted=True)
    with migrated.connect() as db:
        assert (
            db.execute(
                "SELECT count(DISTINCT tenant_id) FROM tenant_raw_evidence_payloads"
            ).fetchone()[0]
            == 2
        )
        assert db.execute("SELECT count(*) FROM raw_evidence_payloads").fetchone()[0] == 0
    for actor, report in ((first, a), (second, b)):
        with bind_context(actor):
            actual = migrated.get(report.id)
            assert actual.evidence == report.evidence
            assert migrated.verify_evidence(report.id).valid
    with pytest.raises(NotFoundError):
        Store(store.path).get(a.id)


def test_case_hold_serializes_with_memory_removal(tmp_path, investigation_request):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from riswan_ir.storage import legal_holds

    store = Store(tmp_path / "hosted.sqlite3", hosted=True)
    actor = context()
    with bind_context(actor):
        report = store.create(investigation_request)
    started = Event()

    def remove():
        with bind_context(actor):
            started.set()
            store.memory_remove(report.id)

    with ThreadPoolExecutor(max_workers=1) as worker:
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            legal_holds.change(
                db,
                report.id,
                str(uuid4()),
                actor.actor_id,
                datetime.now(UTC).isoformat(),
                "Preserve records",
                actor.request_id,
                release=False,
            )
            pending = worker.submit(remove)
            assert started.wait(2)
            assert not pending.done()
        with pytest.raises(ProtectionDenied):
            pending.result(timeout=5)
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM memory_tombstones").fetchone()[0] == 0


def test_transient_compiler_is_request_local_and_closes_workspace(investigation_request):
    from concurrent.futures import ThreadPoolExecutor
    from sqlite3 import ProgrammingError

    compiler = Store(":memory:", hosted=True, transient=True)

    def compile_case(fail):
        actor = context()
        connection = None
        if fail:
            with pytest.raises(RuntimeError), bind_context(actor), compiler.connect() as connection:
                compiler.create_in_transaction(connection, investigation_request)
                raise RuntimeError("abort")
        else:
            with bind_context(actor), compiler.connect() as connection:
                assert connection.execute("PRAGMA temp_store").fetchone()[0] == 2
                assert connection.execute("PRAGMA database_list").fetchone()[2] == ""
                assert connection.execute("SELECT count(*) FROM investigations").fetchone()[0] == 0
                case = compiler.create_in_transaction(connection, investigation_request)
                assert connection.execute("SELECT id FROM investigations").fetchone()[0] == case
        with pytest.raises(ProgrammingError):
            connection.execute("SELECT 1")

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(compile_case, [False, True]))
