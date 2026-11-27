"""Tenant-scoped lifecycle over separate control metadata and value providers."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from riswan_platform.authorization import (
    AuthorizationRequest,
    Permission,
    Resource,
    Scope,
    ScopeType,
)
from riswan_platform.authorization.enforcement import AccessDenied
from riswan_platform.core.context import PlatformContext, require_context
from riswan_platform.identity.models import IdentityType
from riswan_platform.identity.principal import require_principal
from riswan_platform.secrets import (
    NativeSlotProvider,
    ProviderUnavailable,
    Registration,
    Result,
    RotationOperation,
    RotationRequest,
    SecretAccessEvent,
    SecretAccessPolicy,
    SecretError,
    SecretMaterial,
    SecretMetadata,
    SecretProvider,
    SecretReference,
    SecretVersion,
    Status,
    Update,
    checked_material,
    validate_expiry,
)
from riswan_platform.secrets import Scope as SecretScope
from riswan_platform.secrets.providers import Capability

from .secret_routing import SecretRouting
from .tenancy import Tenancy

SCHEMA = """
CREATE TABLE IF NOT EXISTS secret_metadata (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), product TEXT NOT NULL,
    metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS secret_tenant_product ON secret_metadata(tenant_id, product);
CREATE TABLE IF NOT EXISTS secret_versions (
    secret_id TEXT NOT NULL REFERENCES secret_metadata(id), id TEXT NOT NULL, version TEXT NOT NULL,
    PRIMARY KEY(secret_id, id)
);
CREATE TABLE IF NOT EXISTS secret_rotations (
    secret_id TEXT NOT NULL REFERENCES secret_metadata(id), id TEXT NOT NULL, operation TEXT NOT NULL,
    PRIMARY KEY(secret_id, id)
);
CREATE TABLE IF NOT EXISTS secret_consumer_policies (
    secret_id TEXT NOT NULL REFERENCES secret_metadata(id), workload_id TEXT NOT NULL,
    purpose TEXT NOT NULL, policy TEXT NOT NULL, membership_joined TEXT NOT NULL,
    PRIMARY KEY(secret_id, workload_id, purpose)
);
CREATE TABLE IF NOT EXISTS secret_access_events (
    sequence INTEGER PRIMARY KEY, secret_id TEXT NOT NULL, tenant_id TEXT NOT NULL, event TEXT NOT NULL
);
"""


class Secrets:
    def __init__(
        self,
        tenancy: Tenancy,
        provider: SecretProvider | None,
        *,
        environment: str,
        routing: SecretRouting | None = None,
        validate: Callable[[SecretMetadata, SecretMaterial], bool] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        if environment not in {"development", "test", "production"} or (
            environment == "production" and provider is not None and provider.development_only
        ):
            raise ValueError("Secret provider is not permitted in this environment.")
        self.tenancy = tenancy
        self.repository = tenancy.authorization
        self.provider = provider
        self.routing = routing
        self.environment = environment
        self._validate = validate
        self.clock = clock
        if self.repository.initializes_sqlite_schema:
            with self.repository.atomic() as db:
                for statement in SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)

    def _audit(
        self,
        context: PlatformContext,
        key: UUID,
        action: str,
        outcome: str,
        reason: str,
        *,
        provider_instance_id: UUID | None = None,
        integration_id: UUID | None = None,
        target_cloud: str | None = None,
    ) -> None:
        event = SecretAccessEvent(
            id=uuid4(),
            secret_id=key,
            tenant_id=context.tenant_id,
            product_id=context.product_id,
            actor_id=context.actor_id,
            actor_type=context.actor_type,
            request_id=context.request_id,
            correlation_id=context.correlation_id,
            action=action,
            outcome=outcome,
            reason=reason,
            occurred_at=self.clock(),
            provider_instance_id=provider_instance_id,
            integration_id=integration_id,
            target_cloud=target_cloud,
        )
        with self.repository._connection() as db:
            db.execute(
                "INSERT INTO secret_access_events(secret_id, tenant_id, event) VALUES (?, ?, ?)",
                (str(key), str(context.tenant_id), event.model_dump_json()),
            )

    @contextmanager
    def _operation(
        self, key: UUID, permission: Permission | None, action: str
    ) -> Iterator[PlatformContext]:
        context = require_context()
        principal = require_principal()
        with self.repository.transaction():
            scoped = False
            try:
                trusted = self.tenancy.context_for(
                    principal, context.tenant_id, context.product_id, context.request_id
                )
                if (
                    trusted is None
                    or trusted.actor_id != context.actor_id
                    or trusted.actor_type != context.actor_type
                ):
                    raise AccessDenied
                self.repository.bind_secret_product(context.product_id)
                scoped = True
                if permission is not None:
                    org = Scope(ScopeType.ORGANIZATION, str(context.tenant_id))
                    resource = Resource(context.tenant_id, "platform", org)
                    decision = self.tenancy.evaluator.evaluate(
                        AuthorizationRequest(
                            principal, replace(context, product_id="platform"), permission, resource
                        )
                    )
                    if not decision.allowed:
                        raise AccessDenied
                # A write probe is required before provider side effects or credential release.
                self._audit(context, key, action, "started", "AUTHORIZED")
                yield context
            except AccessDenied:
                denial = {
                    "secret.access": "secret.access.denied",
                    "credential.lease": "credential.lease.denied",
                }.get(action, action)
                if scoped or self.repository.initializes_sqlite_schema:
                    self._audit(context, key, denial, "denied", "ACCESS_DENIED")
                raise
            except SecretError:
                self._audit(context, key, action, "failed", "OPERATION_FAILED")
                raise
            else:
                success = "secret.access.granted" if action == "secret.access" else action
                self._audit(context, key, success, "success", "COMPLETED")

    def _load(self, context: PlatformContext, key: UUID) -> SecretMetadata:
        with self.repository._connection() as db:
            row = db.execute(
                "SELECT metadata FROM secret_metadata WHERE id = ? AND tenant_id = ? AND product = ?",
                (str(key), str(context.tenant_id), context.product_id),
            ).fetchone()
        if row is None:
            raise AccessDenied
        item = SecretMetadata.model_validate_json(row[0])
        return item

    def _provider(self, item: SecretMetadata, capability: Capability) -> SecretProvider:
        if item.provider_instance_id is not None:
            if self.routing is None:
                raise ProviderUnavailable("Secret provider binding unavailable.")
            provider = self.routing.provider(item, capability)
        else:
            if self.provider is None or item.provider != self.provider.name:
                raise ProviderUnavailable("Configured provider does not own this credential.")
            provider = self.provider
        if self.environment == "production" and provider.development_only:
            raise ProviderUnavailable("Secret provider unavailable in this environment.")
        return provider

    def bind_existing(self, key: UUID) -> SecretMetadata:
        with self._operation(key, Permission.SECRET_UPDATE, "secret.provider.bound") as context:
            item = self._load(context, key)
            destination = (
                self.routing.destination(context.tenant_id, context.product_id)
                if self.routing
                else None
            )
            if not destination or not self.routing or item.provider_instance_id is not None:
                raise AccessDenied
            provider = self.routing.resolve(
                context.tenant_id,
                context.product_id,
                destination.instance_id,
                Capability.SECRET_READ,
            )
            # AWS references are deterministic. Verify existing material is available at the new binding.
            if (
                provider.name != "aws-secrets-manager"
                or provider.name != item.provider
                or not item.current_version
            ):
                raise AccessDenied
            provider.get(self._key(item, item.current_version))
            bound = item.model_copy(
                update={"provider_instance_id": destination.instance_id, "updated_at": self.clock()}
            )
            with self.repository.atomic() as db:
                self._save(db, bound)
            return bound

    @staticmethod
    def _key(item: SecretMetadata, version: UUID) -> str:
        return f"riswan/{item.tenant_id.hex}/{item.id.hex}/{version.hex}"

    def _read_version(self, item: SecretMetadata, version: SecretVersion) -> SecretMaterial:
        provider = self._provider(item, Capability.SECRET_READ)
        if isinstance(provider, NativeSlotProvider):
            if version.native_version is None:
                raise ProviderUnavailable("Native secret version unavailable.")
            return provider.get_version(self._key(item, version.id), version.native_version)
        return provider.get(self._key(item, version.id))

    def _save(self, db, item: SecretMetadata) -> None:
        self._register_binding(db, item)
        db.execute(
            "UPDATE secret_metadata SET metadata = ? WHERE id = ?",
            (item.model_dump_json(), str(item.id)),
        )

    def _register_binding(self, db, item: SecretMetadata) -> None:
        if self.repository.initializes_sqlite_schema or item.provider_instance_id is None:
            return
        destination = (
            self.routing.destination(item.tenant_id, item.product_id) if self.routing else None
        )
        if destination is None or destination.instance_id != item.provider_instance_id:
            raise AccessDenied
        self._persist_provider(
            db,
            str(item.tenant_id),
            item.product_id,
            destination.instance_id,
            destination.namespace.model_dump_json(),
        )

    @staticmethod
    def _persist_provider(db, tenant: str, product: str, instance: UUID, binding: str) -> None:
        keys = (tenant, product, str(instance))
        db.execute(
            """INSERT INTO secret_provider_bindings VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING""",
            (*keys, binding),
        )
        row = db.execute(
            """SELECT binding FROM secret_provider_bindings
            WHERE tenant_id = ? AND product = ? AND instance_id = ?""",
            keys,
        ).fetchone()
        if row is None or row[0] != binding:
            raise AccessDenied

    def _validate_material(self, item: SecretMetadata, material: SecretMaterial) -> None:
        checked_material(material)
        if self._validate is None:
            return
        try:
            valid = self._validate(item, material)
        except Exception:
            raise SecretError("Credential validation failed.") from None
        if not valid:
            raise SecretError("Credential validation failed.")

    def register(self, request: Registration) -> SecretMetadata:
        with self._operation(request.id, Permission.SECRET_CREATE, "secret.created") as context:
            now = self.clock()
            validate_expiry(request.expires_at, now)
            destination = (
                self.routing.destination(context.tenant_id, context.product_id)
                if self.routing
                else None
            )
            selected = (
                self.routing.resolve(
                    context.tenant_id,
                    context.product_id,
                    destination.instance_id,
                    Capability.SECRET_WRITE,
                )
                if self.routing and destination
                else self.provider
            )
            if selected is None or (self.environment == "production" and selected.development_only):
                raise ProviderUnavailable("Secret provider unavailable.")
            item = SecretMetadata(
                id=request.id,
                tenant_id=context.tenant_id,
                organization_id=self.tenancy.organization_id(context.tenant_id),
                product_id=context.product_id,
                name=request.name,
                kind=request.kind,
                scope=SecretScope.PRODUCT,
                provider=selected.name,
                provider_instance_id=destination.instance_id if destination else None,
                status=Status.CREATED,
                created_by=UUID(context.actor_id),
                created_at=now,
                updated_at=now,
                expires_at=request.expires_at,
                rotation=request.rotation,
            )
            with self.repository._connection() as db:
                self._register_binding(db, item)
                inserted = db.execute(
                    """INSERT INTO secret_metadata (id, tenant_id, product, metadata)
                    VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                    (str(item.id), str(item.tenant_id), item.product_id, item.model_dump_json()),
                )
            if not inserted.rowcount:
                item = self._load(context, request.id)
                if item.status != Status.CREATED:
                    return item
                if item.kind != request.kind:
                    raise SecretError("Credential registration conflict.")
            rotation = RotationRequest(operation_id=request.id, value=request.value)
            self._stage(item, rotation.operation_id)
        return self._publish(request.id, rotation, Permission.SECRET_CREATE)

    def _stage(self, item: SecretMetadata, operation_id: UUID) -> RotationOperation:
        now = self.clock()
        validate_expiry(item.expires_at, now)
        if item.status not in {Status.CREATED, Status.ACTIVE}:
            raise AccessDenied
        with self.repository._connection() as db:
            row = db.execute(
                "SELECT operation FROM secret_rotations WHERE secret_id = ? AND id = ?",
                (str(item.id), str(operation_id)),
            ).fetchone()
            if row:
                return RotationOperation.model_validate_json(row[0])
            operation = RotationOperation(
                id=operation_id,
                secret_id=item.id,
                state="started",
                started_at=now,
                base_version=item.current_version,
            )
            db.execute(
                "INSERT INTO secret_rotations VALUES (?, ?, ?)",
                (str(item.id), str(operation.id), operation.model_dump_json()),
            )
            version = SecretVersion(id=operation.id, created_at=now, state="candidate")
            db.execute(
                "INSERT INTO secret_versions VALUES (?, ?, ?)",
                (str(item.id), str(version.id), version.model_dump_json()),
            )
        return operation

    def _publish(
        self, key: UUID, request: RotationRequest, permission: Permission
    ) -> SecretMetadata:
        recover = False
        with self._operation(key, permission, "secret.rotation.write_reserved") as context:
            item = self._load(context, key)
            operation = self._stage(item, request.operation_id)
            if operation.state == "completed":
                return item
            if operation.base_version != item.current_version:
                raise SecretError("Credential version changed before promotion.")
            if isinstance(self._provider(item, Capability.SECRET_WRITE), NativeSlotProvider):
                recover = operation.write_attempted
                with self.repository.atomic() as db:
                    updated = operation.model_copy(update={"write_attempted": True})
                    db.execute(
                        "UPDATE secret_rotations SET operation = ? WHERE secret_id = ? AND id = ?",
                        (updated.model_dump_json(), str(item.id), str(operation.id)),
                    )
        with self._operation(key, permission, "secret.rotation.completed") as context:
            item = self._load(context, key)
            operation = self._stage(item, request.operation_id)
            if operation.state == "completed":
                return item
            if operation.base_version != item.current_version:
                raise SecretError("Credential version changed before promotion.")
            return self._activate(context, item, request, operation, recover=recover)

    def _activate(
        self,
        context: PlatformContext,
        item: SecretMetadata,
        request: RotationRequest,
        operation: RotationOperation,
        *,
        recover: bool,
    ) -> SecretMetadata:
        now = self.clock()
        with self.repository._connection() as db:
            version = self._version(db, item.id, operation.id)
        self._audit(context, item.id, "secret.rotation.started", "started", "AUTHORIZED")
        try:
            self._validate_material(item, request)
            provider_key = self._key(item, version.id)
            provider = self._provider(item, Capability.SECRET_WRITE)
            native = (
                provider.recover_version(provider_key)
                if recover and isinstance(provider, NativeSlotProvider)
                else provider.put(provider_key, request)
            )
            version = version.model_copy(update={"native_version": native})
            if checked_material(self._read_version(item, version)) != checked_material(request):
                raise ProviderUnavailable("Credential verification failed.")
        except SecretError:
            self._finish_rotation(operation, "failed")
            self._audit(context, item.id, "secret.rotation.failed", "failed", "CANDIDATE_FAILED")
            raise
        except Exception:
            self._finish_rotation(operation, "failed")
            self._audit(context, item.id, "secret.rotation.failed", "failed", "PROVIDER_FAILED")
            raise ProviderUnavailable("Credential storage unavailable.") from None
        with self.repository.atomic() as db:
            if item.current_version is not None:
                old = self._version(db, item.id, item.current_version)
                self._set_version(db, item.id, old.model_copy(update={"state": "retired"}))
            self._set_version(db, item.id, version.model_copy(update={"state": "active"}))
            item = item.model_copy(
                update={
                    "status": Status.ACTIVE,
                    "current_version": version.id,
                    "updated_at": now,
                    "last_rotated_at": now,
                    "next_rotation_at": now + timedelta(days=item.rotation.interval_days),
                }
            )
            self._save(db, item)
            self._finish_rotation(operation, "completed")
            self._audit(
                context,
                item.id,
                "secret.version.created",
                "success",
                "COMPLETED",
                provider_instance_id=item.provider_instance_id,
            )
        return item

    def _finish_rotation(self, operation: RotationOperation, state: str) -> None:
        with self.repository._connection() as db:
            db.execute(
                "UPDATE secret_rotations SET operation = ? WHERE secret_id = ? AND id = ?",
                (
                    operation.model_copy(update={"state": state}).model_dump_json(),
                    str(operation.secret_id),
                    str(operation.id),
                ),
            )

    @staticmethod
    def _version(db, key: UUID, version: UUID) -> SecretVersion:
        row = db.execute(
            "SELECT version FROM secret_versions WHERE secret_id = ? AND id = ?",
            (str(key), str(version)),
        ).fetchone()
        if row is None:
            raise AccessDenied
        return SecretVersion.model_validate_json(row[0])

    @staticmethod
    def _set_version(db, key: UUID, version: SecretVersion) -> None:
        db.execute(
            "UPDATE secret_versions SET version = ? WHERE secret_id = ? AND id = ?",
            (version.model_dump_json(), str(key), str(version.id)),
        )

    def rotate(self, key: UUID, request: RotationRequest) -> SecretMetadata:
        with self._operation(key, Permission.SECRET_ROTATE, "secret.rotation.staged") as context:
            self._stage(self._load(context, key), request.operation_id)
        return self._publish(key, request, Permission.SECRET_ROTATE)

    def _effective_status(self, item: SecretMetadata) -> SecretMetadata:
        if (
            item.status in {Status.CREATED, Status.ACTIVE}
            and item.expires_at
            and item.expires_at <= self.clock()
        ):
            return item.model_copy(update={"status": Status.EXPIRED})
        return item

    def metadata(self, key: UUID) -> SecretMetadata:
        with self._operation(key, Permission.SECRET_READ, "secret.metadata.read") as context:
            return self._effective_status(self._load(context, key))

    def list_metadata(self) -> list[SecretMetadata]:
        with self._operation(
            UUID(int=0), Permission.SECRET_READ, "secret.metadata.list"
        ) as context:
            with self.repository._connection() as db:
                return [
                    self._effective_status(SecretMetadata.model_validate_json(row[0]))
                    for row in db.execute(
                        """SELECT metadata FROM secret_metadata WHERE tenant_id = ? AND product = ?
                        ORDER BY id LIMIT 100""",
                        (str(context.tenant_id), context.product_id),
                    )
                ]

    def update(self, key: UUID, update: Update) -> SecretMetadata:
        with self._operation(key, Permission.SECRET_UPDATE, "secret.metadata.updated") as context:
            item = self._load(context, key)
            now = self.clock()
            validate_expiry(update.expires_at, now)
            if item.status not in {Status.CREATED, Status.ACTIVE} or (
                item.expires_at and item.expires_at <= now
            ):
                raise AccessDenied
            changed = {field: getattr(update, field) for field in update.model_fields_set}
            if any(field in changed and changed[field] is None for field in ("name", "rotation")):
                raise SecretError("Invalid credential metadata.")
            if update.rotation is not None and item.last_rotated_at is not None:
                changed["next_rotation_at"] = item.last_rotated_at + timedelta(
                    days=update.rotation.interval_days
                )
            item = item.model_copy(update={**changed, "updated_at": now})
            with self.repository.atomic() as db:
                self._save(db, item)
            return item

    def versions(self, key: UUID) -> list[SecretVersion]:
        with self._operation(key, Permission.SECRET_READ, "secret.versions.read") as context:
            self._load(context, key)
            with self.repository._connection() as db:
                return [
                    SecretVersion.model_validate_json(row[0])
                    for row in db.execute(
                        "SELECT version FROM secret_versions WHERE secret_id = ? ORDER BY rowid DESC LIMIT 100",
                        (str(key),),
                    )
                ]

    def set_policy(self, key: UUID, policy: SecretAccessPolicy, *, revoke: bool = False) -> None:
        with self._operation(key, Permission.SECRET_POLICY, "secret.policy.updated") as context:
            self._load(context, key)
            with self.repository.atomic() as db:
                keys = (str(key), str(policy.workload_id), policy.purpose)
                if revoke:
                    db.execute(
                        "DELETE FROM secret_consumer_policies WHERE secret_id = ? AND workload_id = ? AND purpose = ?",
                        keys,
                    )
                else:
                    validate_expiry(policy.expires_at, self.clock())
                    joined = db.execute(
                        """SELECT joined_at FROM organization_memberships WHERE tenant_id = ?
                        AND identity_id = ? AND revoked_at IS NULL""",
                        (str(context.tenant_id), str(policy.workload_id)),
                    ).fetchone()
                    if joined is None or not self.tenancy.active_workload(policy.workload_id):
                        raise AccessDenied
                    conflict = (
                        "ON CONFLICT (secret_id, workload_id, purpose) "
                        if self.repository.initializes_sqlite_schema
                        else "ON CONFLICT (secret_id, workload_id, purpose, tenant_id, product) "
                    )
                    db.execute(
                        """INSERT INTO secret_consumer_policies
                        (secret_id, workload_id, purpose, policy, membership_joined)
                        VALUES (?, ?, ?, ?, ?) """
                        + conflict
                        + "DO UPDATE SET policy = excluded.policy, membership_joined = excluded.membership_joined",
                        (*keys, policy.model_dump_json(), joined[0]),
                    )

    def use(
        self, reference: SecretReference, purpose: str, consume: Callable[[SecretMaterial], Result]
    ) -> Result:
        with self._operation(reference.id, None, "secret.access") as context:
            item = self._load(context, reference.id)
            principal = require_principal()
            if principal.identity.identity_type not in {
                IdentityType.SERVICE,
                IdentityType.INTEGRATION,
            }:
                raise AccessDenied
            now = self.clock()
            if item.expires_at and item.expires_at <= now:
                self._audit(context, item.id, "secret.expired", "denied", "EXPIRED")
                raise AccessDenied
            if item.status != Status.ACTIVE or item.current_version is None:
                raise AccessDenied
            with self.repository._connection() as db:
                row = db.execute(
                    """SELECT p.policy FROM secret_consumer_policies p JOIN organization_memberships m
                    ON m.identity_id = p.workload_id AND m.tenant_id = ?
                    AND m.joined_at = p.membership_joined AND m.revoked_at IS NULL
                    WHERE p.secret_id = ? AND p.workload_id = ? AND p.purpose = ?""",
                    (str(context.tenant_id), str(item.id), context.actor_id, purpose),
                ).fetchone()
            if row is None or SecretAccessPolicy.model_validate_json(row[0]).expires_at <= now:
                raise AccessDenied
            try:
                with self.repository._connection() as db:
                    version = self._version(db, item.id, item.current_version)
                return consume(self._read_version(item, version))
            except Exception:
                raise ProviderUnavailable("Credential use failed.") from None

    def revoke(self, key: UUID) -> SecretMetadata:
        with self._operation(key, Permission.SECRET_REVOKE, "secret.revoked") as context:
            item = self._load(context, key)
            if item.status in {Status.DELETED, Status.PENDING_DELETION, Status.REVOKED}:
                return item
            now = self.clock()
            item = item.model_copy(
                update={"status": Status.REVOKED, "revoked_at": now, "updated_at": now}
            )
            with self.repository.atomic() as db:
                self._save(db, item)
            return item

    def delete(self, key: UUID, *, confirm: bool = False) -> SecretMetadata:
        action = "secret.deleted" if confirm else "secret.deletion.scheduled"
        with self._operation(key, Permission.SECRET_DELETE, action) as context:
            item = self._load(context, key)
            if item.status == Status.DELETED:
                return item
            if confirm and item.status != Status.PENDING_DELETION:
                raise AccessDenied
            with self.repository._connection() as db:
                versions = [
                    UUID(row[0])
                    for row in db.execute(
                        "SELECT id FROM secret_versions WHERE secret_id = ?", (str(key),)
                    )
                ]
                if not confirm:
                    item = item.model_copy(
                        update={"status": Status.PENDING_DELETION, "updated_at": self.clock()}
                    )
                    self._save(db, item)
                    for version in versions:
                        self._provider(item, Capability.SECRET_DELETE).schedule_delete(
                            self._key(item, version)
                        )
                elif all(
                    self._provider(item, Capability.SECRET_DELETE).deleted(self._key(item, version))
                    for version in versions
                ):
                    item = item.model_copy(
                        update={
                            "status": Status.DELETED,
                            "current_version": None,
                            "updated_at": self.clock(),
                        }
                    )
                    self._save(db, item)
                return item

    def audit(self, key: UUID) -> list[SecretAccessEvent]:
        with self._operation(key, Permission.SECRET_AUDIT, "secret.audit.read") as context:
            self._load(context, key)
            with self.repository._connection() as db:
                return [
                    SecretAccessEvent.model_validate_json(row[0])
                    for row in db.execute(
                        """SELECT event FROM secret_access_events WHERE secret_id = ? AND tenant_id = ?
                    ORDER BY sequence DESC LIMIT 100""",
                        (str(key), str(context.tenant_id)),
                    )
                ]

    def rollback(self, key: UUID, version_id: UUID) -> SecretMetadata:
        with self._operation(
            key, Permission.SECRET_ROTATE, "secret.rotation.rolled_back"
        ) as context:
            item = self._load(context, key)
            now = self.clock()
            validate_expiry(item.expires_at, now)
            if item.status != Status.ACTIVE or item.current_version is None:
                raise AccessDenied
            with self.repository.atomic() as db:
                version = self._version(db, key, version_id)
                if version.state != "retired":
                    raise AccessDenied
                material = self._read_version(item, version)
                self._validate_material(item, material)
                current = self._version(db, key, item.current_version)
                self._set_version(db, key, current.model_copy(update={"state": "retired"}))
                self._set_version(db, key, version.model_copy(update={"state": "active"}))
                item = item.model_copy(
                    update={
                        "current_version": version_id,
                        "updated_at": now,
                        "last_rotated_at": now,
                        "next_rotation_at": now + timedelta(days=item.rotation.interval_days),
                    }
                )
                self._save(db, item)
                return item
