"""Map selected CloudTrail observations into the canonical event contract."""

from ipaddress import ip_address

from ...models.canonical_event import (
    Actor,
    CanonicalModel,
    CloudContext,
    EventActivity,
    EventClassification,
    EventMetadata,
    EventOutcome,
    NetworkContext,
    Principal,
    Resource,
    SecurityEvent,
    Status,
)
from ...models.provenance import EvidenceReference
from ...models.schema import SchemaExtension, SchemaMapping
from ...models.security_event import NormalizedEvent, Outcome
from ...schema.registry import (
    ACCOUNT_CHANGE,
    API_ACTIVITY,
    AUTHENTICATION,
    BASE_EVENT,
    OCSF,
    OCSF_VERSION,
    SchemaRegistry,
)
from .detection_signals import DetectionSignals

SOURCE = "aws.cloudtrail"
MAPPING_VERSION = "1.0.0"
EXTENSION_VERSION = "1.0.0"
API_OPERATIONS = {
    "AssumeRole": ("sts", 1),
    "AssumeRoleWithSAML": ("sts", 1),
    "AssumeRoleWithWebIdentity": ("sts", 1),
    "CreateUser": ("iam", 1),
    "CreateAccessKey": ("iam", 1),
    "AttachUserPolicy": ("iam", 3),
    "GetObject": ("s3", 2),
    "PutObject": ("s3", 0),
    "RunInstances": ("ec2", 1),
    "AuthorizeSecurityGroupIngress": ("ec2", 3),
    "StopLogging": ("cloudtrail", 3),
}
OUTCOMES = {
    Outcome.SUCCESS: Status.SUCCESS,
    Outcome.FAILURE: Status.FAILURE,
    Outcome.UNKNOWN: Status.UNKNOWN,
}


class CloudTrailExtension(CanonicalModel):
    version: str
    event_version: str | None = None
    record_type: str | None = None
    record_category: str | None = None
    event_source: str | None = None
    reported_source_address: str | None = None
    request_id: str | None = None
    shared_event_id: str | None = None
    recipient_account_id: str | None = None
    vpc_endpoint_id: str | None = None
    session_issuer_arn: str | None = None
    source_identity: str | None = None
    fallback_reason: str | None = None
    identity_type: str | None = None
    detection_signals: DetectionSignals | None = None


REGISTRY = SchemaRegistry()
REGISTRY.register_schema(OCSF)
REGISTRY.register_mapping(
    SchemaMapping(source=SOURCE, version=MAPPING_VERSION, schema_version=OCSF_VERSION)
)
REGISTRY.register_extension(
    SchemaExtension(namespace=SOURCE, source=SOURCE, version=EXTENSION_VERSION),
    CloudTrailExtension,
)


def actor_from(event: NormalizedEvent) -> Actor | None:
    identity = event.identity
    arn = event.principal or (identity.arn if identity else None)
    uid = (identity.principal_id if identity else None) or arn
    name = identity.user_name if identity else None
    user = (
        Principal(uid=uid, name=name, arn=arn, account_uid=event.account_id)
        if uid or name
        else None
    )
    session = identity.session if identity else None
    app_name = identity.invoked_by if identity else None
    created = session.created_at if session else None
    if not (user or app_name or created):
        return None
    return Actor(
        user=user,
        app_name=app_name,
        session_created=created,
        mfa=session.mfa_authenticated if session else None,
    )


def classify(
    event: NormalizedEvent,
    operation: str,
    actor: Actor | None,
    network: NetworkContext,
) -> tuple[int, int, int, Principal | None, str | None]:
    if (
        event.event_type not in (None, "AwsApiCall", "AwsConsoleSignIn", "AwsVpceEvents")
        or event.event_category == "Insight"
    ):
        return 0, BASE_EVENT, 0, None, "event_type_outside_mapped_subset"
    service = event.event_source.split(".", 1)[0] if event.event_source else None
    if operation == "ConsoleLogin" and service == "signin" and actor and actor.user:
        return 3, AUTHENTICATION, 1, actor.user, None
    params = event.request_parameters.attributes if event.request_parameters else {}
    username = params.get("userName")
    if (
        operation in ("CreateUser", "AttachUserPolicy")
        and service == "iam"
        and isinstance(username, str)
    ):
        return (
            3,
            ACCOUNT_CHANGE,
            1 if operation == "CreateUser" else 7,
            Principal(name=username),
            None,
        )
    mapped = API_OPERATIONS.get(operation)
    if (mapped and service == mapped[0]) or (
        event.event_type in ("AwsApiCall", "AwsVpceEvents") and service
    ):
        if actor and network.source_ip:
            return 6, API_ACTIVITY, mapped[1] if mapped and service == mapped[0] else 0, None, None
        return 0, BASE_EVENT, 0, None, "missing_required_api_context"
    return 0, BASE_EVENT, 0, None, "activity_outside_mapped_subset"


def map_event(
    event: NormalizedEvent,
    *,
    evidence: EvidenceReference | None = None,
    parent: str | None = None,
    detection_signals: DetectionSignals | None = None,
) -> SecurityEvent:
    operation = event.operation or event.event
    actor = actor_from(event)
    ip = None
    if event.source_ip:
        try:
            ip = ip_address(event.source_ip)
        except ValueError:
            pass
    network = NetworkContext(source_ip=ip, user_agent=event.user_agent)
    category, event_class, activity, target_user, fallback = classify(
        event, operation, actor, network
    )
    identity_session = event.identity.session if event.identity else None
    extensions = CloudTrailExtension(
        version=EXTENSION_VERSION,
        event_version=event.event_version,
        record_type=event.event_type,
        record_category=event.event_category,
        event_source=event.event_source,
        reported_source_address=event.source_ip if ip is None else None,
        request_id=event.request_id,
        shared_event_id=event.shared_event_id,
        recipient_account_id=event.recipient_account_id,
        vpc_endpoint_id=event.vpc_endpoint_id,
        session_issuer_arn=identity_session.issuer.arn
        if identity_session and identity_session.issuer
        else None,
        source_identity=identity_session.source_identity if identity_session else None,
        fallback_reason=fallback,
        identity_type=event.identity.type if event.identity else None,
        detection_signals=detection_signals,
    )
    resources = [
        Resource(uid=item.arn, type=item.type, account_uid=item.account_id)
        for item in event.resources
        if item.arn or item.type
    ]
    if event.target and all(event.target != item.uid for item in resources):
        resources.append(
            Resource(uid=event.target)
            if event.target.startswith("arn:")
            else Resource(name=event.target)
        )
    canonical = SecurityEvent(
        id=event.id,
        observed_at=event.observed_at,
        classification=EventClassification(
            category_uid=category,
            class_uid=event_class,
            activity_id=activity,
            type_uid=event_class * 100 + activity,
            severity_id=0,
        ),
        metadata=EventMetadata(
            schema_version=OCSF_VERSION,
            mapping_version=MAPPING_VERSION,
            provider="AWS",
            source=SOURCE,
            product="CloudTrail",
        ),
        actor=actor,
        target_user=target_user,
        cloud=CloudContext(
            provider="AWS",
            account_uid=event.recipient_account_id or event.account_id,
            region=event.region,
        ),
        network=network,
        activity=EventActivity(
            name=event.event,
            operation=operation,
            service=event.event_source,
            target=event.target,
            read_only=event.read_only,
        ),
        outcome=EventOutcome(
            status_id=OUTCOMES[event.outcome]
            if "outcome" in event.model_fields_set
            else Status.UNKNOWN,
            status_code=event.error_code,
        ),
        resources=resources,
        extensions={SOURCE: extensions.model_dump(mode="json", exclude_none=True)},
        evidence=evidence,
        linked_from_evidence_id=parent,
    )
    checked = REGISTRY.validate(canonical)
    if not checked.valid:
        raise ValueError(
            "Canonical CloudTrail event failed validation: " + ", ".join(checked.issues)
        )
    return canonical
