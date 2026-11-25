"""Normalize CloudTrail into safe events and transient correlation metadata."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ...core.fields import mapping, text_field, utc_timestamp
from ...ingestion.exports import export_records
from ...models import CloudTrailRecord
from ...models.security_event import EventCategory, Outcome, SecurityEvent, ServiceFamily
from ..base import InvalidRecord, NormalizationBatch, NormalizationIssue
from .identity import normalize_identity
from .resources import (
    ADDITIONAL_FLAGS,
    REQUEST_FIELDS,
    RESPONSE_FIELDS,
    normalize_resources,
    normalize_tls,
    summarize_payload,
)
from .validation import (
    cloud_bool,
    event_category,
    event_source,
    event_timestamp,
    event_version,
    identifier,
    required_field,
)

ROLE_CALLS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
TARGET_FIELDS = {
    **dict.fromkeys(ROLE_CALLS, "roleArn"),
    "GetObject": "bucketName",
    "CreateAccessKey": "userName",
    "AttachUserPolicy": "policyArn",
}
SERVICE_FAMILIES = {
    **dict.fromkeys(("iam", "sts", "signin", "sso"), ServiceFamily.IDENTITY),
    **dict.fromkeys(("s3", "s3control", "elasticfilesystem"), ServiceFamily.STORAGE),
    **dict.fromkeys(("ec2", "lambda"), ServiceFamily.COMPUTE),
    **dict.fromkeys(("vpc", "network-firewall", "vpc-lattice"), ServiceFamily.NETWORK),
    **dict.fromkeys(("kms", "secretsmanager"), ServiceFamily.ENCRYPTION),
    **dict.fromkeys(("cloudtrail", "guardduty", "securityhub"), ServiceFamily.MONITORING),
    **dict.fromkeys(("eks", "ecs", "ecr"), ServiceFamily.CONTAINER),
    **dict.fromkeys(("rds", "dynamodb"), ServiceFamily.DATABASE),
}
IssuedCredential = tuple[str | None, str | None, datetime | None]


@dataclass(frozen=True)
class PreparedEvent:
    event: SecurityEvent
    access_key_id: str | None = field(repr=False)
    credential: IssuedCredential = field(repr=False)
    fingerprint: bytes = field(repr=False)


def classify_service(source: str | None, operation: str) -> ServiceFamily | None:
    if source is None:
        return None
    service = source.partition(".")[0]
    if service == "ec2" and any(
        fragment in operation
        for fragment in ("Vpc", "SecurityGroup", "RouteTable", "NetworkAcl", "Subnet")
    ):
        return ServiceFamily.NETWORK
    return SERVICE_FAMILIES.get(service, ServiceFamily.OTHER)


def normalize(event: CloudTrailRecord) -> SecurityEvent:
    if not isinstance(event, dict):
        raise InvalidRecord("record", "expected_object")
    event_id = required_field(event, "eventID")
    timestamp = event_timestamp(event)
    category = event_category(event.get("eventCategory"))
    event_type = identifier(event.get("eventType"))
    insight = category == EventCategory.INSIGHT or event_type == "AwsCloudTrailInsight"
    details = mapping(event, "insightDetails") if insight else {}
    name = required_field(event if "eventName" in event or not insight else details, "eventName")
    source = event_source(event.get("eventSource", details.get("eventSource")))
    identity = normalize_identity(event)
    parameters = mapping(event, "requestParameters")
    response = mapping(event, "responseElements")
    outcome = Outcome.SUCCESS
    if insight:
        outcome = Outcome.UNKNOWN
    elif (
        event.get("errorCode")
        or event.get("errorMessage")
        or response.get("ConsoleLogin") == "Failure"
    ):
        outcome = Outcome.FAILURE
    return SecurityEvent(
        id=event_id,
        source="aws.cloudtrail",
        observed_at=timestamp,
        event="AssumeRole" if name in ROLE_CALLS else name,
        operation=name,
        event_version=event_version(event.get("eventVersion")),
        event_source=source,
        event_type=event_type,
        event_category=category,
        service_family=classify_service(source, name),
        identity=identity,
        principal=identity.arn if identity else None,
        account_id=identity.account_id if identity else None,
        target=text_field(parameters, TARGET_FIELDS[name]) if name in TARGET_FIELDS else None,
        source_ip=text_field(event, "sourceIPAddress"),
        user_agent=text_field(event, "userAgent", 1024),
        vpc_endpoint_id=identifier(event.get("vpcEndpointId")),
        region=identifier(event.get("awsRegion")),
        recipient_account_id=identifier(event.get("recipientAccountId"))
        or identifier(event.get("recipientAccountID")),
        resources=normalize_resources(event.get("resources")),
        request_parameters=summarize_payload(event.get("requestParameters"), REQUEST_FIELDS),
        response_elements=summarize_payload(event.get("responseElements"), RESPONSE_FIELDS),
        outcome=outcome,
        error_code=identifier(event.get("errorCode")),
        error_message="[redacted]" if event.get("errorMessage") else None,
        read_only=cloud_bool(event.get("readOnly")),
        request_id=identifier(event.get("requestID")),
        shared_event_id=identifier(event.get("sharedEventID")),
        tls_details=normalize_tls(event.get("tlsDetails")),
        additional_event_data=summarize_payload(
            event.get("additionalEventData"), ADDITIONAL_FLAGS, flags=True
        ),
    )


def normalize_batch(payload: object) -> NormalizationBatch[PreparedEvent]:
    try:
        records = export_records(payload)
    except ValueError:
        return NormalizationBatch([], [NormalizationIssue(-1, "records", "invalid_export")])
    if not isinstance(records, list) or len(records) > 2000:
        return NormalizationBatch([], [NormalizationIssue(-1, "records", "invalid_batch")])
    unique: dict[str, PreparedEvent] = {}
    conflicts: set[str] = set()
    issues = []
    for index, record in enumerate(records):
        try:
            event = normalize(record)
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except InvalidRecord as exc:
            issues.append(NormalizationIssue(index, exc.field, exc.code))
            continue
        except (ValueError, TypeError, RecursionError):
            issues.append(NormalizationIssue(index, "record", "invalid_json_value"))
            continue
        fingerprint = hashlib.sha256(canonical.encode()).digest()
        entry = PreparedEvent(
            event,
            text_field(mapping(record, "userIdentity"), "accessKeyId"),
            issued_credential(record, event),
            fingerprint,
        )
        previous = unique.setdefault(event.id, entry)
        if previous.fingerprint != fingerprint and event.id not in conflicts:
            conflicts.add(event.id)
            issues.append(NormalizationIssue(index, "eventID", "conflicting_duplicate"))
    normalized = sorted(
        (entry for key, entry in unique.items() if key not in conflicts),
        key=lambda entry: (entry.event.observed_at, entry.event.id),
    )
    return NormalizationBatch(normalized, issues)


def issued_credential(event: CloudTrailRecord, item: SecurityEvent) -> IssuedCredential:
    response = mapping(event, "responseElements")
    source = (text_field(event, "eventSource") or "").lower()
    if item.event == "AssumeRole" and source in ("", "sts.amazonaws.com"):
        credentials = mapping(response, "credentials")
        expiry = text_field(credentials, "expiration")
        expires_at = None
        if expiry:
            try:
                expires_at = utc_timestamp(expiry)
            except (ValueError, OverflowError):
                try:
                    expires_at = datetime.strptime(expiry, "%b %d, %Y %I:%M:%S %p").replace(
                        tzinfo=timezone.utc
                    )
                except (ValueError, OverflowError):
                    pass
        return (
            text_field(credentials, "accessKeyId"),
            text_field(mapping(response, "assumedRoleUser"), "arn"),
            expires_at,
        )
    if item.event == "CreateAccessKey" and source in ("", "iam.amazonaws.com"):
        return text_field(mapping(response, "accessKey"), "accessKeyId"), None, None
    return None, None, None
