"""Serialize validated canonical events in the supported OCSF JSON shape."""

from datetime import datetime, timezone

from ..core.fields import utc_timestamp
from ..models.canonical_event import Principal, SecurityEvent
from .registry import ACCOUNT_CHANGE, API_ACTIVITY, AUTHENTICATION

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def milliseconds(value: str) -> int:
    delta = utc_timestamp(value) - EPOCH
    return delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000


def user_payload(user: Principal) -> dict[str, object]:
    return {
        key: value
        for key, value in (
            ("uid", user.uid or user.arn),
            ("name", user.name),
            ("account", {"uid": user.account_uid} if user.account_uid else None),
        )
        if value is not None
    }


def ocsf_payload(event: SecurityEvent) -> dict[str, object]:
    source = event.metadata
    classification = event.classification
    outcome = event.outcome
    unmapped: dict[str, object] = {
        "mapping_version": source.mapping_version,
        "provider_operation": event.activity.operation,
        "extensions": event.extensions,
    }
    if event.activity.target:
        unmapped["target"] = event.activity.target
    if event.network and event.network.user_agent:
        unmapped["user_agent"] = event.network.user_agent
    if event.evidence:
        unmapped["evidence"] = event.evidence.payload()
    if event.linked_from_evidence_id:
        unmapped["linked_from_evidence_id"] = event.linked_from_evidence_id
    data: dict[str, object] = {
        **classification.model_dump(mode="json"),
        "time": milliseconds(event.observed_at),
        "status_id": int(outcome.status_id),
        "metadata": {
            "uid": event.id,
            "version": source.schema_version,
            "product": {"name": source.product, "vendor_name": source.provider},
        },
        "unmapped": {"sentinelforge": unmapped},
    }
    if outcome.status_code:
        data["status_code"] = outcome.status_code
    if event.cloud:
        cloud = event.cloud
        data["cloud"] = {
            key: value
            for key, value in (
                ("provider", cloud.provider),
                ("region", cloud.region),
                ("account", {"uid": cloud.account_uid} if cloud.account_uid else None),
            )
            if value is not None
        }
    if classification.class_uid == API_ACTIVITY:
        actor = event.actor
        network = event.network
        assert actor is not None and network is not None and network.source_ip is not None
        actor_data: dict[str, object] = {}
        if actor.user:
            actor_data["user"] = user_payload(actor.user)
        if actor.app_name:
            actor_data["app_name"] = actor.app_name
        if actor.session_created or actor.mfa is not None:
            session: dict[str, object] = {}
            if actor.session_created:
                session["created_time"] = milliseconds(actor.session_created)
            if actor.mfa is not None:
                session["is_mfa"] = actor.mfa
            actor_data["session"] = session
        api: dict[str, object] = {"operation": event.activity.operation}
        if event.activity.service:
            api["service"] = {"name": event.activity.service}
        data.update(
            actor=actor_data,
            api=api,
            src_endpoint={"ip": str(network.source_ip)},
        )
        if event.resources:
            data["resources"] = [
                item.model_dump(mode="json", include={"uid", "name", "type"}, exclude_none=True)
                for item in event.resources
            ]
    if classification.class_uid in (ACCOUNT_CHANGE, AUTHENTICATION):
        assert event.target_user is not None
        data["user"] = user_payload(event.target_user)
        if event.actor and event.actor.user:
            data["actor"] = {"user": user_payload(event.actor.user)}
        if event.network and event.network.source_ip:
            data["src_endpoint"] = {"ip": str(event.network.source_ip)}
    if classification.class_uid == AUTHENTICATION:
        data["service"] = {"name": event.activity.service}
        if event.actor and event.actor.mfa is not None:
            data["is_mfa"] = event.actor.mfa
    return data
