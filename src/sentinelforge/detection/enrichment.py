"""Derive detection attributes from canonical observations and trusted local inventory."""

from ..models.canonical_event import SecurityEvent
from ..models.detection import DetectionContext, FieldPath, Scalar

Attributes = dict[FieldPath, Scalar | None]


def enrich(
    event: SecurityEvent,
    context: DetectionContext,
    seen: set[tuple[str, str]],
) -> Attributes:
    extension = event.extensions.get("aws.cloudtrail", {})
    details = extension.get("detection_signals")
    signals = details if isinstance(details, dict) else {}
    user = event.actor.user if event.actor else None
    actor = (user.arn or user.uid) if user else None
    source_account = user.account_uid if user else None
    account = event.cloud.account_uid if event.cloud else None
    signal_resource = signals.get("resource_uid")
    resource = event.activity.target or (
        signal_resource if isinstance(signal_resource, str) else None
    )
    if resource is None:
        resource = next(
            (item.uid or item.name for item in event.resources if item.uid or item.name), None
        )
    is_assumption = event.activity.name == "AssumeRole" and event.activity.service in {
        "sts.amazonaws.com",
        "sts.amazonaws.com.cn",
    }
    role = resource if is_assumption and resource and ":role/" in resource else None
    role_parts = role.split(":", 5) if role else []
    target_account = role_parts[4] if len(role_parts) == 6 and role_parts[4] else account
    issuer = extension.get("session_issuer_arn")
    identity = extension.get("identity_type")
    ip = event.network.source_ip if event.network else None
    networks = context.expected_networks.get(account or "")
    relationship = context.known_relationships.get(actor or "")
    unseen = None
    if role and actor:
        if (actor, role) in seen:
            unseen = False
        elif relationship is not None:
            unseen = role not in relationship
    result: Attributes = {
        "activity.operation": event.activity.operation,
        "activity.service": event.activity.service,
        "activity.authentication": is_assumption,
        "activity.status_id": int(event.outcome.status_id),
        "actor.uid": actor,
        "actor.kind": identity if isinstance(identity, str) else None,
        "actor.mfa": event.actor.mfa if event.actor else None,
        "actor.session_issuer": issuer if isinstance(issuer, str) else None,
        "cloud.account": account,
        "cloud.region": event.cloud.region if event.cloud else None,
        "resource.uid": resource,
        "resource.criticality": context.resources.get(resource or ""),
        "context.environment": context.account_environments.get(target_account or ""),
        "context.cross_account": source_account != target_account
        if source_account and target_account
        else None,
        "context.role_privileged": context.privileged_roles.get(
            (role or (issuer if isinstance(issuer, str) else ""))
        ),
        "context.unseen_relationship": unseen,
        "context.unexpected_network": not any(ip in network for network in networks)
        if ip is not None and networks
        else None,
    }
    for name in (
        "context.unrestricted_ingress",
        "context.public_policy",
        "context.admin_policy",
        "context.external_snapshot",
    ):
        signal = signals.get(name.split(".", 1)[1])
        result[name] = signal if isinstance(signal, bool) else None
    return result
