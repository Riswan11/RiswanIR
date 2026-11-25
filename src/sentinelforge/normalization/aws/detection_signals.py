"""Project bounded CloudTrail attributes used by defensive detection."""

import json
from typing import Any

from ...core.fields import mapping, text_field
from ...models.canonical_event import CanonicalModel


class DetectionSignals(CanonicalModel):
    version: str = "1.0.0"
    resource_uid: str | None = None
    admin_policy: bool | None = None
    public_policy: bool | None = None
    unrestricted_ingress: bool | None = None
    external_snapshot: bool | None = None


def entries(value: object) -> list[Any]:
    if isinstance(value, dict):
        value = value.get("items", [])
    return value[:128] if isinstance(value, list) else []


def public_policy(value: object) -> bool | None:
    if isinstance(value, str) and len(value) <= 32_768:
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return None
    if not isinstance(value, dict):
        return None
    statements = value.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not 1 <= len(statements) <= 128:
        return None
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else principal
        if not statement.get("Condition") and (aws == "*" or isinstance(aws, list) and "*" in aws):
            return True
    return None


def unrestricted_ingress(params: dict[str, Any]) -> bool | None:
    if params.get("cidrIp") == "0.0.0.0/0" or params.get("cidrIpv6") == "::/0":
        return True
    for change in entries(params.get("securityGroupRuleSet")):
        rule = mapping(change, "securityGroupRule")
        if rule.get("cidrIpv4") == "0.0.0.0/0" or rule.get("cidrIpv6") == "::/0":
            # Existing rules can represent egress. Only claim ingress when reported.
            if rule.get("isEgress") is False:
                return True
    for permission in entries(params.get("ipPermissions")):
        for name, key, public in (
            ("ipRanges", "cidrIp", "0.0.0.0/0"),
            ("ipv6Ranges", "cidrIpv6", "::/0"),
        ):
            ranges = permission.get(name) if isinstance(permission, dict) else None
            if any(isinstance(item, dict) and item.get(key) == public for item in entries(ranges)):
                return True
    return None


def external_snapshot(params: dict[str, Any], account: str | None) -> bool | None:
    attributes = mapping(params, "createVolumePermission")
    grants = entries(attributes.get("add")) or entries(params.get("userIds"))
    for grant in grants:
        if isinstance(grant, dict):
            target = grant.get("userId")
            if grant.get("group") == "all" or (
                account and isinstance(target, str) and target != account
            ):
                return True
        if account and isinstance(grant, str) and grant != account:
            return True
    return None


def project(record: dict[str, Any], operation: str, account: str | None) -> DetectionSignals | None:
    params = mapping(record, "requestParameters")
    target = next(
        (
            item
            for key in (
                "roleArn",
                "bucketName",
                "groupId",
                "snapshotId",
                "keyId",
                "trailName",
                "policyArn",
                "roleName",
                "userName",
                "detectorId",
                "name",
            )
            if (item := text_field(params, key))
        ),
        None,
    )
    policy_arn = text_field(params, "policyArn")
    values = DetectionSignals(
        resource_uid=target,
        admin_policy=policy_arn.rsplit(":", 2)[-2:] == ["aws", "policy/AdministratorAccess"]
        if policy_arn and operation in {"AttachRolePolicy", "AttachGroupPolicy", "AttachUserPolicy"}
        else None,
        public_policy=public_policy(params.get("bucketPolicy", params.get("policy")))
        if operation == "PutBucketPolicy"
        else None,
        unrestricted_ingress=unrestricted_ingress(params)
        if operation in {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}
        else None,
        external_snapshot=external_snapshot(params, account)
        if operation == "ModifySnapshotAttribute"
        else None,
    )
    return values if any(value is not None for key, value in values if key != "version") else None
