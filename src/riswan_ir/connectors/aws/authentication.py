"""Use temporary SDK sessions and restrict assumed roles to read-only operations."""

import json
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError

from ...models.connector import ConnectorConfig
from ..base import CollectionFailure
from .requests import RequestBudget

SDK_CONFIG = Config(
    retries={"total_max_attempts": 1},
    connect_timeout=5,
    read_timeout=20,
    ignore_configured_endpoint_urls=True,
)


def log_prefix(config: ConnectorConfig) -> str:
    source = config.s3
    if source is None:
        raise CollectionFailure("configuration", "s3_settings_required")
    parts = [
        source.prefix.strip("/"),
        "AWSLogs",
        source.organization_id or "",
        config.account.account_id,
        "CloudTrail",
        config.account.region,
    ]
    return "/".join(part for part in parts if part) + "/"


def session_policy(config: ConnectorConfig, partition: str) -> str:
    if config.s3 is None:
        statements = [
            {
                "Effect": "Allow",
                "Action": "cloudtrail:LookupEvents",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": config.account.region}},
            }
        ]
    else:
        bucket = f"arn:{partition}:s3:::{config.s3.bucket}"
        prefix = log_prefix(config)
        statements = [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": bucket,
                "Condition": {"StringLike": {"s3:prefix": prefix + "*"}},
            },
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"{bucket}/{prefix}*.json.gz",
            },
        ]
        if config.s3.kms_key_arn:
            if not config.s3.kms_key_arn.startswith(f"arn:{partition}:"):
                raise CollectionFailure("configuration", "partition_mismatch")
            suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
            statements.append(
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": config.s3.kms_key_arn,
                    "Condition": {
                        "StringEquals": {"kms:ViaService": f"s3.{config.s3.bucket_region}.{suffix}"}
                    },
                }
            )
    allowed = [statement["Action"] for statement in statements]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            *statements,
            {"Effect": "Deny", "NotAction": [*allowed, "sts:GetCallerIdentity"], "Resource": "*"},
        ],
    }
    return json.dumps(policy, separators=(",", ":"))


def service_client(session: Any, service: str, region: str) -> Any:
    return session.client(service, region_name=region, config=SDK_CONFIG, use_ssl=True, verify=True)


def assume_read_only(
    config: ConnectorConfig, session: Any, budget: RequestBudget
) -> dict[str, Any]:
    account = config.account
    partition = session.get_partition_for_region(account.region)
    if not account.role_arn or not account.role_arn.startswith(f"arn:{partition}:"):
        raise CollectionFailure("assume_role", "partition_mismatch")
    sts = service_client(session, "sts", account.region)
    args = {
        "RoleArn": account.role_arn,
        "RoleSessionName": "SentinelForgeTelemetry",
        "DurationSeconds": 900,
        "Policy": session_policy(config, partition),
    }
    if account.external_id:
        args["ExternalId"] = account.external_id.get_secret_value()
    reply = budget.call("assume_role", lambda: sts.assume_role(**args))
    issued = reply["Credentials"]
    if not issued.get("SessionToken"):
        raise CollectionFailure("assume_role", "temporary_credentials_required")
    return issued


def authenticated_session(config: ConnectorConfig, budget: RequestBudget) -> Any:
    account = config.account
    try:
        session = boto3.Session(profile_name=account.profile, region_name=account.region)
        credentials = session.get_credentials()
        if credentials is None or not credentials.get_frozen_credentials().token:
            raise CollectionFailure("credentials", "temporary_credentials_required")
        partition = session.get_partition_for_region(account.region)
        if account.role_arn and not account.role_arn.startswith(f"arn:{partition}:"):
            raise CollectionFailure("assume_role", "partition_mismatch")
        if account.role_arn:
            issued = assume_read_only(config, session, budget)
            session = boto3.Session(
                aws_access_key_id=issued["AccessKeyId"],
                aws_secret_access_key=issued["SecretAccessKey"],
                aws_session_token=issued["SessionToken"],
                region_name=account.region,
            )
        sts = service_client(session, "sts", account.region)
        caller = budget.call("get_caller_identity", sts.get_caller_identity)
        if caller.get("Account") != account.account_id:
            raise CollectionFailure("get_caller_identity", "account_mismatch")
        return session
    except (BotoCoreError, KeyError):
        raise CollectionFailure("credentials", "authentication_failed") from None
