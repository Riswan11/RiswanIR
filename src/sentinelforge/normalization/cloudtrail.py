"""Normalize CloudTrail records and extract credential linkage fields."""

from datetime import datetime, timezone

from ..core.fields import mapping, required, text_field, utc_timestamp


ROLE_CALLS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}


def normalize(event):
    if not isinstance(event, dict):
        raise ValueError("Each CloudTrail record must be an object.")
    identity = mapping(event, "userIdentity")
    event_id = required(event, "eventID")
    timestamp = utc_timestamp(required(event, "eventTime"))
    name = required(event, "eventName")
    params = mapping(event, "requestParameters")
    allowed_targets = {
        **dict.fromkeys(ROLE_CALLS, "roleArn"),
        "GetObject": "bucketName",
        "CreateAccessKey": "userName",
        "AttachUserPolicy": "policyArn",
    }
    return {
        "id": event_id,
        "source": "aws.cloudtrail",
        "observed_at": timestamp.isoformat(timespec="microseconds"),
        "event": "AssumeRole" if name in ROLE_CALLS else name,
        "operation": name,
        "principal": text_field(identity, "arn"),
        "target": text_field(params, allowed_targets.get(name)),
        "source_ip": text_field(event, "sourceIPAddress"),
        "user_agent": text_field(event, "userAgent", 1024),
        "region": text_field(event, "awsRegion"),
        "account_id": text_field(identity, "accountId"),
        "recipient_account_id": text_field(event, "recipientAccountId"),
    }


def issued_credential(event, item):
    response = mapping(event, "responseElements")
    if item["event"] == "AssumeRole" and event.get("eventSource", "sts.amazonaws.com") == "sts.amazonaws.com":
        credentials = mapping(response, "credentials")
        expiry = text_field(credentials, "expiration")
        expires_at = None
        if expiry:
            try:
                expires_at = utc_timestamp(expiry)
            except ValueError:
                try:
                    expires_at = datetime.strptime(expiry, "%b %d, %Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
        return (text_field(credentials, "accessKeyId"),
                text_field(mapping(response, "assumedRoleUser"), "arn"), expires_at)
    if item["event"] == "CreateAccessKey" and event.get("eventSource", "iam.amazonaws.com") == "iam.amazonaws.com":
        return text_field(mapping(response, "accessKey"), "accessKeyId"), None, None
    return None, None, None
