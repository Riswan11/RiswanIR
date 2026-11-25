"""Select structured resource and payload metadata from CloudTrail records."""

from ...models.network import TLSDetails
from ...models.resource import CloudResource, PayloadSummary
from .validation import cloud_bool, identifier

REQUEST_FIELDS = (
    "roleArn",
    "roleName",
    "policyArn",
    "userName",
    "bucketName",
    "vpcId",
    "groupId",
    "keyId",
)
RESPONSE_FIELDS = ("ConsoleLogin",)
ADDITIONAL_FLAGS = ("MFAUsed", "MobileVersion")


def normalize_resources(raw: object) -> list[CloudResource]:
    if not isinstance(raw, list):
        return []
    resources = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        arn = identifier(entry.get("ARN"))
        account_id = identifier(entry.get("accountId"))
        resource_type = identifier(entry.get("type"))
        if arn or account_id or resource_type:
            resources.append(CloudResource(arn=arn, account_id=account_id, type=resource_type))
    return resources


def summarize_payload(
    raw: object, fields: tuple[str, ...], *, flags: bool = False
) -> PayloadSummary | None:
    if not isinstance(raw, dict):
        return None
    attributes: dict[str, str | bool] = {}
    for field in fields:
        value = cloud_bool(raw.get(field)) if flags else identifier(raw.get(field))
        if value is not None:
            attributes[field] = value
    return PayloadSummary(attributes=attributes)


def normalize_tls(raw: object) -> TLSDetails | None:
    if not isinstance(raw, dict):
        return None
    return TLSDetails(
        version=identifier(raw.get("tlsVersion")),
        cipher_suite=identifier(raw.get("cipherSuite")),
        client_host=identifier(raw.get("clientProvidedHostHeader")),
    )
