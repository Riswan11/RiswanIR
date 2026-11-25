"""Construct the selected connector using an account-verified SDK session."""

from ..models.connector import ConnectorConfig
from .aws.authentication import authenticated_session, service_client
from .aws.cloudtrail import CloudTrailHistory
from .aws.requests import RequestBudget
from .aws.s3 import S3CloudTrailLogs
from .base import TelemetryConnector


def create_connector(config: ConnectorConfig, budget: RequestBudget) -> TelemetryConnector:
    session = authenticated_session(config, budget)
    if config.s3 is not None:
        client = service_client(session, "s3", config.s3.bucket_region)
        return S3CloudTrailLogs(config, client, budget)
    client = service_client(session, "cloudtrail", config.account.region)
    return CloudTrailHistory(config, client, budget)
