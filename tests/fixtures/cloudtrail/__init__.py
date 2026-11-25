from sentinelforge.investigation.analysis import analyze
from sentinelforge.models import InvestigationRequest

ROOT = "arn:aws:iam::777788889999:user/John"
SESSION = "arn:aws:sts::111122223333:assumed-role/Developer_Role/Session_Name"
NEXT = "arn:aws:sts::111122223333:assumed-role/SecondRole/Session_Name"
KEY = "ASIAIOSFODNN7EXAMPLE"
NEXT_KEY = "ASIASECOND7EXAMPLE"
LONG_TERM_KEY = "AKIACREATED7EXAMPLE"


def record(event_id, minute, operation, arn=ROOT, key=None, **fields):
    identity = {"arn": arn, "accountId": arn.split(":")[4]}
    if key:
        identity["accessKeyId"] = key
    return {
        "eventID": event_id,
        "eventTime": f"2021-01-22T00:{minute:02}:00Z",
        "eventName": operation,
        "userIdentity": identity,
        **fields,
    }


def assumption(event_id, minute, arn=ROOT, key=None, session=SESSION, issued=KEY, **fields):
    # Adapted from AWS's IAM/STS CloudTrail examples. All values are illustrative.
    return record(
        event_id,
        minute,
        "AssumeRole",
        arn,
        key,
        eventSource="sts.amazonaws.com",
        responseElements={
            "credentials": {
                "accessKeyId": issued,
                "expiration": "Jan 22, 2021 12:46:28 AM",
                "sessionToken": "omit-me",
            },
            "assumedRoleUser": {"arn": session},
        },
        **fields,
    )


def report(records):
    return analyze(
        InvestigationRequest(title="Review AWS credentials", principal=ROOT, records=records)
    ).payload()
