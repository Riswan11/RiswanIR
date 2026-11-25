BASE = "/v1/investigations"


def test_failed_activity_evidence_without_success_scoring(client, request_payload, cloudtrail):
    failed = {
        **cloudtrail["Records"][0],
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "eventVersion": "1.09",
        "eventCategory": "NetworkActivity",
        "eventType": "AwsVpceEvents",
        "awsRegion": "us-west-2",
        "recipientAccountId": "999988887777",
        "eventTime": "2025-01-01T04:10:00+01:00",
        "errorCode": "AccessDenied",
        "errorMessage": "fixture-private-error",
        "requestID": "request-test",
        "sharedEventID": "shared-test",
        "vpcEndpointId": "vpce-012345",
        "readOnly": False,
        "tlsDetails": {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256"},
        "resources": [{"ARN": "arn:aws:iam::123456789012:user/build", "type": "AWS::IAM::User"}],
        "requestParameters": {"userName": "build", "opaqueValue": "fixture-private-request"},
        "responseElements": {"opaqueValue": "fixture-private-response"},
        "additionalEventData": {"MFAUsed": "Yes", "opaqueValue": "fixture-private-context"},
    }
    status, report, _ = client("POST", BASE, {**request_payload, "records": failed})
    assert status == 201 and report["assessment"]["score"] == 0 and report["action"] is None
    evidence = report["evidence"][0]
    assert evidence["observed_at"] == "2025-01-01T03:10:00.000000+00:00"
    assert evidence["outcome"] == "failure" and evidence["error_code"] == "AccessDenied"
    assert evidence["error_message"] == "[redacted]"
    assert evidence["region"] == "us-west-2" and evidence["recipient_account_id"] == "999988887777"
    assert evidence["vpc_endpoint_id"] == "vpce-012345" and evidence["read_only"] is False
    assert evidence["request_id"] == "request-test" and evidence["shared_event_id"] == "shared-test"
    assert evidence["event_version"] == "1.09" and evidence["event_category"] == "NetworkActivity"
    assert evidence["tls_details"]["version"] == "TLSv1.3"
    assert evidence["request_parameters"]["attributes"] == {"userName": "build"}
    assert evidence["response_elements"]["attributes"] == {}
    assert evidence["additional_event_data"]["attributes"] == {"MFAUsed": True}
    assert evidence["resources"][0]["type"] == "AWS::IAM::User"
    assert "fixture-private-" not in str(report)
    assert client("GET", f"{BASE}/{report['id']}/evidence")[1] == report["evidence"]


def test_invalid_record_does_not_log_payload_or_create_case(
    client, request_payload, cloudtrail, caplog
):
    cloudtrail["Records"][1]["eventTime"] = "fixture-private-timestamp"
    status, response, _ = client("POST", BASE, request_payload)
    assert status == 400 and "record 2, eventTime: invalid_timestamp" in response["error"]
    assert (
        "fixture-private-timestamp" not in str(response)
        and "fixture-private-timestamp" not in caplog.text
    )
    assert client("GET", BASE)[:2] == (200, [])
