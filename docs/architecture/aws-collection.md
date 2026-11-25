# Read-only AWS collection

The local `riswan-ir-collect` CLI reads CloudTrail Event History or gzip logs from S3. It runs alongside the existing local app and shares its SQLite evidence pipeline. The browser API has no connector or credential controls. Manual ingestion remains available.

| Source | Coverage | Cloud API calls |
| --- | --- | --- |
| Event History | The last 90 days of regional management events | CloudTrail LookupEvents |
| S3 | Management and data events already configured for delivery to the selected trail and standard CloudTrail prefix | S3 ListObjectsV2 and GetObject |

Both authenticate using STS GetCallerIdentity. An optional STS AssumeRole session further restricts permissions. S3 supports opt-in decrypt permission for one configured KMS key via S3. [Event History limits](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/lookup_events.html) · [S3 log layout](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)

## Configuration

Keep the configuration file outside source control. Each JSON array entry selects a single source, account, region, and starting principal. Add entries for additional accounts or regions.

```json
[
  {
    "kind": "cloudtrail",
    "account": {
      "account_id": "123456789012",
      "region": "us-east-1",
      "profile": "sandbox-sso"
    },
    "principal": "arn:aws:iam::123456789012:user/example",
    "interval_seconds": 300,
    "window_minutes": 60,
    "overlap_minutes": 15,
    "max_requests": 200,
    "max_events": 10000
  },
  {
    "kind": "s3",
    "account": {
      "account_id": "999988887777",
      "region": "us-west-2",
      "profile": "sandbox-sso",
      "role_arn": "arn:aws:iam::999988887777:role/SentinelForgeTelemetry"
    },
    "principal": "arn:aws:iam::999988887777:user/example",
    "s3": {
      "bucket": "example-trail-archive",
      "bucket_region": "us-east-1",
      "owner_account_id": "999988887777",
      "prefix": "optional-prefix"
    },
    "overlap_minutes": 60,
    "max_object_bytes": 8000000
  }
]
```

Use an AWS SDK credential chain that supplies temporary credentials, such as an authenticated SSO profile or a workload role. Connector configuration rejects access key and session token fields. For a configured cross-account role, the role ARN must match the requested account and partition. Set `external_id` in the account configuration only when the role trust requires it. Specify `organization_id` for organization logs and `kms_key_arn` for a KMS-encrypted S3 archive. Configure the bucket's actual region separately from the CloudTrail event region.

## IAM and trust

- Grant the Event History role `cloudtrail:LookupEvents` on `*` with an `aws:RequestedRegion` condition. No other CloudTrail operations are needed.
- Grant the S3 role `s3:ListBucket` on the named bucket with an `s3:prefix` condition restricted to `<prefix>/AWSLogs/[<organization>/]<account>/CloudTrail/<region>/*`. Grant `s3:GetObject` only on the corresponding `*.json.gz` objects. Allow `kms:Decrypt` only for the configured encryption key and via the bucket region's S3 service when needed. Bucket and key policies must allow the role where applicable.
- Grant the source identity `sts:AssumeRole` only on the configured role. In the target role's trust policy, name the exact trusted source principal and add the external ID condition where appropriate. Avoid a wildcard trust principal. The assumed-session policy allows the selected read operations, scopes their resources and explicitly denies other actions. Direct SDK sessions depend on the IAM permissions of the selected profile. Use a dedicated read-only identity.
- The connector uses TLS with certificate verification, verifies the caller account, checks reported recipient account and region when present, and supplies ExpectedBucketOwner to S3 List and Get. Keep the local database and logs under workstation access controls.

[AWS role session permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_assumerole.html) · [AWS external ID guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html) · [S3 owner checks](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)

## Run and monitor

```sh
python -m pip install .
riswan-ir-collect --config ../aws-targets.json run
riswan-ir-collect --config ../aws-targets.json run --watch
riswan-ir-collect --config ../aws-targets.json status
```

The first run collects a trailing window. Later runs continue from a SQLite checkpoint with configured overlap. The runner saves a pending window before collection so an interruption can resume the same range, including on the first run. Earlier pages can have committed before a later failure. Retry skips already committed source receipts. A checkpoint moves forward only after every batch in the reserved window persists successfully. A repeated event at another S3 location retains the additional provenance. Conflicting payloads for an existing event ID within one scope fail the run.

For a historical range, use `run --start <ISO-8601-with-timezone> --end <ISO-8601-with-timezone>`. Keep the duration within `window_minutes`. Backfills leave incremental progress unchanged. Use a larger overlap or a separate backfill for delayed deliveries. No completeness guarantee is made beyond the covered service, prefixes and windows.

CloudTrail lookups are paced per account and region within the collector process. A run applies request and event budgets and bounded retries with exponential backoff. AWS profile refresh traffic is managed by the SDK. Keep one watch process per overlapping AWS scope. Windows are bounded by time and request budgets; reduce window size or increase the explicitly authorized budget when a scope repeatedly exceeds it. The S3 connector caps compressed and decompressed object size.

The runner emits structured summaries and stores latest health and checkpoint data. It omits credentials, raw payloads, request URLs and AWS exception messages. Each persisted batch creates a report for the configured starting ARN and retains all raw events in that batch. Correlation remains within a report.

## Dedicated sandbox verification

Use a dedicated account and an existing CloudTrail trail and S3 prefix with the read-only roles above. Run a short window for each connector, verify reports and local forensic provenance, and confirm a second collection of the same explicit range adds no new receipts. Review the role against the allowed operation list and use IAM policy simulation or an administrator's policy review for explicit write denials. Routine tests use botocore Stubber and Moto where available and do not require cloud credentials.
