# Rule authoring

The bundled [AWS rule registry](../../src/sentinelforge/detection/aws-rules.yml) is a YAML list. Rule IDs and versions form immutable pairs. Bump the version whenever semantics change. Keep previous version rows when operators need to select them for other cases. By default, the registry chooses the highest numeric version per ID. A disabled latest version disables the rule. Changes to reviewed inventory also warrant a context version bump. Each run additionally fingerprints the complete resolved configuration.

A rule specifies `id`, `name`, `version`, `description`, `severity`, `provider`, `conditions`, and `recommendation`. Optional fields include `enabled`, `class_uid`, `outcomes`, `any_conditions`, `threshold`, `suppression`, and `mitre`. All `conditions` must match. When `any_conditions` is nonempty, at least one alternative must also match. Outcomes default to successful events. Only verified ATT&CK mappings should be recorded. The Python model can emit a JSON schema.

```bash
python -c "import json; from sentinelforge.models.detection import DetectionRule; print(json.dumps(DetectionRule.model_json_schema(), indent=2))"
```

Supported selectors are shown in [the model](../../src/sentinelforge/models/detection.py). Operators are `equals`, `not_equals`, `in`, `gte`, `lte`, and `exists`. Unknown values fail every operator, including `not_equals`. Numeric operators compare integers without boolean coercion. Quote strings that YAML would otherwise resolve as dates, booleans, or numbers.

A threshold requires a minimum count with identical configured grouping fields inside an inclusive event-time window. A suppression rule suppresses later findings sharing all configured grouping fields until the suppression window elapses. An unresolved threshold group does not count. An unresolved suppression group does not suppress. Exception selectors use exact equality and apply from the start time through the instant before expiration. Exceptions apply before threshold counting. The first matching exception is recorded.

This example uses synthetic inventory values.

```json
{
  "version": "1.0.0",
  "account_environments": {"111122223333": "production"},
  "privileged_roles": {"arn:aws:iam::111122223333:role/SecurityAdmin": true},
  "resources": {"example-sensitive-bucket": "critical"},
  "expected_networks": {"111122223333": ["192.0.2.0/24"]},
  "known_relationships": {"arn:aws:iam::444455556666:user/Example": []},
  "exceptions": [
    {
      "id": "maintenance-42",
      "rule_id": "SF-AWS-DEF-004",
      "approved_by": "Cloud security",
      "reason": "Scheduled logging review",
      "starts_at": "2026-12-01T10:00:00Z",
      "expires_at": "2026-12-01T11:00:00Z",
      "match": {
        "cloud.account": "111122223333",
        "actor.uid": "arn:aws:iam::111122223333:role/ApprovedMaintenance"
      }
    }
  ]
}
```

Resource inventory keys match the canonical resource identifier or selected request field, such as an S3 bucket name or security group ID. Use `ACCOUNT/RESOURCE` for an account-specific entry that takes precedence over the resource-only key. Keep the YAML and JSON files writable only by trusted local operators. Review and test rule changes in Git, including a legitimate and missing-context case. The engine rejects arbitrary operators, YAML aliases, tags, duplicate keys, and oversized configurations. It does not execute rule expressions or remediation.
