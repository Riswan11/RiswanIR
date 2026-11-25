# Canonical security events

Riswan IR pins OCSF **1.6.0** at upstream revision `d0cd8a0fef198bf93086044e33fda6d80c74b9ef`. The registry validates a scoped subset and versioned provider extensions. [Pinned upstream schema](https://github.com/ocsf/ocsf-schema/tree/d0cd8a0fef198bf93086044e33fda6d80c74b9ef)

The AWS normalizer selects safe observations. The mapper builds the canonical classification, activity, actor, cloud, network, resources and outcome. Detection, correlation and graph generation consume canonical fields. The AWS adapter still interprets provider-specific STS data.

New cases store canonical snapshots with normalized and raw evidence references and a separate custody digest. Retrieve OCSF-shaped JSON at `GET /v1/investigations/{id}/events`. The response identifies archived results and legacy projections.

[CloudTrail mapping](ocsf-mapping.md) · [Versioning](versioning.md) · [Extensions](extension-guidelines.md)
