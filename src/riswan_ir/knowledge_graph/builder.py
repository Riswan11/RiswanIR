"""Build a deterministic, evidence-backed graph from a stored investigation."""

from collections import defaultdict
from collections.abc import Iterable

from ..core.fields import utc_timestamp
from ..correlation.aws import arn_account, partition
from ..models import InvestigationReport
from ..models.canonical_event import SecurityEvent, Status
from ..models.correlation import CorrelationConfidence
from ..normalization.aws.ocsf_mapper import map_event
from .models import GraphNode, Observation, SecurityGraph, SecurityRelationship
from .ontology import VERSION, Entity, Relation
from .resolver import identifier

CORRELATED = {
    "ASSUMED_ROLE": (Relation.ASSUMED_ROLE, Entity.IDENTITY, Entity.IDENTITY),
    "ESTABLISHED_SESSION": (Relation.ESTABLISHED_SESSION, Entity.IDENTITY, Entity.SESSION),
    "AUTHENTICATED_AS": (Relation.AUTHENTICATED_AS, Entity.SESSION, Entity.IDENTITY),
    "CHAINED_TO": (Relation.CHAINED_TO, Entity.SESSION, Entity.SESSION),
    "PERFORMED_ACTION": (Relation.PERFORMED_ACTION, Entity.SESSION, Entity.EVENT),
}
IAM = {"iam.amazonaws.com", "iam.amazonaws.com.cn"}
S3 = {"s3.amazonaws.com", "s3.amazonaws.com.cn"}
STS = {"sts.amazonaws.com", "sts.amazonaws.com.cn"}
READ_S3 = {
    "GetObject",
    "GetObjectAttributes",
    "HeadObject",
    "ListBucket",
    "ListObjects",
    "ListObjectsV2",
    "SelectObjectContent",
}
WRITE_OPERATIONS = {
    "s3": frozenset(
        "PutObject DeleteObject PutBucketPolicy DeleteBucketPolicy PutBucketEncryption DeleteBucketEncryption".split()
    ),
    "ec2": frozenset(
        "AuthorizeSecurityGroupIngress RevokeSecurityGroupIngress AuthorizeSecurityGroupEgress RevokeSecurityGroupEgress ModifySecurityGroupRules ModifySnapshotAttribute".split()
    ),
    "cloudtrail": frozenset(
        "StopLogging StartLogging UpdateTrail DeleteTrail PutEventSelectors".split()
    ),
}


class GraphBuilder:
    def __init__(self, report: InvestigationReport):
        self.report = report
        canonical = report.canonical_events
        if canonical is None:
            canonical = [
                map_event(item, evidence=item.reference, parent=item.linked_from_evidence_id)
                for item in report.evidence
            ]
        self.events = {event.id: event for event in canonical}
        self.normalized = {item.id: item for item in report.evidence}
        self.provider = "aws"  # This builder consumes CloudTrail; the ontology is provider-neutral.
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, Relation, str], dict[tuple[str, str | None], Observation]] = {}
        self.entities: dict[tuple[Entity, str], GraphNode] = {}
        self.sessions_by_event: dict[str, GraphNode] = {}
        self.evidence: dict[str, GraphNode] = {}
        self.subjects: dict[tuple[str | None, str | None, str, str], list[GraphNode]] = defaultdict(
            list
        )
        self.observation_count = 0

    def node(
        self,
        kind: Entity,
        key: str,
        label: str,
        *,
        partition_id: str | None = None,
        account: str | None = None,
        local: bool = False,
        subtype: str | None = None,
    ) -> GraphNode:
        provider = (
            None
            if kind in {Entity.FINDING, Entity.THREAT, Entity.INVESTIGATION, Entity.ACTION}
            else self.provider
        )
        node_id = identifier(
            kind, provider, partition_id, account, self.report.id if local else None, key
        )
        if node_id not in self.nodes:
            if len(self.nodes) >= 30_000:
                raise ValueError("Security graph entity limit exceeded.")
            self.nodes[node_id] = GraphNode(
                id=node_id,
                kind=kind,
                key=key,
                label=label,
                provider=provider,
                partition=partition_id,
                account=account,
                metadata={"type": subtype} if subtype else {},
            )
        return self.nodes[node_id]

    def link(
        self,
        source: GraphNode,
        relation: Relation,
        target: GraphNode,
        event_ids: Iterable[str],
        confidence: CorrelationConfidence | None = None,
    ) -> None:
        key = (source.id, relation, target.id)
        observations = self.edges.setdefault(key, {})
        for event_id in event_ids:
            event = self.events[event_id]
            if (event_id, confidence) not in observations:
                self.observation_count += 1
                if self.observation_count > 60_000:
                    raise ValueError("Security graph observation limit exceeded.")
            observations[(event_id, confidence)] = Observation(
                event_id=event_id,
                evidence_id=event.evidence.evidence_id if event.evidence else None,
                observed_at=event.observed_at,
                source=event.metadata.source,
                confidence=confidence,
            )

    def belongs(self, node: GraphNode, event_ids: Iterable[str]) -> None:
        if node.account and node.partition:
            account = self.node(
                Entity.ACCOUNT,
                node.account,
                node.account,
                partition_id=node.partition,
                account=node.account,
            )
            self.link(node, Relation.BELONGS_TO, account, event_ids)

    def build(self) -> SecurityGraph:
        case = self.node(Entity.INVESTIGATION, self.report.id, self.report.title, local=True)
        for event_id in sorted(self.events):
            event = self.events[event_id]
            self.event_nodes(event, case)
        if self.report.correlation:
            self.correlate()
        for event_id in sorted(self.events):
            self.activity(self.events[event_id])
        for claim in self.report.assessment.claims:
            evidence = sorted(set(claim.evidence_ids))
            key = identifier("triage", claim.rule_id, claim.summary, *evidence)
            self.finding(
                key,
                claim.summary,
                evidence,
                [claim.possible_attack_technique] if claim.possible_attack_technique else [],
                case,
            )
        if self.report.detection:
            for finding in self.report.detection.findings:
                self.finding(
                    finding.idempotency_key,
                    finding.summary,
                    finding.evidence_ids,
                    finding.mitre.techniques if finding.mitre else [],
                    case,
                )
        action = self.report.action
        if action:
            node = self.node(Entity.ACTION, action.id, action.summary, local=True)
            decision = self.report.decision
            node.metadata["status"] = decision.decision.value if decision else "proposed"
            if decision:
                node.metadata["decision_at"] = decision.created_at
            self.link(node, Relation.PART_OF, case, action.evidence_ids)
            for event_id in action.evidence_ids:
                self.link(node, Relation.SUPPORTED_BY, self.evidence[event_id], [event_id])

        return SecurityGraph(
            investigation_id=self.report.id,
            ontology_version=VERSION,
            nodes=sorted(self.nodes.values(), key=lambda node: node.id),
            relationships=[
                SecurityRelationship(
                    id=identifier(source, relation, target),
                    source=source,
                    target=target,
                    relation=relation,
                    observations=sorted(
                        observations.values(),
                        key=lambda obs: (
                            utc_timestamp(obs.observed_at),
                            obs.event_id,
                            obs.confidence or "",
                        ),
                    ),
                )
                for (source, relation, target), observations in sorted(self.edges.items())
            ],
        )

    def event_nodes(self, event: SecurityEvent, case: GraphNode) -> None:
        account = event.cloud.account_uid if event.cloud else None
        region = event.cloud.region if event.cloud else None
        scope = partition(event.principal_arn, region) if not region else partition(None, region)
        node = self.node(
            Entity.EVENT,
            event.id,
            event.activity.operation,
            local=True,
            partition_id=scope,
            account=account,
        )
        node.metadata.update({"observed_at": event.observed_at, "source": event.metadata.source})
        if region:
            node.metadata["region"] = region
        self.entities[(Entity.EVENT, event.id)] = node
        self.belongs(node, [event.id])
        self.link(node, Relation.PART_OF, case, [event.id])
        origin = event.evidence
        evidence_id = origin.evidence_id if origin else event.id
        evidence = self.node(
            Entity.EVIDENCE, evidence_id, "Normalized evidence", local=True, subtype="normalized"
        )
        evidence.metadata.update({"representation": "normalized", "event_id": event.id})
        self.evidence[event.id] = evidence
        self.link(node, Relation.SUPPORTED_BY, evidence, [event.id])
        if origin:
            evidence.metadata["raw_evidence_id"] = origin.parent_evidence_id
            raw = self.node(
                Entity.EVIDENCE,
                origin.parent_evidence_id,
                "Raw evidence",
                local=True,
                subtype="raw",
            )
            raw.metadata["representation"] = "raw"
            self.link(evidence, Relation.DERIVED_FROM, raw, [event.id])
        actor = event.actor.user if event.actor else None
        actor_account = actor.account_uid if actor else None
        if (
            actor_account
            and actor_account != account
            and arn_account(event.principal_arn) in (None, actor_account)
        ):
            self.node(
                Entity.ACCOUNT,
                actor_account,
                actor_account,
                partition_id=partition(event.principal_arn, region),
                account=actor_account,
            )

    def correlate(self) -> None:
        result = self.report.correlation
        assert result is not None
        for item in result.identities:
            label = next((alias.value for alias in item.aliases if alias.kind == "arn"), item.id)
            node = self.node(
                Entity.IDENTITY,
                item.id,
                label,
                account=item.account_id,
                partition_id=item.partition,
                local=not item.account_id,
                subtype=item.kind,
            )
            self.entities[(Entity.IDENTITY, item.id)] = node
            for kind in ("user", "role"):
                if f":{kind}/" in label:
                    self.subjects[
                        (item.partition, item.account_id, kind, label.rsplit("/", 1)[-1])
                    ].append(node)
        for session in result.sessions:
            owner = self.entities[(Entity.IDENTITY, session.identity_id)]
            node = self.node(
                Entity.SESSION,
                session.id,
                session.id,
                account=owner.account,
                partition_id=owner.partition,
                local=not owner.account,
            )
            self.entities[(Entity.SESSION, session.id)] = node
        for edge in result.relationships:
            if edge.relationship == "BELONGS_TO_ACCOUNT":
                self.belongs(self.entities[(Entity.IDENTITY, edge.source)], edge.evidence_ids)
            if edge.relationship not in CORRELATED:
                continue
            relation, left, right = CORRELATED[edge.relationship]
            source, target = self.entities[(left, edge.source)], self.entities[(right, edge.target)]
            self.link(source, relation, target, edge.evidence_ids, edge.confidence)
            if relation in {Relation.AUTHENTICATED_AS, Relation.ESTABLISHED_SESSION}:
                self.belongs(source if left == Entity.SESSION else target, edge.evidence_ids)
            if relation == Relation.PERFORMED_ACTION:
                self.sessions_by_event[edge.target] = source

    def activity(self, event: SecurityEvent) -> None:
        event_node = self.entities[(Entity.EVENT, event.id)]
        session = self.sessions_by_event.get(event.id)
        actor = event.actor.user if event.actor else None
        principal = session
        if principal is None and actor and (actor.arn or actor.uid):
            key = actor.arn or actor.uid
            assert key is not None
            account = arn_account(actor.arn) or actor.account_uid
            # A contradictory account claim cannot produce a stable shared identity.
            if actor.account_uid and arn_account(actor.arn) not in (None, actor.account_uid):
                account = None
            principal = self.node(
                Entity.IDENTITY,
                key if account else identifier(event.id, key),
                key,
                account=account,
                partition_id=event_node.partition,
                local=account is None,
            )
            self.belongs(principal, [event.id])
            self.link(principal, Relation.PERFORMED_ACTION, event_node, [event.id])
        if event.network and event.network.source_ip:
            address = str(event.network.source_ip)
            # IPs can overlap across networks and accounts.
            key = identifier(
                event_node.account or event.id, event.cloud.region if event.cloud else None, address
            )
            network = self.node(
                Entity.NETWORK,
                key,
                address,
                account=event_node.account,
                partition_id=event_node.partition,
                local=event_node.account is None,
                subtype="ip",
            )
            self.link(event_node, Relation.ORIGINATED_FROM, network, [event.id])
            if session:
                self.link(session, Relation.ORIGINATED_FROM, network, [event.id])
        endpoint = self.normalized[event.id].vpc_endpoint_id
        if endpoint:
            node = self.node(
                Entity.NETWORK,
                identifier(event.cloud.region if event.cloud else None, endpoint),
                endpoint,
                account=event_node.account,
                partition_id=event_node.partition,
                local=event_node.account is None,
                subtype="vpc-endpoint",
            )
            self.link(event_node, Relation.VIA_NETWORK, node, [event.id])
        if event.activity.service in IAM:
            self.permission(event, event_node)
        self.resource_edges(event, event_node, principal)

    def resource_edges(
        self,
        event: SecurityEvent,
        event_node: GraphNode,
        principal: GraphNode | None,
    ) -> None:
        observed = self.normalized[event.id]
        params = observed.request_parameters.attributes if observed.request_parameters else {}
        service, operation = event.activity.service, event.activity.operation
        entries = [(item.uid or item.name, item.account_uid, item.type) for item in event.resources]
        if service not in STS | IAM:
            extension = event.extensions.get("aws.cloudtrail", {}).get("detection_signals")
            signal = extension.get("resource_uid") if isinstance(extension, dict) else None
            target = event.activity.target or (signal if isinstance(signal, str) else None)
            if target is None and service in S3:
                candidate = params.get("bucketName")
                target = candidate if isinstance(candidate, str) else None
            equivalent_targets = {target}
            if target and service in S3:
                bucket_scope = partition(None, observed.region)
                bucket_arn = f"arn:{bucket_scope}:s3:::{target}"
                equivalent_targets.add(bucket_arn)
                if any(name == bucket_arn for name, _, _ in entries):
                    entries = [entry for entry in entries if entry[0] != target]
                else:
                    entries = [
                        (name, account, "bucket" if name == target else kind)
                        for name, account, kind in entries
                    ]
            if target and all(name not in equivalent_targets for name, _, _ in entries):
                entries.append((target, None, "bucket" if service in S3 else None))
        for name, explicit_account, subtype in sorted(
            set(entries), key=lambda item: tuple(value or "" for value in item)
        ):
            if not name or (service in IAM and ":policy/" in name):
                continue
            arn_owner = arn_account(name)
            if arn_owner and explicit_account and arn_owner != explicit_account:
                continue
            owner = explicit_account or arn_owner
            scope_account = owner or observed.recipient_account_id
            scope = partition(name if name.startswith("arn:") else None, observed.region)
            region = observed.region if not name.startswith("arn:") and service not in S3 else None
            arn_prefix = f"arn:{scope}:s3:::"
            bucket = None
            if service in S3:
                if name.startswith(arn_prefix) and "/" not in name:
                    bucket = name.removeprefix(arn_prefix)
                elif subtype == "bucket" and not name.startswith("arn:"):
                    bucket = name
            if bucket:
                key = identifier(service, scope_account or event.id, bucket)
                label = bucket
            else:
                key = (
                    name
                    if name.startswith("arn:")
                    else identifier(service, region, scope_account or event.id, name)
                )
                label = name
            node = self.node(
                Entity.RESOURCE,
                key,
                label,
                account=scope_account,
                partition_id=scope,
                local=scope_account is None and (bucket is not None or not name.startswith("arn:")),
                subtype="bucket" if bucket else subtype,
            )
            if owner:
                self.belongs(node, [event.id])
            self.link(event_node, Relation.TARGETED, node, [event.id])
            if event.outcome.status_id == Status.SUCCESS:
                if principal and (
                    event.activity.read_only is True or service in S3 and operation in READ_S3
                ):
                    self.link(principal, Relation.ACCESSED_RESOURCE, node, [event.id])
                service_name, _, domain = (service or "").partition(".")
                if domain in {
                    "amazonaws.com",
                    "amazonaws.com.cn",
                } and operation in WRITE_OPERATIONS.get(service_name, frozenset()):
                    self.link(event_node, Relation.MODIFIED, node, [event.id])

    def permission(self, event: SecurityEvent, event_node: GraphNode) -> None:
        subjects = {
            "AttachUserPolicy": ("userName", "user"),
            "AttachRolePolicy": ("roleName", "role"),
        }
        info = subjects.get(event.activity.operation)
        normalized = self.normalized[event.id]
        if (
            not info
            or event.outcome.status_id != Status.SUCCESS
            or not normalized.request_parameters
        ):
            return
        params = normalized.request_parameters.attributes
        field, kind = info
        name, policy = params.get(field), params.get("policyArn")
        account = normalized.recipient_account_id or event_node.account
        if not account or not isinstance(name, str) or not isinstance(policy, str):
            return
        owner = arn_account(policy)
        parts = policy.split(":", 5)
        if (
            len(parts) != 6
            or parts[:3] != ["arn", event_node.partition, "iam"]
            or not parts[5].startswith("policy/")
            or (parts[4] != "aws" and owner != account)
        ):
            return
        # Infer no entitlement for the caller. Only the explicitly named attachment subject.
        candidates = self.subjects.get((event_node.partition, account, kind, name), [])
        if len(candidates) > 1:
            return
        identity = (
            candidates[0]
            if len(candidates) == 1
            else self.node(
                Entity.IDENTITY,
                identifier(kind, name),
                name,
                account=account,
                partition_id=event_node.partition,
                subtype=kind,
            )
        )
        permission = self.node(
            Entity.PERMISSION,
            policy,
            policy,
            account=owner,
            partition_id=event_node.partition,
            subtype="iam-policy",
        )
        self.belongs(identity, [event.id])
        self.belongs(permission, [event.id])
        self.link(identity, Relation.HAS_PERMISSION, permission, [event.id])

    def finding(
        self, key: str, title: str, ids: list[str], techniques: list[str], case: GraphNode
    ) -> None:
        finding = self.node(Entity.FINDING, key, title, local=True)
        self.link(finding, Relation.PART_OF, case, ids)
        for event_id in ids:
            self.link(finding, Relation.SUPPORTED_BY, self.evidence[event_id], [event_id])
        for technique in techniques:
            node = self.node(Entity.THREAT, technique, technique)
            self.link(finding, Relation.INDICATES_TECHNIQUE, node, ids)


def build_security_graph(report: InvestigationReport) -> SecurityGraph:
    return GraphBuilder(report).build()
