"""Dispatch validated graph requests without sharing data between case IDs."""

import re
from typing import Protocol
from urllib.parse import parse_qs

from ..core.errors import NotFoundError
from .models import SecurityGraph
from .ontology import REGISTRY
from .query import GraphFilter, GraphQuery, Traversal


class GraphSource(Protocol):
    def security_graph(self, investigation_id: str) -> SecurityGraph: ...


def serve_graph(
    store: GraphSource, case_id: str, suffix: str, query_string: str
) -> dict[str, object]:
    if len(query_string) > 2048:
        raise ValueError("Graph query string is too large.")
    query = parse_qs(query_string, keep_blank_values=True, max_num_fields=16, strict_parsing=True)
    if suffix == "/ontology":
        if query:
            raise ValueError("Ontology does not take query parameters.")
        graph = store.security_graph(case_id)
        return {
            "version": graph.ontology_version,
            "relationships": {
                relation: sorted((source, target) for source, target in pairs)
                for relation, pairs in REGISTRY[graph.ontology_version].items()
            },
        }
    data: dict[str, object] = {}
    for key, values in query.items():
        if key == "relations" and suffix == "/traverse":
            data[key] = values
        elif len(values) == 1:
            data[key] = values[0]
        else:
            raise ValueError("Duplicate graph query parameter.")
    if suffix == "/traverse":
        traversal = Traversal.model_validate(data)
        return GraphQuery(
            store.security_graph(case_id),
            traversal.account,
            traversal.partition,
        ).traverse(traversal)
    match = re.fullmatch(r"/(nodes|relationships)/([a-f0-9]{64})", suffix)
    if not match and suffix not in {"", "/relationships"}:
        raise NotFoundError("Graph route not found.")
    filters = GraphFilter.model_validate(data)
    if match and set(data) - {"account", "partition"}:
        raise ValueError("Graph detail accepts only account and partition filters.")
    scoped = GraphQuery(store.security_graph(case_id), filters.account, filters.partition)
    if match:
        kind, identifier = match.groups()
        if kind == "nodes":
            return scoped.node(identifier).payload()
        return scoped.provenance(identifier)
    return scoped.page(filters, relationships_only=suffix == "/relationships")
