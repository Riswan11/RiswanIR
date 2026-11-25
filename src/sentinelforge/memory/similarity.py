"""Rank prior reviewed investigations by shared event types."""

import json


def similar_investigations(report, history):
    events = {item["event"] for item in report["evidence"]}
    similar = []
    for item in history:
        prior = json.loads(item["report"])
        shared = sorted(events.intersection(event["event"] for event in prior["evidence"]))
        if shared:
            similar.append({"id": prior["id"], "title": prior["title"],
                            "disposition": item["disposition"], "shared_events": shared})
    return sorted(
        similar, key=lambda item: len(item["shared_events"]), reverse=True)[:5]
