"""Hash the canonical JSON representation of an evidence item."""

import hashlib
import json


def integrity_hash(item):
    canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
