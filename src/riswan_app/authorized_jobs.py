"""Guard case-scoped worker operations with the same policy as the API."""

from riswan_ir.models.chain_of_custody import EvidenceIntegrity
from riswan_ir.models.detection import DetectionReplayResult
from riswan_ir.storage.sqlite import Store
from riswan_platform.authorization import Permission, Scope, ScopeType
from riswan_platform.authorization.enforcement import Enforcement


class CaseJobs:
    def __init__(self, store: Store, enforcement: Enforcement):
        self._store = store
        self._enforcement = enforcement

    def _require(self, case_id: str, action: Permission) -> None:
        parent = Scope(ScopeType.INVESTIGATION, case_id)
        for permission in (Permission.READ, Permission.EVIDENCE, action):
            self._enforcement.require(permission, parent.kind, parent.id)
        evidence = (
            *(f"normalized/{key}" for key in self._store.evidence_ids(case_id)),
            *self._store.evidence_ids(case_id, raw=True),
        )
        for evidence_id in evidence:
            self._enforcement.require(
                Permission.EVIDENCE, ScopeType.EVIDENCE, f"{case_id}/{evidence_id}", parent=parent
            )

    def verify_evidence(self, case_id: str) -> EvidenceIntegrity:
        with self._enforcement.operation(mutation=True):
            self._require(case_id, Permission.EVIDENCE)
            return self._store.verify_evidence(case_id)

    def replay_detection(self, case_id: str) -> DetectionReplayResult:
        with self._enforcement.operation():
            self._require(case_id, Permission.DETECTION_READ)
            return self._store.replay_detection(case_id)
