"""Transactional persistence port for the existing local collection adapter."""

from contextlib import AbstractContextManager
from sqlite3 import Connection
from typing import Protocol

from ..models import InvestigationRequest


class CollectionRepository(Protocol):
    def connect(self) -> AbstractContextManager[Connection]: ...
    def create_in_transaction(self, db: Connection, request: InvestigationRequest) -> str: ...
