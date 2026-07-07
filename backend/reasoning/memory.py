"""
memory.py
---------
Cross-session entity memory store for the SOC Analyst.
"""

import time
import threading
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class SessionRecord:
    session_id: str
    timestamp: str
    epoch: float
    sequence: List[int]
    event_types: List[str]
    anomaly_score: float
    mitre_mappings: List[str]
    events_summary: List[Dict[str, Any]]
    entity_id: str


class EntityMemoryStore:
    MAX_SESSIONS_PER_ENTITY = 50
    TTL_SECONDS = 86400

    def __init__(self):
        self._store: Dict[str, List[SessionRecord]] = {}
        self._lock = threading.Lock()

    def store_session(self, record: SessionRecord) -> None:
        with self._lock:
            entity = record.entity_id
            if entity not in self._store:
                self._store[entity] = []
            cutoff = time.time() - self.TTL_SECONDS
            self._store[entity] = [
                r for r in self._store[entity] if r.epoch >= cutoff
            ]
            self._store[entity].append(record)
            if len(self._store[entity]) > self.MAX_SESSIONS_PER_ENTITY:
                self._store[entity] = self._store[entity][
                    -self.MAX_SESSIONS_PER_ENTITY :
                ]

    def get_sessions(
        self, entity_id: str, window_seconds: int = 21600
    ) -> List[SessionRecord]:
        with self._lock:
            records = self._store.get(entity_id, [])
            cutoff = time.time() - window_seconds
            return [r for r in records if r.epoch >= cutoff]

    def get_all_entities(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())


_memory = EntityMemoryStore()

def get_memory_store() -> EntityMemoryStore:
    return _memory

def update_memory(record: SessionRecord) -> None:
    _memory.store_session(record)
