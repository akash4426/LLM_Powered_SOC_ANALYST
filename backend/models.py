from pydantic import BaseModel
from typing import List

class LogRequest(BaseModel):
    logs: str


class InvestigationReport(BaseModel):
    attack_stage: str
    mitre_technique: str
    severity: str
    confidence: float
    explanation: str
    recommended_actions: List[str]