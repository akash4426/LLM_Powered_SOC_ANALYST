"""
decision_engine.py — Deterministic Decision Engine
====================================================

The LLM NEVER determines Severity, Risk, Confidence, or Final Action.

Instead this deterministic engine calculates all security-critical
decisions using policy rules and weighted evidence, guaranteeing
reproducibility.

Formulas:
  Confidence = 0.35·LSTM + 0.20·RAG + 0.15·Correlation +
               0.10·ThreatIntel + 0.10·Pattern + 0.10·IOC
  Risk       = anomaly·35 + confidence·25 + TI·20 + pattern·10 + correlation·10
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.reasoning.evidence_aggregator import AccumulatedEvidence


# ═══════════════════════════════════════════════════════════════════════════════
# INVESTIGATION DECISION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InvestigationDecision:
    """The deterministic output of the decision engine."""
    severity: str = "LOW"
    risk_score: float = 0.0
    confidence: float = 0.0
    recommended_action: str = "MONITOR"
    incident_type: str = "Single Session Activity"

    # Breakdown for transparency
    confidence_breakdown: Dict[str, float] = field(default_factory=dict)
    risk_breakdown: Dict[str, float] = field(default_factory=dict)
    severity_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "incident_type": self.incident_type,
            "confidence_breakdown": self.confidence_breakdown,
            "risk_breakdown": self.risk_breakdown,
            "severity_factors": self.severity_factors,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CAMPAIGN PATTERNS (for incident classification)
# ═══════════════════════════════════════════════════════════════════════════════

CAMPAIGN_PATTERNS = {
    "full_kill_chain": ["LOGIN", "PRIV_ESC", "LATERAL_MOVE", "EXFILTRATION"],
    "privilege_escalation_chain": ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
    "apt_lateral_movement": ["RECON", "LATERAL_MOVE", "EXFILTRATION"],
    "ransomware_deployment": ["DEFENSE_EVADE", "SUSPICIOUS_EXEC", "EXFILTRATION"],
    "brute_force_escalation": ["LOGIN", "LOGIN", "PRIV_ESC"],
    "recon_to_exploit": ["RECON", "SUSPICIOUS_EXEC", "PRIV_ESC"],
    "credential_theft": ["LOGIN", "SUSPICIOUS_EXEC", "EXFILTRATION"],
}


# ═══════════════════════════════════════════════════════════════════════════════
# DECISION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class DecisionEngine:
    """
    Deterministic decision engine for security-critical calculations.

    All calculations are rule-based, weighted, and fully reproducible.
    No LLM involvement in severity/risk/confidence/action decisions.
    """

    @staticmethod
    def compute_confidence(evidence: AccumulatedEvidence) -> tuple:
        """
        Compute investigation confidence score.

        Returns (confidence_float, breakdown_dict).
        """
        lstm_component = 0.35 * min(evidence.compound_anomaly_score, 1.0)
        rag_component = 0.20 * min(evidence.rag_matches / 5.0, 1.0)
        corr_component = 0.15 * min(evidence.correlation_depth / 4.0, 1.0)
        ti_component = 0.10 * min(evidence.threat_intel_score, 1.0)
        pattern_component = 0.10 * min(evidence.pattern_score, 1.0)
        ioc_component = 0.10 * min(evidence.ioc_count / 10.0, 1.0)

        total = (
            lstm_component + rag_component + corr_component
            + ti_component + pattern_component + ioc_component
        )
        confidence = round(min(total, 1.0), 4)

        breakdown = {
            "lstm": round(lstm_component, 4),
            "rag": round(rag_component, 4),
            "correlation": round(corr_component, 4),
            "threat_intel": round(ti_component, 4),
            "pattern": round(pattern_component, 4),
            "ioc": round(ioc_component, 4),
        }

        return confidence, breakdown

    @staticmethod
    def compute_severity(evidence: AccumulatedEvidence) -> tuple:
        """
        Compute severity level based on evidence thresholds.

        Returns (severity_str, factors_list).
        """
        anomaly = evidence.compound_anomaly_score
        corr_depth = evidence.correlation_depth
        mitre_count = len(evidence.compound_mitre_mappings)
        ti_score = evidence.threat_intel_score

        factors: List[str] = []

        if anomaly < 0.2:
            if mitre_count >= 1 or ti_score > 0 or corr_depth >= 1:
                severity = "MEDIUM"
                if mitre_count >= 1:
                    factors.append(f"MITRE techniques detected ({mitre_count})")
                if ti_score > 0:
                    factors.append(f"Threat intel positive (score={ti_score:.2f})")
                if corr_depth >= 1:
                    factors.append(f"Cross-session correlation (depth={corr_depth})")
            else:
                severity = "LOW"
                factors.append("No significant indicators")
        elif anomaly < 0.6:
            severity = "MEDIUM"
            factors.append(f"Moderate anomaly score ({anomaly:.2f})")
        else:
            if (
                anomaly >= 0.8
                or corr_depth >= 2
                or mitre_count >= 2
                or ti_score > 0.5
            ):
                severity = "CRITICAL"
                if anomaly >= 0.8:
                    factors.append(f"Critical anomaly ({anomaly:.2f})")
                if corr_depth >= 2:
                    factors.append(f"Deep correlation ({corr_depth} sessions)")
                if mitre_count >= 2:
                    factors.append(f"Multiple MITRE techniques ({mitre_count})")
                if ti_score > 0.5:
                    factors.append(f"High threat intel ({ti_score:.2f})")
            else:
                severity = "HIGH"
                factors.append(f"Elevated anomaly ({anomaly:.2f})")

        return severity, factors

    @staticmethod
    def compute_risk_score(
        anomaly: float,
        confidence: float,
        ti_score: float,
        pattern_score: float,
        corr_depth: int,
    ) -> tuple:
        """
        Compute overall risk score (0-100).

        Returns (risk_float, breakdown_dict).
        """
        anomaly_comp = anomaly * 35
        confidence_comp = confidence * 25
        ti_comp = ti_score * 20
        pattern_comp = pattern_score * 10
        corr_comp = min(corr_depth / 4.0, 1.0) * 10

        raw = anomaly_comp + confidence_comp + ti_comp + pattern_comp + corr_comp
        risk = round(min(raw, 100.0), 1)

        breakdown = {
            "anomaly": round(anomaly_comp, 1),
            "confidence": round(confidence_comp, 1),
            "threat_intel": round(ti_comp, 1),
            "pattern": round(pattern_comp, 1),
            "correlation": round(corr_comp, 1),
        }

        return risk, breakdown

    @staticmethod
    def decide_action(confidence: float, severity: str) -> str:
        """Determine recommended action based on severity and confidence."""
        sev = severity.upper()
        if sev == "CRITICAL" and confidence >= 0.5:
            return "AUTO_REMEDIATE"
        elif sev in ("HIGH", "CRITICAL") or confidence >= 0.6:
            return "ESCALATE_L2"
        return "MONITOR"

    @staticmethod
    def classify_incident(
        pattern_name: Optional[str],
        correlation_depth: int,
    ) -> str:
        """Classify the incident type based on detected patterns."""
        if pattern_name == "BRUTE_FORCE":
            return "Brute Force Attack Attempt"
        elif pattern_name == "SUSPICIOUS_EXECUTION_CHAIN":
            return "Suspicious Execution Chain"
        elif pattern_name == "PRIVILEGE_ESCALATION_SPIKE":
            return "Privilege Escalation Attempt"
        elif pattern_name == "CREDENTIAL_HARVESTING":
            return "Credential Harvesting Campaign"
        elif pattern_name == "DEFENSE_EVASION_CHAIN":
            return "Defense Evasion Campaign"
        elif pattern_name == "DATA_STAGING":
            return "Data Staging & Exfiltration"
        elif pattern_name == "RECON_TO_EXPLOIT":
            return "Reconnaissance to Exploitation"
        elif pattern_name == "C2_COMMUNICATION":
            return "Command & Control Communication"
        elif correlation_depth == 0:
            return "Single Session Activity"
        elif correlation_depth == 1:
            return "Repeated Suspicious Activity"
        elif correlation_depth == 2:
            return "Correlated Attack Campaign"
        else:
            return "Multi-Stage Attack"

    def decide(self, evidence: AccumulatedEvidence) -> InvestigationDecision:
        """
        Run the full deterministic decision pipeline.

        Takes accumulated evidence and produces Severity, Risk, Confidence,
        Action, and Incident Type — all deterministically.
        """
        # Confidence
        confidence, conf_breakdown = self.compute_confidence(evidence)

        # Severity
        severity, sev_factors = self.compute_severity(evidence)

        # Risk score
        risk, risk_breakdown = self.compute_risk_score(
            anomaly=evidence.compound_anomaly_score,
            confidence=confidence,
            ti_score=evidence.threat_intel_score,
            pattern_score=evidence.pattern_score,
            corr_depth=evidence.correlation_depth,
        )

        # Action
        action = self.decide_action(confidence, severity)

        # Incident type
        incident_type = self.classify_incident(
            evidence.pattern_name, evidence.correlation_depth
        )

        return InvestigationDecision(
            severity=severity,
            risk_score=risk,
            confidence=confidence,
            recommended_action=action,
            incident_type=incident_type,
            confidence_breakdown=conf_breakdown,
            risk_breakdown=risk_breakdown,
            severity_factors=sev_factors,
        )
