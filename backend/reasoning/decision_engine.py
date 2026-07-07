"""
decision_engine.py — Deterministic Decision Engine
===================================================

Computes Confidence, Risk, Severity, and Action using strictly deterministic
formulas based on the evidence in the InvestigationObject.
The LLM is NEVER used for these calculations.
"""

from backend.schemas.investigation import InvestigationObject


class DecisionEngine:
    
    @staticmethod
    def evaluate(inv_obj: InvestigationObject) -> None:
        """
        Evaluate the InvestigationObject and assign confidence, severity, risk,
        and decision directly to it.
        """
        
        # 1. Extract signals from tool outputs
        lstm_score = 0.0
        ti_score = 0.0
        ioc_count = 0
        rag_matches = 0
        pattern_score = 0.0
        correlation_sessions = 0
        
        for r in inv_obj.tool_outputs:
            if not isinstance(r.evidence, dict):
                continue
            
            if r.tool_name == "Behavior Analyst":
                lstm_score = r.evidence.get("anomaly_score", 0.0)
            elif r.tool_name == "Threat Context":
                ti_score = r.evidence.get("max_risk_score", 0.0) / 100.0
            elif r.tool_name == "IOC Analyst":
                ioc_count = r.evidence.get("suspicious_count", 0)
            elif r.tool_name == "MITRE Knowledge":
                rag_matches = len(r.evidence.get("techniques_found", []))
            elif r.tool_name == "Pattern Analyst":
                pattern_score = r.evidence.get("pattern_score", 0.0)
            elif r.tool_name == "Cross Session Memory":
                correlation_sessions = r.evidence.get("suspicious_sessions", 0)

        # 2. Compute Confidence (0.0 - 1.0)
        c = (
            0.35 * min(lstm_score, 1.0) +
            0.20 * min(rag_matches / 5.0, 1.0) +
            0.15 * min(correlation_sessions / 4.0, 1.0) +
            0.10 * min(ti_score, 1.0) +
            0.10 * min(pattern_score, 1.0) +
            0.10 * min(ioc_count / 10.0, 1.0)
        )
        
        # V12 FIX: Apply evidence completeness and contradiction penalties
        contradictions_count = sum(1 for e in inv_obj.evidence_timeline if e.get("type") == "Contradiction")
        penalty = 0.0
        
        if inv_obj.evidence_completeness < 0.5:
            penalty += 0.2
        if contradictions_count > 0:
            penalty += (0.15 * contradictions_count)
            
        c = max(0.0, c - penalty)
        inv_obj.confidence = round(min(c, 1.0), 4)

        inv_obj.confidence_breakdown = {
            "Behavior": round(0.35 * min(lstm_score, 1.0), 4),
            "MITRE_Knowledge": round(0.20 * min(rag_matches / 5.0, 1.0), 4),
            "Cross_Session_Memory": round(0.15 * min(correlation_sessions / 4.0, 1.0), 4),
            "Threat_Context": round(0.10 * min(ti_score, 1.0), 4),
            "Pattern_Analyst": round(0.10 * min(pattern_score, 1.0), 4),
            "IOC_Analyst": round(0.10 * min(ioc_count / 10.0, 1.0), 4),
            "Penalties": round(penalty, 4)
        }

        # 3. Compute Risk Score (0 - 100)
        risk = (
            (lstm_score * 35) +
            (inv_obj.confidence * 25) +
            (ti_score * 20) +
            (pattern_score * 10) +
            (min(correlation_sessions / 4.0, 1.0) * 10)
        )
        inv_obj.risk = round(min(risk, 100.0), 2)
        
        inv_obj.risk_breakdown = {
            "Anomaly_Signal": round(lstm_score * 35, 2),
            "Overall_Confidence": round(inv_obj.confidence * 25, 2),
            "Threat_Intel": round(ti_score * 20, 2),
            "Pattern_Match": round(pattern_score * 10, 2),
            "Memory_Correlation": round(min(correlation_sessions / 4.0, 1.0) * 10, 2)
        }

        # 4. Determine Severity and Factors
        factors = []
        if lstm_score > 0.7: factors.append(f"High behavioral anomaly ({lstm_score})")
        if ti_score > 0.5: factors.append(f"Known malicious indicators found")
        if pattern_score > 0.7: factors.append(f"Matches known attack pattern")
        if contradictions_count > 0: factors.append(f"Confidence reduced due to {contradictions_count} contradiction(s)")
        if inv_obj.evidence_completeness < 0.5: factors.append(f"Low evidence completeness ({inv_obj.evidence_completeness * 100}%)")
        
        if not factors: factors.append("No significant risk factors")
        inv_obj.severity_factors = factors

        if inv_obj.risk >= 85:
            inv_obj.severity = "CRITICAL"
        elif inv_obj.risk >= 65:
            inv_obj.severity = "HIGH"
        elif inv_obj.risk >= 40:
            inv_obj.severity = "MEDIUM"
        else:
            inv_obj.severity = "LOW"

        # 5. Determine Action
        if inv_obj.severity == "CRITICAL":
            inv_obj.decision = "ISOLATE_HOST_AND_PULL_MEMORY"
        elif inv_obj.severity == "HIGH":
            inv_obj.decision = "BLOCK_IPS_AND_ALERT_ONCALL"
        elif inv_obj.severity == "MEDIUM":
            inv_obj.decision = "CREATE_JIRA_TICKET"
        else:
            inv_obj.decision = "MONITOR"
