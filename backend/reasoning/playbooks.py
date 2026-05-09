"""
playbooks.py
------------
Automated response playbook engine for SOC incident handling.

Maps incident types and severity levels to structured response playbooks
containing immediate actions, investigation steps, recovery procedures,
and escalation criteria.

Playbooks are severity-adaptive: CRITICAL incidents get aggressive containment
actions while MEDIUM incidents focus on investigation and monitoring.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class PlaybookAction:
    """A single action in a playbook."""
    action: str
    priority: str          # "IMMEDIATE", "SHORT_TERM", "LONG_TERM"
    category: str          # "containment", "investigation", "recovery", "escalation"
    automated: bool = False  # Can this be automated?

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "priority": self.priority,
            "category": self.category,
            "automated": self.automated,
        }


@dataclass
class ResponsePlaybook:
    """A complete response playbook for an incident type."""
    playbook_id: str
    name: str
    description: str
    severity: str
    actions: List[PlaybookAction] = field(default_factory=list)
    escalation_criteria: List[str] = field(default_factory=list)
    sla_minutes: int = 60      # Target response time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "actions": [a.to_dict() for a in self.actions],
            "escalation_criteria": self.escalation_criteria,
            "sla_minutes": self.sla_minutes,
            "total_actions": len(self.actions),
            "immediate_actions": len([a for a in self.actions if a.priority == "IMMEDIATE"]),
        }


# ── Playbook Templates ──────────────────────────────────────────────────────

def _brute_force_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Block source IP at perimeter firewall", "IMMEDIATE", "containment", True),
        PlaybookAction("Lock affected user accounts and force password reset", "IMMEDIATE", "containment", True),
        PlaybookAction("Enable account lockout policy (5 failed attempts)", "IMMEDIATE", "containment", True),
        PlaybookAction("Review authentication logs for successful logins from attacker IP", "SHORT_TERM", "investigation"),
        PlaybookAction("Check for lateral movement from compromised accounts", "SHORT_TERM", "investigation"),
        PlaybookAction("Correlate with threat intelligence feeds for attacker IP", "SHORT_TERM", "investigation"),
        PlaybookAction("Implement MFA for all affected accounts", "LONG_TERM", "recovery"),
        PlaybookAction("Deploy rate-limiting on authentication endpoints", "LONG_TERM", "recovery"),
    ]

    if severity in ("CRITICAL", "HIGH"):
        actions.insert(0, PlaybookAction(
            "Isolate affected systems from network immediately", "IMMEDIATE", "containment", True
        ))
        actions.append(PlaybookAction(
            "Conduct full credential audit across Active Directory", "SHORT_TERM", "investigation"
        ))

    return ResponsePlaybook(
        playbook_id="PB-BRUTE-001",
        name="Brute Force Attack Response",
        description="Response procedure for detected credential brute force attacks",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "Successful login detected from attacker IP",
            "Multiple accounts compromised",
            "Lateral movement observed post-compromise",
        ],
        sla_minutes=15 if severity == "CRITICAL" else 30,
    )


def _lateral_movement_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Isolate source and destination hosts from network", "IMMEDIATE", "containment", True),
        PlaybookAction("Disable compromised user accounts", "IMMEDIATE", "containment", True),
        PlaybookAction("Block lateral movement tools (PsExec, WMI) at EDR level", "IMMEDIATE", "containment", True),
        PlaybookAction("Capture memory dump from affected hosts", "SHORT_TERM", "investigation"),
        PlaybookAction("Review SMB/RDP/WinRM connections between hosts", "SHORT_TERM", "investigation"),
        PlaybookAction("Check for credential dumping artifacts (LSASS, SAM, NTDS.dit)", "SHORT_TERM", "investigation"),
        PlaybookAction("Scan for persistence mechanisms (services, scheduled tasks, registry)", "SHORT_TERM", "investigation"),
        PlaybookAction("Reset all credentials for affected accounts (KRBTGT if DC compromised)", "LONG_TERM", "recovery"),
        PlaybookAction("Rebuild compromised hosts from known-good images", "LONG_TERM", "recovery"),
        PlaybookAction("Implement network segmentation to limit lateral paths", "LONG_TERM", "recovery"),
    ]

    return ResponsePlaybook(
        playbook_id="PB-LATERAL-001",
        name="Lateral Movement Response",
        description="Response procedure for detected lateral movement and credential theft",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "Domain controller access detected",
            "Pass-the-hash/ticket activity confirmed",
            "More than 3 hosts compromised",
        ],
        sla_minutes=10 if severity == "CRITICAL" else 20,
    )


def _exfiltration_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Block outbound traffic to destination IP/domain immediately", "IMMEDIATE", "containment", True),
        PlaybookAction("Isolate source host from network", "IMMEDIATE", "containment", True),
        PlaybookAction("Capture and preserve network traffic (PCAP) for forensics", "IMMEDIATE", "containment"),
        PlaybookAction("Identify data classification of exfiltrated files", "SHORT_TERM", "investigation"),
        PlaybookAction("Review DNS query logs for tunneling indicators", "SHORT_TERM", "investigation"),
        PlaybookAction("Check DLP alerts and correlate with file access logs", "SHORT_TERM", "investigation"),
        PlaybookAction("Determine scope: what data was accessed and transferred", "SHORT_TERM", "investigation"),
        PlaybookAction("Notify data protection officer and legal team", "LONG_TERM", "escalation"),
        PlaybookAction("Implement enhanced DLP rules for sensitive data patterns", "LONG_TERM", "recovery"),
        PlaybookAction("Deploy network-level encryption monitoring", "LONG_TERM", "recovery"),
    ]

    return ResponsePlaybook(
        playbook_id="PB-EXFIL-001",
        name="Data Exfiltration Response",
        description="Response procedure for detected data exfiltration attempts",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "PII or classified data confirmed in exfiltration",
            "Data volume exceeds 1GB",
            "Exfiltration to known C2 infrastructure",
            "Regulatory notification thresholds met",
        ],
        sla_minutes=10 if severity == "CRITICAL" else 15,
    )


def _ransomware_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Isolate ALL affected hosts from network immediately", "IMMEDIATE", "containment", True),
        PlaybookAction("Disable affected user accounts and service accounts", "IMMEDIATE", "containment", True),
        PlaybookAction("Disconnect network shares and mapped drives", "IMMEDIATE", "containment", True),
        PlaybookAction("Preserve Volume Shadow Copies if any remain", "IMMEDIATE", "containment"),
        PlaybookAction("Identify ransomware variant from ransom note and file extensions", "SHORT_TERM", "investigation"),
        PlaybookAction("Determine initial access vector (phishing, RDP, exploit)", "SHORT_TERM", "investigation"),
        PlaybookAction("Map full blast radius — all affected systems and shares", "SHORT_TERM", "investigation"),
        PlaybookAction("Check for backup integrity — verify backups are not compromised", "SHORT_TERM", "investigation"),
        PlaybookAction("Engage incident response retainer and cyber insurance carrier", "SHORT_TERM", "escalation"),
        PlaybookAction("Restore systems from verified clean backups", "LONG_TERM", "recovery"),
        PlaybookAction("Implement application whitelisting on critical servers", "LONG_TERM", "recovery"),
        PlaybookAction("Deploy endpoint detection with ransomware-specific behavioral rules", "LONG_TERM", "recovery"),
    ]

    return ResponsePlaybook(
        playbook_id="PB-RANSOM-001",
        name="Ransomware Incident Response",
        description="Critical response procedure for ransomware deployment detection",
        severity="CRITICAL",
        actions=actions,
        escalation_criteria=[
            "File encryption actively spreading",
            "Backup systems potentially compromised",
            "Critical business systems affected",
            "Ransom demand received",
        ],
        sla_minutes=5,
    )


def _privilege_escalation_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Revoke elevated privileges from affected accounts", "IMMEDIATE", "containment", True),
        PlaybookAction("Kill suspicious elevated processes", "IMMEDIATE", "containment", True),
        PlaybookAction("Review sudo/runas logs for unauthorized elevation", "SHORT_TERM", "investigation"),
        PlaybookAction("Check for new admin accounts or group membership changes", "SHORT_TERM", "investigation"),
        PlaybookAction("Audit SUID/SGID binaries and scheduled task permissions", "SHORT_TERM", "investigation"),
        PlaybookAction("Implement least-privilege access controls", "LONG_TERM", "recovery"),
        PlaybookAction("Deploy Privileged Access Management (PAM) solution", "LONG_TERM", "recovery"),
    ]

    return ResponsePlaybook(
        playbook_id="PB-PRIVESC-001",
        name="Privilege Escalation Response",
        description="Response procedure for unauthorized privilege elevation",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "Root/SYSTEM access obtained by attacker",
            "Domain admin privileges compromised",
            "UAC bypass confirmed",
        ],
        sla_minutes=15 if severity == "CRITICAL" else 30,
    )


def _defense_evasion_playbook(severity: str) -> ResponsePlaybook:
    actions = [
        PlaybookAction("Verify security tool integrity (AV, EDR, SIEM agents)", "IMMEDIATE", "containment"),
        PlaybookAction("Re-enable disabled security controls", "IMMEDIATE", "containment", True),
        PlaybookAction("Restore cleared event logs from backup or SIEM", "IMMEDIATE", "containment"),
        PlaybookAction("Check for tampered binaries and rootkits", "SHORT_TERM", "investigation"),
        PlaybookAction("Audit Group Policy for unauthorized changes", "SHORT_TERM", "investigation"),
        PlaybookAction("Implement tamper protection for security tools", "LONG_TERM", "recovery"),
        PlaybookAction("Deploy centralized log shipping (cannot be cleared locally)", "LONG_TERM", "recovery"),
    ]

    return ResponsePlaybook(
        playbook_id="PB-EVASION-001",
        name="Defense Evasion Response",
        description="Response when attacker attempts to disable or evade security controls",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "Security tooling confirmed disabled",
            "Event logs wiped across multiple hosts",
            "Shadow copies deleted (ransomware preparation)",
        ],
        sla_minutes=10 if severity == "CRITICAL" else 20,
    )


def _generic_playbook(severity: str) -> ResponsePlaybook:
    """Fallback playbook for unclassified incidents."""
    actions = [
        PlaybookAction("Review alert details and validate detection accuracy", "IMMEDIATE", "investigation"),
        PlaybookAction("Collect additional context from surrounding logs", "SHORT_TERM", "investigation"),
        PlaybookAction("Correlate with other alerts for the same entity", "SHORT_TERM", "investigation"),
        PlaybookAction("Document findings and close or escalate as appropriate", "LONG_TERM", "investigation"),
    ]

    if severity in ("HIGH", "CRITICAL"):
        actions.insert(0, PlaybookAction(
            "Isolate affected systems as precaution", "IMMEDIATE", "containment"
        ))

    return ResponsePlaybook(
        playbook_id="PB-GENERIC-001",
        name="Generic Incident Response",
        description="Standard triage procedure for unclassified security incidents",
        severity=severity,
        actions=actions,
        escalation_criteria=[
            "Evidence of active compromise found during investigation",
            "Multiple related alerts for the same entity",
        ],
        sla_minutes=30 if severity in ("HIGH", "CRITICAL") else 60,
    )


# ── Pattern-to-playbook mapping ─────────────────────────────────────────────

_PLAYBOOK_MAP = {
    "BRUTE_FORCE": _brute_force_playbook,
    "brute_force_escalation": _brute_force_playbook,
    "credential_theft": _brute_force_playbook,
    "CREDENTIAL_HARVESTING": _brute_force_playbook,

    "LATERAL_MOVEMENT": _lateral_movement_playbook,
    "apt_lateral_movement": _lateral_movement_playbook,
    "full_kill_chain": _lateral_movement_playbook,

    "EXFILTRATION": _exfiltration_playbook,
    "DATA_STAGING": _exfiltration_playbook,

    "RANSOMWARE": _ransomware_playbook,
    "ransomware_deployment": _ransomware_playbook,
    "DEFENSE_EVASION_CHAIN": _defense_evasion_playbook,

    "SUSPICIOUS_EXECUTION_CHAIN": _privilege_escalation_playbook,
    "PRIVILEGE_ESCALATION_SPIKE": _privilege_escalation_playbook,
    "privilege_escalation_chain": _privilege_escalation_playbook,
    "recon_to_exploit": _privilege_escalation_playbook,
    "C2_COMMUNICATION": _defense_evasion_playbook,
}

# Incident type to playbook mapping
_INCIDENT_TYPE_MAP = {
    "Brute Force Attack Attempt": _brute_force_playbook,
    "Suspicious Execution Chain": _privilege_escalation_playbook,
    "Privilege Escalation Attempt": _privilege_escalation_playbook,
    "Correlated Attack Campaign": _lateral_movement_playbook,
    "Multi-Stage Attack": _lateral_movement_playbook,
}


def get_playbook(
    incident_type: str,
    severity: str,
    campaign_pattern: Optional[str] = None,
    pattern_name: Optional[str] = None,
) -> ResponsePlaybook:
    """
    Select and return the appropriate response playbook.

    Priority:
      1. Campaign pattern match (most specific)
      2. Pattern name match
      3. Incident type match
      4. Generic fallback

    Args:
        incident_type: Classified incident type string
        severity: Incident severity (LOW, MEDIUM, HIGH, CRITICAL)
        campaign_pattern: Campaign pattern from agent hypothesis
        pattern_name: Heuristic pattern from pattern_detector

    Returns:
        ResponsePlaybook with severity-adapted actions
    """
    severity = (severity or "MEDIUM").upper()

    # Try campaign pattern first
    if campaign_pattern and campaign_pattern in _PLAYBOOK_MAP:
        return _PLAYBOOK_MAP[campaign_pattern](severity)

    # Try pattern name
    if pattern_name and pattern_name in _PLAYBOOK_MAP:
        return _PLAYBOOK_MAP[pattern_name](severity)

    # Try incident type
    if incident_type in _INCIDENT_TYPE_MAP:
        return _INCIDENT_TYPE_MAP[incident_type](severity)

    return _generic_playbook(severity)
