"""
pattern_detector.py
-------------------
Enhanced heuristic rule engine with 8 attack patterns.

Catches known structured attacks that statistical LSTM models might miss,
such as brute force sequences, execution chains, privilege escalation,
data staging, credential harvesting, defense evasion chains, recon-to-exploit,
and C2 communication patterns.

Each pattern returns:
  (pattern_name, score, matched_indicators, mitre_suggestions)
"""

from typing import List, Tuple, Optional
from backend.processing.event_extractor import SecurityEvent


def detect_patterns(
    events: List[SecurityEvent],
) -> Tuple[Optional[str], float, List[str], List[str]]:
    """
    Evaluates a sequence of SecurityEvents for known attack patterns.

    Returns:
        (pattern_name, pattern_score, matched_indicators, mitre_suggestions)
        of the highest-scoring match. Returns (None, 0.0, [], []) if no match.
    """

    brute_force_count = 0
    sus_exec_match = False
    priv_esc_count = 0
    defense_evade_count = 0
    recon_count = 0
    lateral_count = 0
    exfil_indicators = 0
    c2_indicators = 0
    file_access_count = 0
    compression_detected = False
    credential_indicators = 0
    outbound_count = 0

    sus_exec_keywords = ["mimikatz", "net use", "powershell -enc", "whoami", "curl http",
                         "invoke-expression", "certutil", "bitsadmin", "mshta", "regsvr32"]
    credential_keywords = ["mimikatz", "lsass", "ntds.dit", "sam dump", "credential",
                           "pass-the-hash", "pass-the-ticket", "golden ticket", "dcsync"]
    c2_keywords = ["beacon", "c2", "callback", "reverse shell", "bind shell",
                   "payload", "dropper", "encoded", "base64"]
    defense_keywords = ["shadow copy", "vssadmin", "event log clear", "wevtutil",
                        "disable antivirus", "defender", "bcdedit", "backup.*stop"]

    matched_indicators: List[str] = []

    for evt in events:
        raw_lower = evt.raw.lower() if evt.raw else ""
        desc_lower = evt.description.lower() if evt.description else ""
        combined_text = raw_lower + " " + desc_lower

        # ── Brute Force ──────────────────────────────────────────────────
        if evt.event_type == "LOGIN" and ("fail" in combined_text or "invalid" in combined_text):
            brute_force_count += 1
            matched_indicators.append(f"Failed login: {evt.source_ip or 'unknown'}")

        # ── Suspicious Execution ─────────────────────────────────────────
        if evt.event_type == "SUSPICIOUS_EXEC":
            if any(k in combined_text for k in sus_exec_keywords):
                sus_exec_match = True
                for k in sus_exec_keywords:
                    if k in combined_text:
                        matched_indicators.append(f"Suspicious exec: {k}")
                        break

        # ── Privilege Escalation ─────────────────────────────────────────
        if evt.event_type == "PRIV_ESC":
            if "sudo" in combined_text or "root" in combined_text or "system" in combined_text:
                priv_esc_count += 1
                matched_indicators.append(f"Privilege escalation: {evt.user or 'unknown'}")

        # ── Defense Evasion ──────────────────────────────────────────────
        if evt.event_type == "DEFENSE_EVADE":
            defense_evade_count += 1
            for k in defense_keywords:
                if k in combined_text:
                    matched_indicators.append(f"Defense evasion: {k}")
                    break

        # ── Reconnaissance ───────────────────────────────────────────────
        if evt.event_type == "RECON":
            recon_count += 1

        # ── Lateral Movement ─────────────────────────────────────────────
        if evt.event_type == "LATERAL_MOVE":
            lateral_count += 1
            matched_indicators.append(f"Lateral movement: {evt.description[:60] if evt.description else 'detected'}")

        # ── Exfiltration ─────────────────────────────────────────────────
        if evt.event_type == "EXFILTRATION":
            exfil_indicators += 1
            matched_indicators.append(f"Exfiltration indicator: {evt.description[:60] if evt.description else 'detected'}")

        # ── File Access (data staging) ───────────────────────────────────
        if evt.event_type == "FILE_ACCESS":
            file_access_count += 1
            if any(k in combined_text for k in ["compress", "7zip", "zip", "tar", "archive"]):
                compression_detected = True
                matched_indicators.append("Data compression/staging detected")

        # ── Outbound Connections ─────────────────────────────────────────
        if evt.event_type == "OUTBOUND_CONN":
            outbound_count += 1

        # ── Credential Harvesting (cross-type check) ─────────────────────
        if any(k in combined_text for k in credential_keywords):
            credential_indicators += 1
            if credential_indicators <= 3:  # limit indicator noise
                for k in credential_keywords:
                    if k in combined_text:
                        matched_indicators.append(f"Credential indicator: {k}")
                        break

        # ── C2 Communication (cross-type check) ─────────────────────────
        if any(k in combined_text for k in c2_keywords):
            c2_indicators += 1
            if c2_indicators <= 3:
                for k in c2_keywords:
                    if k in combined_text:
                        matched_indicators.append(f"C2 indicator: {k}")
                        break

    # ── Pattern scoring ──────────────────────────────────────────────────

    patterns: List[Tuple[str, float, List[str], List[str]]] = []

    # 1. Brute Force (3+ failed logins)
    if brute_force_count >= 3:
        score = min(0.6 + (brute_force_count - 3) * 0.1, 0.95)
        patterns.append((
            "BRUTE_FORCE", score,
            [i for i in matched_indicators if "Failed login" in i],
            ["T1110", "T1110.001"],
        ))

    # 2. Suspicious Execution Chain
    if sus_exec_match:
        score = 0.80
        if priv_esc_count > 0:
            score += 0.1
        patterns.append((
            "SUSPICIOUS_EXECUTION_CHAIN", min(score, 0.95),
            [i for i in matched_indicators if "Suspicious exec" in i],
            ["T1059", "T1059.001"],
        ))

    # 3. Privilege Escalation Spike (2+ escalations)
    if priv_esc_count >= 2:
        patterns.append((
            "PRIVILEGE_ESCALATION_SPIKE", 0.75,
            [i for i in matched_indicators if "Privilege escalation" in i],
            ["T1548", "T1068"],
        ))

    # 4. Data Staging (file access + compression + outbound/exfil)
    if file_access_count >= 1 and compression_detected and (outbound_count >= 1 or exfil_indicators >= 1):
        patterns.append((
            "DATA_STAGING", 0.85,
            [i for i in matched_indicators if "compression" in i.lower() or "Exfiltration" in i],
            ["T1074", "T1560", "T1041"],
        ))

    # 5. Credential Harvesting (mimikatz/LSASS + pass-the-hash)
    if credential_indicators >= 2:
        patterns.append((
            "CREDENTIAL_HARVESTING", 0.90,
            [i for i in matched_indicators if "Credential" in i],
            ["T1003", "T1003.001", "T1550"],
        ))

    # 6. Defense Evasion Chain (2+ defense evasion events)
    if defense_evade_count >= 2:
        patterns.append((
            "DEFENSE_EVASION_CHAIN", 0.85,
            [i for i in matched_indicators if "Defense evasion" in i],
            ["T1562", "T1070"],
        ))

    # 7. Recon to Exploit (recon + suspicious exec + priv esc)
    if recon_count >= 1 and sus_exec_match and priv_esc_count >= 1:
        patterns.append((
            "RECON_TO_EXPLOIT", 0.88,
            [i for i in matched_indicators if "Suspicious exec" in i or "Privilege" in i],
            ["T1595", "T1190", "T1059"],
        ))

    # 8. C2 Communication (c2 indicators + outbound connections)
    if c2_indicators >= 1 and outbound_count >= 1:
        patterns.append((
            "C2_COMMUNICATION", 0.82,
            [i for i in matched_indicators if "C2" in i],
            ["T1071", "T1573", "T1095"],
        ))

    if not patterns:
        return None, 0.0, [], []

    # Return highest scoring pattern
    patterns.sort(key=lambda x: x[1], reverse=True)
    return patterns[0]
