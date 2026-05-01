"""
pattern_detector.py
-------------------
Lightweight heuristic rule engine to catch known structured attacks that 
statistical LSTM models might miss (e.g., specific authentication brute force 
or execution chains).
"""

from typing import List, Tuple, Optional
from backend.processing.event_extractor import SecurityEvent

def detect_patterns(events: List[SecurityEvent]) -> Tuple[Optional[str], float]:
    """
    Evaluates a sequence of SecurityEvents within a session for known patterns.
    Returns the (pattern_name, pattern_score) of the highest scoring match.
    """
    
    brute_force_count = 0
    sus_exec_match = False
    priv_esc_count = 0

    sus_exec_keywords = ["mimikatz", "net use", "powershell -enc", "whoami", "curl http"]

    for evt in events:
        raw_lower = evt.raw.lower() if evt.raw else ""
        desc_lower = evt.description.lower() if evt.description else ""
        combined_text = raw_lower + " " + desc_lower

        if evt.event_type == "LOGIN" and ("fail" in combined_text or "invalid" in combined_text):
            brute_force_count += 1
            
        if evt.event_type == "SUSPICIOUS_EXEC":
            if any(k in combined_text for k in sus_exec_keywords):
                sus_exec_match = True
                
        if evt.event_type == "PRIV_ESC":
            if "sudo" in combined_text or "root" in combined_text:
                priv_esc_count += 1

    patterns = []
    
    if brute_force_count >= 3:
        patterns.append(("BRUTE_FORCE", 0.9))
        
    if sus_exec_match:
        patterns.append(("SUSPICIOUS_EXECUTION_CHAIN", 0.8))
        
    if priv_esc_count >= 2:
        patterns.append(("PRIVILEGE_ESCALATION_SPIKE", 0.7))
        
    if not patterns:
        return None, 0.0
        
    # Return highest scoring pattern
    patterns.sort(key=lambda x: x[1], reverse=True)
    return patterns[0]
