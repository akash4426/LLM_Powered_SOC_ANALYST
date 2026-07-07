from backend.processing.event_extractor import SecurityEvent
from backend.processing.threat_intel import enrich_events
from backend.processing.pattern_detector import detect_patterns

events = [SecurityEvent(
    event_type="LOGIN",
    event_code=1,
    source_ip="192.168.1.50",
    dest_ip="10.0.0.5",
    user="admin",
    hostname="server1",
    timestamp="2026-07-07T12:00:00Z",
    description="test",
    raw="test",
    mitre_hint=None,
    severity="low"
)]

print("Testing threat intel...")
try:
    ti = enrich_events(events)
    print("Threat intel success:", ti)
except Exception as e:
    import traceback
    traceback.print_exc()

print("Testing pattern detector...")
try:
    p = detect_patterns(events)
    print("Pattern success:", p)
except Exception as e:
    import traceback
    traceback.print_exc()
