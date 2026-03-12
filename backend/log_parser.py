def parse_logs(raw_logs: str):
    lines = raw_logs.split("\n")
    events = []

    for line in lines:
        events.append({"event": line.strip()})

    return events