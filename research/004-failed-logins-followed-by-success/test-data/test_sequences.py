"""Reference model for Project 004. Validates intended semantics, not SPL/KQL runtime."""
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "synthetic_authentication_scenarios.csv"
EXPECTED = BASE / "expected_results.csv"

def detect(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row["scenario"]].append(row)
    counts = {}
    for scenario, events in groups.items():
        events.sort(key=lambda e: e["timestamp"])
        failures = []
        detections = 0
        for event in events:
            time = datetime.fromisoformat(event["timestamp"])
            if event["result"] == "FAIL":
                failures.append(time)
            elif event["result"] == "SUCCESS":
                if len(failures) >= 3 and 0 < (time - failures[0]).total_seconds() <= 600:
                    detections += 1
                failures = []
        counts[scenario] = detections
    return counts

def main():
    with DATA.open(newline="", encoding="utf-8") as f:
        actual = detect(csv.DictReader(f))
    with EXPECTED.open(newline="", encoding="utf-8") as f:
        expected = {r["scenario"]: int(r["expected_detections"]) for r in csv.DictReader(f)}
    for name, count in expected.items():
        observed = actual.get(name, 0)
        print(f'{"PASS" if observed == count else "FAIL"} {name}: expected={count}, actual={observed}')
    assert actual == expected, f"Mismatch: {actual!r} != {expected!r}"
    print(f"PASS: {len(expected)} reference scenarios")

if __name__ == "__main__":
    main()
