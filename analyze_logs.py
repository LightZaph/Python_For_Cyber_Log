#!/usr/bin/env python3
"""Simple security log analyzer for authentication events."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<level>\S+)\s+"
    r"(?P<event>\S+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"status=(?P<status>\S+)"
)


@dataclass(frozen=True)
class LogEvent:
    timestamp: str
    level: str
    event: str
    user: str
    ip: str
    status: str


def parse_line(line: str) -> LogEvent | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    return LogEvent(**match.groupdict())


def load_events(path: Path) -> List[LogEvent]:
    events: List[LogEvent] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        event = parse_line(raw_line)
        if event:
            events.append(event)
    return events


def failed_attempts(events: Iterable[LogEvent]) -> List[LogEvent]:
    return [event for event in events if event.status.lower() == "failed"]


def suspicious_ips(events: Iterable[LogEvent], threshold: int) -> Counter[str]:
    failed_by_ip = Counter(event.ip for event in failed_attempts(events))
    return Counter({ip: count for ip, count in failed_by_ip.items() if count >= threshold})


def build_summary(events: List[LogEvent], threshold: int) -> dict:
    failed = failed_attempts(events)
    by_user = Counter(event.user for event in failed)
    by_ip = suspicious_ips(events, threshold)
    return {
        "parsed_events": len(events),
        "unique_ips": len({event.ip for event in events}),
        "failed_attempts": len(failed),
        "failed_by_user": dict(by_user),
        "suspicious_ips": dict(by_ip),
        "threshold": threshold,
    }


def print_text_summary(summary: dict) -> None:
    print(f"Parsed events: {summary['parsed_events']}")
    print(f"Unique source IPs: {summary['unique_ips']}")
    print(f"Failed login attempts: {summary['failed_attempts']}")
    print(f"Suspicious IPs (threshold={summary['threshold']}):")
    suspicious = summary["suspicious_ips"]
    if not suspicious:
        print("- none")
        return
    for ip, count in suspicious.items():
        print(f"- {ip} ({count} failed attempts)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze auth logs and flag suspicious IPs")
    parser.add_argument("--input", required=True, help="Path to log file")
    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=3,
        help="Minimum failed attempts per IP to mark it as suspicious",
    )
    parser.add_argument("--json", action="store_true", help="Output summary as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    log_path = Path(args.input)

    if not log_path.exists() or not log_path.is_file():
        print(f"Input file not found: {log_path}")
        return 1

    if args.failed_threshold < 1:
        print("--failed-threshold must be >= 1")
        return 1

    events = load_events(log_path)
    summary = build_summary(events, args.failed_threshold)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_text_summary(summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
