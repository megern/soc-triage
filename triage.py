"""Offline, evidence-based triage for a small, explicit event schema."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps must include a UTC offset")
    return result.astimezone(timezone.utc)


def analyze(events: list[dict], window_seconds: int = 300, failure_threshold: int = 5, spray_threshold: int | None = None) -> dict:
    if window_seconds <= 0 or failure_threshold < 2:
        raise ValueError("window must be positive and threshold must be at least 2")
    if spray_threshold is not None and (type(spray_threshold) is not int or spray_threshold < 2):
        raise ValueError("spray threshold must be an integer of at least 2")
    if not isinstance(events, list) or any(not isinstance(event, dict) for event in events):
        raise ValueError("events must be a list of objects")
    seen, ordered = set(), []
    for event in events:
        for field in ("id", "timestamp", "kind", "user", "source_ip"):
            if not isinstance(event.get(field), str) or not event[field].strip():
                raise ValueError(f"event requires nonempty {field}")
        if event["id"] in seen:
            raise ValueError(f"duplicate event id: {event['id']}")
        seen.add(event["id"])
        ordered.append((parse_time(event["timestamp"]), event))
    ordered.sort(key=lambda pair: (pair[0], pair[1]["id"]))
    groups = defaultdict(list)
    for stamp, event in ordered:
        groups[(event["source_ip"], event["user"])].append((stamp, event))
    findings = []
    for (source_ip, user), group in sorted(groups.items()):
        failures = []
        for stamp, event in group:
            failures = [(t, e) for t, e in failures if (stamp - t).total_seconds() <= window_seconds]
            if event["kind"] == "login_failed":
                failures.append((stamp, event))
            if len(failures) >= failure_threshold and event["kind"] in {"login_failed", "login_success"}:
                success = event["kind"] == "login_success"
                evidence = [e["id"] for _, e in failures]
                if success:
                    evidence.append(event["id"])
                finding = {
                    "rule": "failures_then_success" if success else "repeated_login_failures",
                    "severity": "high" if success else "medium",
                    "user": user, "source_ip": source_ip,
                    "evidence_ids": evidence,
                    "first_seen": failures[0][0].isoformat(), "last_seen": stamp.isoformat(),
                    "reason": f"{len(failures)} failed logins within {window_seconds}s" + (" followed by success" if success else ""),
                    "next_step": "Check whether the user recognizes this source and inspect session activity." if success else "Review authentication context before deciding to block the source.",
                }
                # Extend an existing finding instead of emitting one per additional failure.
                if findings and findings[-1]["rule"] == finding["rule"] and findings[-1]["user"] == user and findings[-1]["source_ip"] == source_ip and set(findings[-1]["evidence_ids"]) & set(evidence):
                    findings[-1] = finding
                else:
                    findings.append(finding)
            if event["kind"] == "privilege_granted":
                findings.append({"rule": "privilege_change", "severity": "review", "user": user,
                    "source_ip": source_ip, "evidence_ids": [event["id"]],
                    "first_seen": stamp.isoformat(), "last_seen": stamp.isoformat(),
                    "reason": "A privilege grant was recorded; authorization is unknown.",
                    "next_step": "Compare with an approved change request."})
    if spray_threshold is not None:
        by_source = defaultdict(deque)
        latest = {}
        for stamp, event in ordered:
            if event["kind"] != "login_failed":
                continue
            source = event["source_ip"]
            active = by_source[source]
            while active and (stamp - active[0][0]).total_seconds() > window_seconds:
                active.popleft()
            active.append((stamp, event))
            users = sorted({e["user"] for _, e in active})
            if len(users) < spray_threshold:
                continue
            finding = {"rule": "cross_account_login_failures", "severity": "medium",
                       "source_ip": source, "users": users, "evidence_ids": [e["id"] for _, e in active],
                       "first_seen": active[0][0].isoformat(), "last_seen": stamp.isoformat(),
                       "reason": f"Failed logins for {len(users)} distinct accounts within {window_seconds}s",
                       "next_step": "Check shared NAT/proxy context and whether this resembles password spraying; no automatic blocking."}
            previous = latest.get(source)
            if previous is not None and set(findings[previous]["evidence_ids"]) & set(finding["evidence_ids"]):
                findings[previous] = finding
            else:
                latest[source] = len(findings)
                findings.append(finding)
    return {"schema_version": 1, "backend": "deterministic_rules", "event_count": len(events),
        "findings": findings,
        "timeline": [{**event, "timestamp": stamp.isoformat()} for stamp, event in ordered],
        "limitations": ["Rule matches are leads for investigation, not proof of compromise.",
            "Cross-account correlation is opt-in and requires a shared source; NAT/proxy traffic can cause false positives.",
            "No automated response or external network requests."]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path, default=Path("report.json"))
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--spray-threshold", type=int, help="Opt-in distinct-account threshold at one source")
    args = parser.parse_args()
    if args.events.resolve() == args.output.resolve():
        parser.error("The report output must not overwrite the input events file.")
    try:
        events = [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()]
        report = analyze(events, args.window_seconds, args.failure_threshold, args.spray_threshold)
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f"Input error: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(f"Reviewed {report['event_count']} events; {len(report['findings'])} findings. {args.output}")


if __name__ == "__main__":
    main()
