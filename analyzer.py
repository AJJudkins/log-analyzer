"""Simple auth-log analyzer: parses sshd lines and detects failed-login bursts."""
import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LINE_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\s(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)")


def parse_line(line, year=2026):
    """Return a dict for a login event, or None if the line is not one."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
    for kind, rx in (("failed", FAILED_RE), ("accepted", ACCEPTED_RE)):
        e = rx.search(m["msg"])
        if e:
            return {"time": ts, "host": m["host"], "event": kind, "user": e["user"], "ip": e["ip"]}
    return None


def parse_lines(lines, year=2026):
    return [e for e in (parse_line(l, year) for l in lines) if e]


def detect_bursts(events, threshold=5, window_seconds=60):
    """Find IPs with >= threshold failed logins inside a sliding window."""
    by_ip = defaultdict(list)
    for e in events:
        if e["event"] == "failed":
            by_ip[e["ip"]].append(e["time"])
    bursts = []
    window = timedelta(seconds=window_seconds)
    for ip, times in by_ip.items():
        times.sort()
        start = 0
        best = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            best = max(best, end - start + 1)
        if best >= threshold:
            bursts.append({"ip": ip, "max_failures_in_window": best})
    return sorted(bursts, key=lambda b: -b["max_failures_in_window"])


def summarize(events, threshold=5, window_seconds=60):
    failed = [e for e in events if e["event"] == "failed"]
    return {
        "total_events": len(events),
        "failed_logins": len(failed),
        "accepted_logins": len(events) - len(failed),
        "top_failed_ips": Counter(e["ip"] for e in failed).most_common(3),
        "top_failed_users": Counter(e["user"] for e in failed).most_common(3),
        "bursts": detect_bursts(events, threshold, window_seconds),
        "threshold": threshold,
        "window_seconds": window_seconds,
    }


def format_report(s):
    lines = ["=== Auth Log Report ===",
             f"Events parsed:   {s['total_events']}",
             f"Failed logins:   {s['failed_logins']}",
             f"Accepted logins: {s['accepted_logins']}",
             "Top failed IPs:   " + ", ".join(f"{i} ({n})" for i, n in s["top_failed_ips"]),
             "Top failed users: " + ", ".join(f"{u} ({n})" for u, n in s["top_failed_users"]),
             f"Bursts (>= {s['threshold']} failures in {s['window_seconds']}s):"]
    if s["bursts"]:
        lines += [f"  ALERT {b['ip']}: {b['max_failures_in_window']} failures" for b in s["bursts"]]
    else:
        lines.append("  none detected")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Analyze an auth/syslog file for failed-login bursts.")
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=60, help="window in seconds")
    ap.add_argument("--year", type=int, default=2026, help="syslog lines have no year")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    a = ap.parse_args(argv)
    with open(a.logfile, errors="replace") as f:
        events = parse_lines(f, a.year)
    s = summarize(events, a.threshold, a.window)
    print(json.dumps(s, indent=2, default=str) if a.json else format_report(s))


if __name__ == "__main__":
    main()
