"""Log analyzer: failed-login / auth-failure burst detection for real log files.

Formats: syslog-style auth.log (sshd), and optionally nginx/apache access logs
(common or combined format; HTTP 401/403 count as auth failures).
Streams line by line (constant memory per distinct IP/user), reads files, gzip
files or stdin, and can redact IP addresses in the output. Read-only.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

LINE_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
ISO_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\s(?P<host>\S+)\s(?P<proc>[\w\-/\.]+)(?:\[\d+\])?:\s(?P<msg>.*)$")
FAILED_RE = re.compile(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED_RE = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
# nginx/apache common + combined log format
WEB_RE = re.compile(r'^(?P<ip>[0-9a-fA-F:.]+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) \S+')

FORMATS = ("auto", "syslog", "nginx", "apache")


def _syslog_time(ts, year):
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_line(line, year=2026):
    """Parse a syslog/auth.log line into a login event dict, or None."""
    line = line.strip()
    m = LINE_RE.match(line)
    if m:
        try:
            ts = _syslog_time(m["ts"], year)
        except ValueError:
            return None
    else:
        m = ISO_RE.match(line)
        if not m:
            return None
        ts = datetime.fromisoformat(m["ts"].replace(" ", "T"))
    for kind, rx in (("failed", FAILED_RE), ("failed", INVALID_RE), ("accepted", ACCEPTED_RE)):
        e = rx.search(m["msg"])
        if e:
            return {"time": ts, "host": m["host"], "event": kind, "user": e["user"] or "?", "ip": e["ip"]}
    return None


def parse_web_line(line, year=None):
    """Parse an nginx/apache access-log line; 401/403 => failed, 2xx with a user => accepted."""
    m = WEB_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    status = int(m["status"])
    user = m["user"] if m["user"] != "-" else "-"
    if status in (401, 403):
        kind = "failed"
    elif 200 <= status < 300 and user != "-":
        kind = "accepted"
    else:
        return None
    return {"time": ts, "host": "web", "event": kind, "user": user, "ip": m["ip"]}


def parse_lines(lines, year=2026, fmt="syslog"):
    p = parse_line if fmt == "syslog" else parse_web_line
    return [e for e in (p(l, year) for l in lines) if e]


def detect_format(sample_lines):
    """Pick a format from the first lines of input."""
    for l in sample_lines:
        if WEB_RE.match(l.strip()):
            return "nginx"
        if LINE_RE.match(l.strip()) or ISO_RE.match(l.strip()):
            return "syslog"
    return "syslog"


class StreamingAnalyzer:
    """Constant-memory-per-IP analyzer: feed events in log (chronological) order."""

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold, self.window_seconds = threshold, window_seconds
        self._window = timedelta(seconds=window_seconds)
        self.total = self.failed = self.accepted = 0
        self.ips, self.users = Counter(), Counter()
        self._recent = defaultdict(deque)
        self._best = Counter()

    def feed(self, e):
        self.total += 1
        if e["event"] != "failed":
            self.accepted += 1
            return
        self.failed += 1
        self.ips[e["ip"]] += 1
        self.users[e["user"]] += 1
        dq = self._recent[e["ip"]]
        dq.append(e["time"])
        while e["time"] - dq[0] > self._window:
            dq.popleft()
        if len(dq) > self._best[e["ip"]]:
            self._best[e["ip"]] = len(dq)

    def summary(self):
        bursts = [{"ip": ip, "max_failures_in_window": n} for ip, n in self._best.items() if n >= self.threshold]
        bursts.sort(key=lambda b: (-b["max_failures_in_window"], b["ip"]))
        return {"total_events": self.total, "failed_logins": self.failed, "accepted_logins": self.accepted,
                "top_failed_ips": self.ips.most_common(3), "top_failed_users": self.users.most_common(3),
                "bursts": bursts, "threshold": self.threshold, "window_seconds": self.window_seconds}


def detect_bursts(events, threshold=5, window_seconds=60):
    a = StreamingAnalyzer(threshold, window_seconds)
    for e in sorted(events, key=lambda e: e["time"]):
        a.feed(e)
    return a.summary()["bursts"]


def summarize(events, threshold=5, window_seconds=60):
    a = StreamingAnalyzer(threshold, window_seconds)
    for e in sorted(events, key=lambda e: e["time"]):
        a.feed(e)
    return a.summary()


class Redactor:
    """Replaces IPs with a per-run random-salted tag (consistent within a run, not reversible)."""

    def __init__(self, salt=None):
        self.salt = salt or os.urandom(8).hex()

    def ip(self, ip):
        return "ip-" + hashlib.sha256((self.salt + ip).encode()).hexdigest()[:8]

    def summary(self, s):
        s = dict(s)
        s["top_failed_ips"] = [(self.ip(i), n) for i, n in s["top_failed_ips"]]
        s["bursts"] = [dict(b, ip=self.ip(b["ip"])) for b in s["bursts"]]
        return s


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


def open_log(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def analyze_stream(lines, fmt="auto", year=None, threshold=5, window_seconds=60):
    """Stream lines through the analyzer. Returns (summary, format_used, skipped_line_count)."""
    year = year or datetime.now().year
    an = StreamingAnalyzer(threshold, window_seconds)
    skipped = 0
    it = iter(lines)
    if fmt == "auto":
        head = []
        for l in it:
            head.append(l)
            if len(head) >= 20:
                break
        fmt = detect_format(head)
        import itertools
        it = itertools.chain(head, it)
    parse = parse_line if fmt == "syslog" else parse_web_line
    for line in it:
        e = parse(line, year)
        if e:
            an.feed(e)
        else:
            skipped += 1
    return an.summary(), fmt, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Analyze an auth.log (syslog) or nginx/apache access log for auth-failure bursts. "
                    "Read-only; use '-' to read stdin; .gz files supported.",
        epilog="Exit codes: 0 ok, 1 bursts found (with --fail-on-burst), 2 usage/input error.")
    ap.add_argument("logfile", help="path to log file, or - for stdin")
    ap.add_argument("--format", choices=FORMATS, default="auto",
                    help="log format (default: auto-detect from the first lines)")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=60, help="window in seconds")
    ap.add_argument("--year", type=int, default=None, help="syslog lines have no year (default: current year)")
    ap.add_argument("--redact-ips", action="store_true", help="replace IPs in the output with salted hash tags")
    ap.add_argument("--fail-on-burst", action="store_true", help="exit 1 if any burst is detected")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    a = ap.parse_args(argv)
    if a.threshold < 1 or a.window < 1:
        print("error: --threshold and --window must be >= 1", file=sys.stderr)
        return 2
    try:
        with open_log(a.logfile) as f:
            s, fmt, skipped = analyze_stream(f, a.format, a.year, a.threshold, a.window)
    except (OSError, EOFError) as e:
        print(f"error: cannot read log: {e}", file=sys.stderr)
        return 2
    if a.redact_ips:
        s = Redactor().summary(s)
    s["format"] = fmt
    s["unparsed_or_irrelevant_lines"] = skipped
    print(json.dumps(s, indent=2, default=str) if a.json else format_report(s) + f"\n(format: {fmt}; lines not matched: {skipped})")
    return 1 if (a.fail_on_burst and s["bursts"]) else 0


if __name__ == "__main__":
    sys.exit(main())
