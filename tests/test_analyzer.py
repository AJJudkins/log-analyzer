import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import analyzer

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_data", "auth.log")


def load():
    with open(SAMPLE) as f:
        return analyzer.parse_lines(f)


def test_parse_failed_line():
    e = analyzer.parse_line("Oct 12 08:05:01 h sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2")
    assert e["event"] == "failed" and e["user"] == "root" and e["ip"] == "203.0.113.50"


def test_ignores_non_login_lines():
    assert analyzer.parse_line("Oct 12 10:15:00 h CRON[2]: session opened") is None


def test_burst_detected_for_attacker_only():
    bursts = analyzer.detect_bursts(load())
    assert [b["ip"] for b in bursts] == ["203.0.113.50"]
    assert bursts[0]["max_failures_in_window"] == 6


def test_slow_failures_not_a_burst():
    ips = [b["ip"] for b in analyzer.detect_bursts(load())]
    assert "198.51.100.7" not in ips


def test_summary_counts():
    s = analyzer.summarize(load())
    assert s["failed_logins"] == 8 and s["accepted_logins"] == 2
