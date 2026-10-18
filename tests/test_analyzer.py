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


import gzip
import io
import json as _json

NGINX = ['203.0.113.9 - - [12/Oct/2026:08:00:0%d +0000] "POST /login HTTP/1.1" 401 12 "-" "curl/8"' % i for i in range(6)]
NGINX += ['192.0.2.5 - bob [12/Oct/2026:08:01:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"',
          '192.0.2.5 - - [12/Oct/2026:08:01:01 +0000] "GET / HTTP/1.1" 200 5 "-" "x"']


def test_nginx_parse_and_burst():
    s, fmt, skipped = analyzer.analyze_stream(NGINX, "auto")
    assert fmt == "nginx" and s["failed_logins"] == 6 and s["accepted_logins"] == 1
    assert s["bursts"][0]["ip"] == "203.0.113.9" and skipped == 1


def test_iso_timestamp_and_invalid_user():
    e = analyzer.parse_line("2026-10-12T08:05:01.123456+00:00 h sshd[1]: Invalid user test from 2001:db8::1 port 22")
    assert e["event"] == "failed" and e["ip"] == "2001:db8::1" and e["user"] == "test"


def test_stdin_and_gz(tmp_path, monkeypatch, capsys):
    text = open(SAMPLE).read()
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    assert analyzer.main(["-", "--json", "--year", "2026"]) == 0
    assert _json.loads(capsys.readouterr().out)["failed_logins"] == 8
    gz = tmp_path / "a.log.gz"
    gz.write_bytes(gzip.compress(text.encode()))
    assert analyzer.main([str(gz), "--fail-on-burst"]) == 1


def test_redaction_hides_ips(capsys):
    assert analyzer.main([SAMPLE, "--redact-ips"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.50" not in out and "ip-" in out


def test_streaming_is_bounded_memory():
    an = analyzer.StreamingAnalyzer(5, 60)
    from datetime import datetime, timedelta
    t0 = datetime(2026, 1, 1)
    for i in range(50000):
        an.feed({"time": t0 + timedelta(seconds=i * 20), "event": "failed", "user": "u", "ip": "192.0.2.1"})
    assert len(an._recent["192.0.2.1"]) <= 4 and an.summary()["bursts"] == []


def test_errors(tmp_path, capsys):
    assert analyzer.main([str(tmp_path / "nope.log")]) == 2
    assert analyzer.main([SAMPLE, "--threshold", "0"]) == 2
