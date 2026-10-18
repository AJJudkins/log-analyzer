# Security policy

## Scope and safety
read-only: reads log files, `.gz` files or stdin and prints a report; never writes to or modifies logs. `--redact-ips` masks IPs in the report with per-run salted tags (it does not alter the log, and usernames are not redacted). Analyze only logs you are allowed to review.

## What was and was not tested
**Tested (automated, in CI and locally):** syslog (classic and ISO timestamps), nginx/apache access-log parsing, gzip and stdin input, streaming memory bound, redaction and exit codes, all on small synthetic fixtures built to match documented formats.

**Not tested:** real production `/var/log/auth.log` or web server logs (never run against any real log), very large multi-GB files, logs rotated mid-read, non-English locales, or custom log formats.

## Reporting a problem
This is a small personal portfolio project, not a supported product. If you find a security issue, please open a GitHub issue **without** secrets, credentials or real system details, or use GitHub's "Report a vulnerability" button on the Security tab if it is enabled.
