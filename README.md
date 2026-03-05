# Python_For_Cyber_Log

Practical Python project for security log triage.

This repository is a work-in-progress focused on quick detection of suspicious authentication activity from text logs.

## Current Status

- `MVP` available: log parser + suspicious IP scoring + summary report
- Built for learning and iterative hardening

## Features (MVP)

- Parse common auth-style log lines (`timestamp level event user ip status`)
- Count failed logins by IP and user
- Detect suspicious source IPs with configurable threshold
- Export summary as text or JSON

## Project Structure

```text
.
├── analyze_logs.py
├── samples/
│   └── auth.log
├── tests/
│   └── test_analyze_logs.py
└── README.md
```

## Quick Start

```bash
python3 analyze_logs.py --input samples/auth.log
```

JSON output:

```bash
python3 analyze_logs.py --input samples/auth.log --json
```

Custom threshold (default: `3` failed attempts):

```bash
python3 analyze_logs.py --input samples/auth.log --failed-threshold 5
```

## Example Output

```text
Parsed events: 10
Unique source IPs: 4
Failed login attempts: 7
Suspicious IPs (threshold=3):
- 203.0.113.10 (4 failed attempts)
```

## Testing

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Next Improvements

- Add detection for impossible travel and user-agent anomalies
- Add support for JSON logs and web server access logs
- Add severity scoring and alert output (CSV/JSON)
- Package as reusable CLI (`pipx` installable)

## Notes

No real credentials or private logs should be committed. Use synthetic data in `samples/`.
