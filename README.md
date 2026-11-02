# Login Log Analyser

An offline Python command-line tool that finds repeated failed logins from an IP address within a configurable time window. Uses only the Python standard library; no accounts, network access or dependencies required.

## Quick start

Requires Python 3.10 or newer. From this project folder:

```bash
python analyser.py examples/logins.csv
python analyser.py examples/logins.csv --threshold 3 --window-minutes 5 --output report.json
python -m unittest discover -v
```

On Windows, use `py` if `python` is unavailable.

The sample produces one alert: five failed attempts from `203.0.113.10` between 10:00 and 10:04 UTC. All sample addresses are reserved for documentation.

## Input

CSV columns: `timestamp,username,ip,status`. Timestamps must be ISO 8601 with a timezone (`Z` or an offset). Status is `success` or `failure`. IPv4 and IPv6 are supported. Input may be unsorted. Invalid rows are skipped and listed by line number in the report; missing required columns fail with exit code 2.

## Detection behaviour

For each IP, a sliding window finds the largest number of failures within the configured duration. Both window endpoints are included. One alert per IP reports its earliest maximum window, count, times, and affected usernames. Successful attempts do not count and do not reset failures. The default is five failures within ten minutes.

## Limits

Alerts are investigation leads, not proof of an attack. Shared IP addresses can cause false positives; distributed attacks and low-rate attempts can evade this rule. This tool reads the documented CSV format, not raw Windows or Linux authentication logs. It loads failed attempts into memory and is intended for small offline datasets. Duplicate input rows count separately. Exit code 0 means analysis completed, even when alerts or invalid rows exist.

Reports contain usernames and IP addresses; keep real logs and reports out of public repositories. The included data is synthetic.

## Development

Tests cover time boundaries, out-of-order events, separate IPs, successful logins, malformed input, configuration validation and IPv6/timezone normalization.

Created with AI assistance as a cybersecurity portfolio project.
