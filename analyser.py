"""Offline CSV login analysis. Python 3.10+, standard library only."""
import argparse
import csv
import ipaddress
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def analyse(stream, threshold=5, window_minutes=10):
    if threshold < 1 or window_minutes < 1:
        raise ValueError('Threshold and window must be positive integers')
    reader = csv.DictReader(stream)
    required = {'timestamp', 'username', 'ip', 'status'}
    if not required.issubset(reader.fieldnames or []):
        raise ValueError('Required CSV columns: timestamp,username,ip,status')
    failures = defaultdict(list)
    errors = []
    valid = successful = 0
    for line, row in enumerate(reader, 2):
        try:
            stamp = datetime.fromisoformat(row['timestamp'].strip().replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('timestamp must include a timezone')
            stamp = stamp.astimezone(timezone.utc)
            address = str(ipaddress.ip_address(row['ip'].strip()))
            username = row['username'].strip()
            status = row['status'].strip().lower()
            if not username or status not in {'success', 'failure'}:
                raise ValueError('username required; status must be success or failure')
        except (ValueError, AttributeError, TypeError) as exc:
            errors.append({'line': line, 'error': str(exc)})
            continue
        valid += 1
        if status == 'success':
            successful += 1
        else:
            failures[address].append((stamp, username))
    alerts = []
    window = timedelta(minutes=window_minutes)
    for address, events in sorted(failures.items()):
        events.sort()
        left = 0
        best = []
        for right, (stamp, _) in enumerate(events):
            while stamp - events[left][0] > window:
                left += 1
            if right - left + 1 > len(best):
                best = events[left:right + 1]
        if len(best) >= threshold:
            alerts.append({'ip': address, 'failed_attempts': len(best),
                           'start': best[0][0].isoformat(), 'end': best[-1][0].isoformat(),
                           'usernames': sorted({user for _, user in best})})
    return {'valid_rows': valid, 'successful_logins': successful,
            'failed_logins': valid - successful, 'invalid_rows': errors,
            'threshold': threshold, 'window_minutes': window_minutes, 'alerts': alerts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='CSV file to inspect')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-minutes', type=int, default=10)
    parser.add_argument('--output', help='Save JSON report to this path')
    args = parser.parse_args()
    try:
        with open(args.file, encoding='utf-8-sig', newline='') as source:
            report = analyse(source, args.threshold, args.window_minutes)
        result = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as target:
                target.write(result + '\n')
        print(result)
        return 0
    except (OSError, ValueError, csv.Error) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
