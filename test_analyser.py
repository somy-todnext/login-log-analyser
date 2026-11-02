import io
import unittest
from analyser import analyse


def run_rows(rows, **kwargs):
    return analyse(io.StringIO('timestamp,username,ip,status\n' + '\n'.join(rows)), **kwargs)


class AnalysisTests(unittest.TestCase):
    def test_unsorted_inclusive_window(self):
        result = run_rows(['2026-01-01T00:10:00Z,a,192.0.2.1,failure',
                           '2026-01-01T00:00:00Z,b,192.0.2.1,failure'], threshold=2)
        self.assertEqual(result['alerts'][0]['failed_attempts'], 2)

    def test_spaced_attempts_do_not_alert(self):
        result = run_rows(['2026-01-01T00:00:00Z,a,192.0.2.1,failure',
                           '2026-01-01T00:10:01Z,a,192.0.2.1,failure'], threshold=2)
        self.assertEqual(result['alerts'], [])

    def test_success_and_other_ip_do_not_count(self):
        result = run_rows(['2026-01-01T00:00:00Z,a,192.0.2.1,failure',
                           '2026-01-01T00:01:00Z,a,192.0.2.1,success',
                           '2026-01-01T00:02:00Z,a,192.0.2.2,failure'], threshold=2)
        self.assertEqual(result['alerts'], [])
        self.assertEqual(result['successful_logins'], 1)

    def test_invalid_rows_are_reported(self):
        result = run_rows(['bad,a,192.0.2.1,failure',
                           '2026-01-01T00:00:00,a,192.0.2.1,failure',
                           '2026-01-01T00:00:00Z,a,invalid,failure'])
        self.assertEqual(len(result['invalid_rows']), 3)

    def test_missing_columns(self):
        with self.assertRaises(ValueError):
            analyse(io.StringIO('username\na'))

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            run_rows([], threshold=0)

    def test_offset_and_ipv6(self):
        result = run_rows(['2026-01-01T01:00:00+01:00,a,2001:db8::1,failure',
                           '2026-01-01T00:01:00Z,b,2001:db8::1,failure'], threshold=2)
        self.assertEqual(len(result['alerts']), 1)


if __name__ == '__main__':
    unittest.main()
