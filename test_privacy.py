import json
import unittest
from triage import analyze, pseudonymize_report


class PrivacyTests(unittest.TestCase):
    def test_correlation_preserved_and_extra_fields_omitted(self):
        events = [dict(id=f'private-event-{i}', timestamp=f'2026-01-01T00:00:0{i}Z',
                       kind='login_failed', user='private-account', source_ip='192.0.2.123',
                       authorization='secret-token') for i in range(3)]
        report = analyze(events, failure_threshold=2)
        shared = pseudonymize_report(report, b'x' * 32)
        serialized = json.dumps(shared)
        for secret in ('private-event', 'private-account', '192.0.2.123', 'secret-token', 'authorization'):
            self.assertNotIn(secret, serialized)
        self.assertEqual(shared['findings'][0]['evidence_ids'], [e['id'] for e in shared['timeline']])
        self.assertEqual(shared['findings'][0]['user'], shared['timeline'][0]['user'])
        self.assertEqual(shared, pseudonymize_report(report, b'x' * 32))
        self.assertNotEqual(shared['timeline'][0]['id'], pseudonymize_report(report, b'y' * 32)['timeline'][0]['id'])
        self.assertEqual(events[0]['user'], 'private-account')

    def test_short_key_rejected(self):
        with self.assertRaisesRegex(ValueError, '32 bytes'):
            pseudonymize_report(analyze([]), b'short')


if __name__ == '__main__':
    unittest.main()
