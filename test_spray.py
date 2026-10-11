import unittest
from triage import analyze
from test_triage import event
class SprayTests(unittest.TestCase):
 def test_individually_quiet_accounts_correlated_only_when_enabled(self):
  events=[event(i,user=f'account{i}') for i in range(5)]
  self.assertEqual(analyze(events)['findings'],[])
  finding=analyze(events,spray_threshold=5)['findings'][0]
  self.assertEqual(finding['rule'],'cross_account_login_failures');self.assertEqual(finding['evidence_ids'],['0','1','2','3','4'])
 def test_expired_failures_and_distinct_sources_do_not_mix(self):
  events=[event(i,user=f'account{i}') for i in range(4)]+[event(5,minute=8,user='last')]
  self.assertEqual(analyze(events,spray_threshold=5)['findings'],[])
  events[-1]=event(5,user='last');events[-1]['source_ip']='192.0.2.2'
  self.assertEqual(analyze(events,spray_threshold=5)['findings'],[])
 def test_repeated_account_is_not_distinct_accounts(self):
  self.assertFalse(any(f['rule']=='cross_account_login_failures' for f in analyze([event(i) for i in range(5)],spray_threshold=5)['findings']))
 def test_bad_event_and_threshold_fail_explicitly(self):
  for value in (0,1,True):
   with self.assertRaises(ValueError):analyze([],spray_threshold=value)
  with self.assertRaises(ValueError):analyze([42])

class CounterExpiryTests(unittest.TestCase):
    def test_expired_account_removed_but_repeated_active_account_retained(self):
        events=[{'id':str(i),'timestamp':stamp,'kind':'login_failed','user':user,'source_ip':'example'}
                for i,(stamp,user) in enumerate([('2026-01-01T00:00:00Z','a'),('2026-01-01T00:00:01Z','b'),('2026-01-01T00:04:59Z','b'),('2026-01-01T00:05:02Z','c')])]
        report=analyze(events,failure_threshold=20,spray_threshold=2)
        last=report['findings'][-1]
        self.assertEqual(last['users'],['b','c'])
        self.assertEqual(last['evidence_ids'],['2','3'])
    def test_input_order_does_not_change_results(self):
        events=[{'id':str(i),'timestamp':'2026-01-01T00:00:00Z','kind':'login_failed','user':str(i),'source_ip':'example'} for i in range(5)]
        self.assertEqual(analyze(events,spray_threshold=3),analyze(list(reversed(events)),spray_threshold=3))
