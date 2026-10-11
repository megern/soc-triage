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
