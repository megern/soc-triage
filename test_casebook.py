import tempfile
import unittest
from pathlib import Path
from casebook import connect,ingest,snapshot,transition

class CasebookTests(unittest.TestCase):
    def test_collision_rolls_back_whole_batch_and_reingest_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            conn=connect(Path(temp)/'db')
            e={'id':'a','timestamp':'2026-01-01T00:00:00Z','kind':'login_failed','user':'u','source_ip':'s'}
            self.assertEqual(ingest(conn,[e])['new_events'],1)
            self.assertEqual(ingest(conn,[e])['new_events'],0)
            with self.assertRaises(ValueError): ingest(conn,[dict(e,id='b'),dict(e,kind='login_success')])
            self.assertEqual(snapshot(conn)['events_stored'],1);self.assertEqual(len(snapshot(conn)['ingest_history']),2);conn.close()
    def test_closed_case_reopens_with_new_evidence_and_keeps_review_history(self):
        with tempfile.TemporaryDirectory() as temp:
            conn=connect(Path(temp)/'db')
            events=[{'id':str(i),'timestamp':f'2026-01-01T00:00:0{i}Z','kind':'login_failed','user':'u','source_ip':'s'} for i in range(5)]
            ingest(conn,events); case=snapshot(conn)['cases'][0]['id']
            transition(conn,case,'closed','analyst','Reviewed approved maintenance')
            ingest(conn,[dict(events[-1],id='extra',timestamp='2026-01-01T00:00:06Z')])
            report=snapshot(conn);self.assertEqual(report['cases'][0]['status'],'open');self.assertEqual(len(report['review_history']),3)
            self.assertEqual(report['cases'][0]['owner'],'analyst');conn.close()
