import json
import pathlib
import tempfile
import threading
import unittest
from tunnelscope.store import Store

class FastStoreTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=pathlib.Path.cwd());self.s=Store(str(pathlib.Path(self.temp.name)/'db.sqlite'))
  self.s.ingest({'id':'c','clients':[{'id':'a','source':'xray','label':'Alice','ips':[]},{'id':'b','source':'csqtt','label':'Bob','ips':[]}]})
  self.s.set_owner({'ip':'1.2.3.4','holder':'Example Network','asn':'AS123'})
  flows=[{'id':'one','source':'xray','client_id':'a','domain':'site.example','destination':'1.2.3.4','up':10,'down':20},{'id':'two','source':'csqtt','client_id':'b','domain':'other.example','destination':'1.2.3.4','up':5,'down':7},{'id':'three','source':'xray','client_id':'a','domain':'site.example','destination':'8.8.8.8','up':1,'down':2}]
  self.s.ingest({'id':'f','flows':flows})
 def tearDown(self):self.s.db.close();self.temp.cleanup()
 def test_aggregates_filters_owner_and_limit(self):
  for kw,n,up in [({},3,16),({'client':'a'},2,11),({'source':'csqtt'},1,5),({'search':'Example Network'},2,15),({'search':'Alice'},2,11)]:
   d=self.s.snapshot(**kw,limit=1);self.assertEqual(d['totals']['connections'],n);self.assertEqual(d['totals']['observed_up'],up);self.assertEqual(len(d['flows']),1)
   self.assertEqual(sum(x['connections'] for x in d['top']),n)
  d=self.s.snapshot();self.assertEqual(d['top'][0]['holder'],'Example Network');self.assertEqual(d['totals']['domains'],2)
 def test_cache_bounds_age_fresh_rows_force_and_alias_invalidation(self):
  d=self.s.snapshot();stamp=d['summary_updated'];self.assertEqual(d['totals']['connections'],3)
  self.s.ingest({'id':'next','flows':[{'id':'four','source':'xray','client_id':'a','domain':'new.example','destination':'1.2.3.4','up':100}]})
  d=self.s.snapshot();self.assertEqual(d['summary_updated'],stamp);self.assertEqual(len(d['flows']),4)
  self.assertEqual(self.s.snapshot(fresh=True)['totals']['connections'],4)
  self.s.snapshot(search='Renamed');self.assertTrue(self.s.rename('a','Renamed'));self.assertEqual(self.s.snapshot(search='Renamed')['totals']['connections'],3)
  for i in range(12):self.s.snapshot(search=str(i))
  self.assertLessEqual(len(self.s.summaries),8)
 def test_background_summary_returns_rows_before_aggregation(self):
  from unittest.mock import patch
  import time
  entered,release=threading.Event(),threading.Event();original=self.s.aggregate
  def slow(*args):
   entered.set();release.wait(3);return original(*args)
  with patch.object(self.s,'aggregate',side_effect=slow):
   d=self.s.snapshot(background=True);self.assertTrue(d['summary_pending']);self.assertIsNone(d['totals']['connections']);self.assertEqual(len(d['flows']),3)
   self.assertTrue(entered.wait(1));self.s.snapshot(background=True);self.assertEqual(len(self.s.pending),1);release.set()
   until=time.monotonic()+3
   while self.s.pending and time.monotonic()<until:time.sleep(.01)
  d=self.s.snapshot(background=True);self.assertFalse(d['summary_pending']);self.assertEqual(d['totals']['connections'],3)
 def test_wal_reader_does_not_wait_for_ingest_python_lock(self):
  done=threading.Event();errors=[]
  def read():
   try:self.s.snapshot()
   except Exception as e:errors.append(e)
   finally:done.set()
  with self.s.lock:
   t=threading.Thread(target=read);t.start();self.assertTrue(done.wait(2),'Snapshot must not acquire the ingestion lock')
  t.join();self.assertFalse(errors)

if __name__=='__main__':unittest.main()
