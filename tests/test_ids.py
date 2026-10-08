import unittest,pandas as pd
from app.detection import analyze
class TestIDS(unittest.TestCase):
 def test_bad_port_detected(self):
  df=pd.DataFrame([{'timestamp':'x','src_ip':'10.0.0.2','dst_ip':'10.0.0.1','protocol':'TCP','src_port':50000,'dst_port':445,'bytes':500,'packets':5,'duration':.1,'scenario':'odd_port'}]*5)
  r=analyze(df,use_ml=False); self.assertTrue(any('high-risk' in x['reasons'] for x in r))
 def test_output(self):
  df=pd.DataFrame([{'timestamp':'x','src_ip':'10.0.0.2','dst_ip':'10.0.0.1','protocol':'TCP','src_port':50000,'dst_port':443,'bytes':1000,'packets':10,'duration':1,'scenario':'normal'}]*10)
  r=analyze(df,use_ml=False); self.assertEqual(len(r),10)
if __name__=='__main__': unittest.main()
