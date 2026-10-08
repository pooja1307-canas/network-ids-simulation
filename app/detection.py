import numpy as np
from .generator import generate
BAD={21,23,445,3389,4444}
def features(df):
 x=df.copy(); x['bytes_z']=(x.bytes-x.bytes.mean())/(x.bytes.std() or 1); x['packets_z']=(x.packets-x.packets.mean())/(x.packets.std() or 1); x['duration_z']=(x.duration-x.duration.mean())/(x.duration.std() or 1); x['pps']=x.packets/x.duration.clip(lower=.001); return x.fillna(0)
def analyze(df,use_ml=True):
 x=features(df); ml=np.zeros(len(x),dtype=bool); mlscore=np.zeros(len(x))
 if use_ml:
  try:
   from sklearn.ensemble import IsolationForest
   cols=['bytes','packets','duration','src_port','dst_port','pps']; m=IsolationForest(n_estimators=150,contamination=.1,random_state=42); ml=m.fit_predict(x[cols])==-1; raw=-m.score_samples(x[cols]); mlscore=(raw-raw.min())/(raw.max()-raw.min()+1e-9)*100
  except Exception: pass
 out=[]
 for idx,r in x.iterrows():
  score=0; reasons=[]
  if int(r.dst_port) in BAD: score+=25; reasons.append(f'high-risk destination port {int(r.dst_port)}')
  if r.scenario=='port_scan': score+=35; reasons.append('synthetic port-scan pattern')
  if r.bytes_z>=3: score+=20; reasons.append('unusual byte volume')
  if r.packets_z>=3: score+=20; reasons.append('unusual packet volume')
  if r.duration_z>=3: score+=10; reasons.append('unusual flow duration')
  if r.pps>=1000: score+=20; reasons.append('very high synthetic packet rate')
  anomaly=min(100,int(max(abs(r.bytes_z),abs(r.packets_z),abs(r.duration_z))*20))
  if max(abs(r.bytes_z),abs(r.packets_z),abs(r.duration_z))>=3: reasons.append('statistical anomaly detector flagged flow')
  if ml[idx]: anomaly=max(anomaly,float(mlscore[idx])); reasons.append('Isolation Forest anomaly')
  risk=int(min(100,score*.65+anomaly*.35+(10 if ml[idx] else 0)))
  sev='CRITICAL' if risk>=80 else 'HIGH' if risk>=60 else 'MEDIUM' if risk>=35 else 'LOW' if risk>=15 else 'INFO'
  cls='POTENTIAL INTRUSION' if risk>=60 else 'SUSPICIOUS' if risk>=15 else 'NORMAL'
  out.append({**r.to_dict(),'classification':cls,'severity':sev,'risk_score':risk,'reasons':'; '.join(reasons) or 'no detection rule triggered','status':'OPEN' if cls!='NORMAL' else 'CLOSED'})
 return out
