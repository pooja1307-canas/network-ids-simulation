import random
from datetime import datetime,timedelta,timezone
import pandas as pd
NORMAL=[22,25,53,80,110,123,143,443,3306]
BAD=[21,23,445,3389,4444]
def generate(rows=500,seed=42):
 random.seed(seed); now=datetime.now(timezone.utc).replace(microsecond=0); out=[]
 for i in range(rows):
  scenario=random.choices(['normal','port_scan','burst','odd_port','long_flow'],[72,8,7,8,5])[0]
  dp=random.choice(NORMAL); packets=random.randint(3,80); bytes_=random.randint(300,12000); duration=random.uniform(.01,5)
  if scenario=='port_scan': dp=random.randint(1,1024); packets=random.randint(1,5); bytes_=random.randint(40,500); duration=random.uniform(.001,.08)
  elif scenario=='burst': packets=random.randint(500,3000); bytes_=random.randint(50000,500000); duration=random.uniform(.1,1.5)
  elif scenario=='odd_port': dp=random.choice(BAD)
  elif scenario=='long_flow': duration=random.uniform(60,300); packets=random.randint(200,800); bytes_=random.randint(30000,120000)
  out.append({'timestamp':(now+timedelta(seconds=i*2)).isoformat(),'src_ip':f'10.0.0.{random.randint(2,254)}','dst_ip':random.choice(['10.0.0.1','10.0.0.10','10.0.0.20','10.0.0.50']),'protocol':random.choice(['TCP','UDP','ICMP']),'src_port':random.randint(1024,65535),'dst_port':dp,'bytes':bytes_,'packets':packets,'duration':round(duration,3),'scenario':scenario})
 return pd.DataFrame(out)
def save(path,rows=500,seed=42):
 df=generate(rows,seed); df.to_csv(path,index=False); return df
