import argparse,pandas as pd
from .config import TRAFFIC
from .generator import save
from .detection import analyze
from .db import init,reset,insert

def main():
 p=argparse.ArgumentParser(); s=p.add_subparsers(dest='cmd',required=True)
 g=s.add_parser('generate'); g.add_argument('--rows',type=int,default=500)
 d=s.add_parser('detect'); d.add_argument('--no-ml',action='store_true')
 m=s.add_parser('demo'); m.add_argument('--rows',type=int,default=500); m.add_argument('--no-ml',action='store_true')
 s.add_parser('reset')
 a=p.parse_args(); init()
 if a.cmd=='generate': save(TRAFFIC,a.rows); print(f'Generated {a.rows} synthetic flows')
 elif a.cmd=='reset': reset(); print('Database reset')
 else:
  if a.cmd=='demo': save(TRAFFIC,a.rows)
  if not TRAFFIC.exists(): save(TRAFFIC,500)
  reset(); rows=analyze(pd.read_csv(TRAFFIC),not a.no_ml)
  for r in rows: insert(r)
  print(f'Analyzed {len(rows)} flows; alerts stored in ids.db')
if __name__=='__main__': main()
