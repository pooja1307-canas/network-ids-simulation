from pathlib import Path
BASE_DIR=Path(__file__).resolve().parent.parent
DATA_DIR=BASE_DIR/'data'; REPORT_DIR=BASE_DIR/'reports'; DB_PATH=BASE_DIR/'ids.db'; TRAFFIC=DATA_DIR/'traffic.csv'; REPORT=REPORT_DIR/'generated'/'incident_report.html'
DATA_DIR.mkdir(exist_ok=True); REPORT.parent.mkdir(parents=True,exist_ok=True)
