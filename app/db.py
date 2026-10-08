import sqlite3
from .config import DB_PATH
SCHEMA='''CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,src_ip TEXT,dst_ip TEXT,protocol TEXT,src_port INTEGER,dst_port INTEGER,classification TEXT,severity TEXT,risk_score INTEGER,reasons TEXT,bytes INTEGER,packets INTEGER,duration REAL,status TEXT);'''
def conn():
 c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; return c
def init():
 with conn() as c: c.execute(SCHEMA)
def reset():
 with conn() as c: c.execute('DELETE FROM alerts')
def insert(a):
 with conn() as c: c.execute('INSERT INTO alerts(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,classification,severity,risk_score,reasons,bytes,packets,duration,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(a['timestamp'],a['src_ip'],a['dst_ip'],a['protocol'],a['src_port'],a['dst_port'],a['classification'],a['severity'],a['risk_score'],a['reasons'],a['bytes'],a['packets'],a['duration'],a['status']))
def alerts(limit=500):
 with conn() as c: return c.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?',(limit,)).fetchall()
def stats():
    with conn() as c:
        total = c.execute(
            'SELECT COUNT(*) FROM alerts'
        ).fetchone()[0]

        suspicious = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE classification != 'NORMAL'"
        ).fetchone()[0]

        high = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH','CRITICAL')"
        ).fetchone()[0]

        open_alerts = c.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='OPEN'"
        ).fetchone()[0]

        severity_rows = c.execute(
            '''
            SELECT severity, COUNT(*) AS count
            FROM alerts
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    WHEN 'INFO' THEN 5
                    ELSE 6
                END
            '''
        ).fetchall()

        class_rows = c.execute(
            '''
            SELECT classification, COUNT(*) AS count
            FROM alerts
            GROUP BY classification
            ORDER BY count DESC
            '''
        ).fetchall()

        return {
            'total': total,
            'suspicious': suspicious,
            'high': high,
            'open': open_alerts,
            'by_severity': [
                {
                    'severity': row['severity'],
                    'count': row['count']
                }
                for row in severity_rows
            ],
            'by_class': [
                {
                    'classification': row['classification'],
                    'count': row['count']
                }
                for row in class_rows
            ]
        }
def status(i,s):
 with conn() as c:c.execute('UPDATE alerts SET status=? WHERE id=?',(s,i))
def get_alert(alert_id):
    with conn() as c:
        return c.execute(
            'SELECT * FROM alerts WHERE id=?',
            (alert_id,)
        ).fetchone()


def update_alert_status(alert_id, new_status):
    with conn() as c:
        c.execute(
            'UPDATE alerts SET status=? WHERE id=?',
            (new_status, alert_id)
        )
def analytics():
    with conn() as c:
        severity = c.execute(
            'SELECT severity, COUNT(*) as count '
            'FROM alerts GROUP BY severity'
        ).fetchall()

        classification = c.execute(
            'SELECT classification, COUNT(*) as count '
            'FROM alerts GROUP BY classification'
        ).fetchall()

        sources = c.execute(
            'SELECT src_ip, COUNT(*) as count '
            'FROM alerts GROUP BY src_ip '
            'ORDER BY count DESC LIMIT 10'
        ).fetchall()

        ports = c.execute(
            'SELECT dst_port, COUNT(*) as count '
            'FROM alerts GROUP BY dst_port '
            'ORDER BY count DESC LIMIT 10'
        ).fetchall()

        return {
            'severity': [dict(x) for x in severity],
            'classification': [dict(x) for x in classification],
            'sources': [dict(x) for x in sources],
            'ports': [dict(x) for x in ports]
        }