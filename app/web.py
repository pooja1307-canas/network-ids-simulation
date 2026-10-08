from flask import Flask, render_template, request, redirect, send_file
from pathlib import Path
from .db import (
    init,
    alerts,
    stats,
    status,
    get_alert,
    update_alert_status,
    analytics,
    insert
)
from .config import REPORT
from .detection import analyze
import pandas as pd
from html import escape

app = Flask(__name__)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

init()


@app.route('/')
def home():
    return render_template('dashboard.html', stats=stats())


@app.route('/alerts')
def alert_page():
    s = request.args.get('severity')
    a = alerts()
    a = [x for x in a if not s or x['severity'] == s]

    return render_template(
        'alerts.html',
        alerts=a,
        selected=s or ''
    )


@app.route('/alert/<int:alert_id>')
def investigate(alert_id):
    alert = get_alert(alert_id)

    if alert is None:
        return "Alert not found", 404

    return render_template(
        'investigate.html',
        alert=alert
    )


@app.post('/alerts/<int:i>')
def update(i):
    new_status = request.form.get('status', 'OPEN')
    update_alert_status(i, new_status)

    return redirect(f'/alert/{i}')


@app.route('/analytics')
def analytics_page():
    data = analytics()

    return render_template(
        'analytics.html',
        data=data
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload_csv():
    message = ''

    if request.method == 'POST':
        file = request.files.get('file')

        if not file or file.filename == '':
            message = 'Please select a CSV file.'

        elif not file.filename.lower().endswith('.csv'):
            message = 'Only CSV files are allowed.'

        else:
            save_path = UPLOAD_DIR / file.filename
            file.save(save_path)

            try:
                df = pd.read_csv(save_path)

                required = {
                    'timestamp',
                    'src_ip',
                    'dst_ip',
                    'protocol',
                    'src_port',
                    'dst_port',
                    'bytes',
                    'packets',
                    'duration',
                    'scenario'
                }

                if not required.issubset(df.columns):
                    missing = required - set(df.columns)

                    message = (
                        f'Invalid CSV. Missing columns: '
                        f'{", ".join(missing)}'
                    )

                else:
                    results = analyze(df)

                    for alert in results:
                        insert(alert)

                    message = (
                        f'CSV analyzed successfully. '
                        f'{len(results)} network flows processed.'
                    )

            except Exception as e:
                message = f'Error processing CSV: {e}'

    return render_template(
        'upload.html',
        message=message
    )


@app.route('/report')
def report():
    a = alerts(100)

    rows = ''.join(
        f"<tr>"
        f"<td>{escape(str(x['timestamp']))}</td>"
        f"<td>{x['src_ip']}</td>"
        f"<td>{x['dst_ip']}:{x['dst_port']}</td>"
        f"<td>{x['classification']}</td>"
        f"<td>{x['severity']}</td>"
        f"<td>{x['risk_score']}</td>"
        f"<td>{escape(x['reasons'])}</td>"
        f"</tr>"
        for x in a
    )

    REPORT.write_text(
        f"""
        <html>
        <head>
            <title>IDS Incident Report</title>
        </head>
        <body>
            <h1>Network IDS Incident Report</h1>

            <p>
                Total events: {stats()['total']}
                |
                Suspicious: {stats()['suspicious']}
                |
                High/Critical: {stats()['high']}
            </p>

            <table border='1'>
                <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Class</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Reasons</th>
                </tr>

                {rows}

            </table>
        </body>
        </html>
        """,
        encoding='utf-8'
    )

    return send_file(
        REPORT,
        as_attachment=True,
        download_name='ids_incident_report.html'
    )
