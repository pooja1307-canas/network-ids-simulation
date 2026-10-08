# Network Intrusion Detection System (IDS) Simulation

A safe, offline, industry-oriented defensive IDS/SOC project for students.

## Features
- Synthetic network-flow generator
- Protocol/port/source/destination analysis
- Signature/rule detection
- Statistical anomaly detection
- Optional Isolation Forest ML
- Risk scoring and severity
- SQLite event storage
- Flask SOC dashboard
- Alert investigation lifecycle
- HTML incident report
- Unit tests

## Safety
No public or third-party scanning, probing, exploitation, disruption, or real malicious traffic. Attack-like behavior exists only as synthetic records generated locally.

## Architecture
Synthetic Traffic → Feature Engineering → Rule Engine + Anomaly Detector → Risk/Severity → SQLite → Flask SOC Dashboard → Investigation/Report

## Windows setup
```bat
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m app.cli demo --rows 500
python run.py
```
Open `http://127.0.0.1:5000`.

## Commands
```bat
python -m app.cli generate --rows 500
python -m app.cli detect
python -m app.cli demo --rows 500
python -m app.cli reset
python -m unittest discover -s tests -v
```

## Detection model
Rules flag configured high-risk ports, synthetic port-scan patterns, unusual bytes/packets/duration and high synthetic packet rate. Statistical z-scores provide explainable anomaly evidence. Isolation Forest is optional and runs locally on the generated feature set.

## SOC workflow
Generate telemetry → detect → review severity/risk → filter alerts → set OPEN/INVESTIGATING/CLOSED → export report.

## GitHub strategy
Repo: `network-intrusion-detection-system`
Suggested commits: `feat: add traffic generator`, `feat: add signature detection`, `feat: add anomaly detection`, `feat: add sqlite alerts`, `feat: add soc dashboard`, `test: add ids tests`, `docs: add screenshots and report`.

Do not commit `ids.db`, virtual environments, generated traffic, secrets, or large datasets.

## Resume bullet
Built a defensive Network Intrusion Detection System simulation using Python, Flask, SQLite and Scikit-learn, combining signature and anomaly-based detection with risk scoring, alert lifecycle management and SOC-style incident reporting.

## Interview pitch
“I built a safe IDS simulation using synthetic network-flow telemetry. It engineers features, applies deterministic signatures and anomaly detection, optionally uses Isolation Forest, combines evidence into a risk score, stores alerts in SQLite, and provides a SOC investigation dashboard. No real system is attacked.”

## Production limitations
Educational simulation only. Production IDS would require real telemetry, calibrated baselines, authentication/RBAC, threat intelligence, rule tuning, deduplication, log integrity and operational monitoring.
