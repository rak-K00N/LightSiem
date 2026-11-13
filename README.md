# LightSIEM - A Lightweight SIEM & AI/ML Log Analysis Tool

Pipeline (same stages as an enterprise SIEM like Elastic/Splunk): **Collect -> Parse/Normalise -> Store + Search -> Detect (Rules + ML) -> Dashboard / Visual Analytics**.

The core pipeline (collect, parse, store, rules, web dashboard) is pure Python 3.9+ standard library with SQLite FTS5 (no JVM, no heavyweight external services).
The AI/ML detection and visual demonstration components use `scikit-learn`, `numpy`, `matplotlib`, and `seaborn`.

| Stage | File | What it does |
|---|---|---|
| Collect | `siem/ingest.py` | Reads files (merged chronologically) or follows a live file (`tail -f`) |
| Parse | `siem/parser.py` | Syslog/sshd, Apache/Nginx, OpenVPN, and dnsmasq logs -> common event schema |
| Store/Search | `siem/store.py` | SQLite database, indexes on time & IP, FTS5 full-text search index |
| Detect | `siem/detect.py` | Streaming sliding-window rules + adaptive EWMA rate anomaly detector |
| Dashboard | `siem/server.py`, `static/index.html` | Real-time web dashboard & JSON REST API |
| ML Detector | `siem/ml.py` | Isolation Forest (unsupervised) and Random Forest (supervised) on 5-min IP windows |
| Russell Mitchell | `siem/russell.py` | Multi-host parser & label loader for the AECID/AIT Cyber Attack Dataset |
| AIML Visuals | `demo_visualize.py` | Interactive Matplotlib/Seaborn charts (Confusion Matrix, ROC, Feature Importance) |
| Test Data | `siem/gen_logs.py` | Synthetic log generator with ground-truth attacker labels |
| Evaluation | `evaluate.py`, `evaluate_ml.py`, `evaluate_russell.py` | Automated accuracy scoring against ground-truth attack labels |

---

## Quick Start & Demonstration

### 1. Visual AIML Demo (Matplotlib & Seaborn Charts)
For project demonstrations, presentations, or lab evaluations, [`demo_visualize.py`](demo_visualize.py) displays 8 interactive charts directly inside VSCode or desktop terminals:

```bash
# Option A: Instant synthetic demo (Fastest: ~5 seconds, no dataset needed)
python demo_visualize.py --demo

# Option B: Ingest a slice of the Russell Mitchell dataset to a database
python demo_visualize.py "/path/to/russellmitchell" --host intranet_server --db rm_demo.db

# Option C: Re-run charts instantly from an existing database (skips ingestion)
python demo_visualize.py --db rm_demo.db --skip-ingest
```

#### Charts Displayed:
1. **Event Timeline & Alerts**: Traffic distribution over time with flagged attack timestamps.
2. **Log Categories**: Bar chart of events by protocol (`http`, `ssh`, `syslog`, `openvpn`, `dns`).
3. **Top Source IPs**: Identifies highest-volume IPs (confirmed attackers highlighted in red).
4. **Feature Importance (Random Forest)**: Which network behaviors (failed logins, 4xx ratios, distinct URLs) signal malicious activity.
5. **Confusion Matrix**: True Positive / False Positive breakdown on 5-minute traffic windows.
6. **ROC Curves & AUC**: Side-by-side comparison of Isolation Forest vs Random Forest.
7. **Model Comparison**: Precision, Recall, and F1-score across Rules, Isolation Forest, and Random Forest.
8. **Anomaly Score Distribution**: Histogram of Isolation Forest scores showing separation of normal vs attack traffic.

---

### 2. Interactive Web Dashboard
```bash
# Demo mode: generate sample data, ingest, and launch browser UI at http://127.0.0.1:8080
python lightsiem.py demo

# Ingest custom log files and launch web UI:
python lightsiem.py ingest auth.log access.log --db siem.db --year 2026
python lightsiem.py serve --db siem.db --port 8080
```
**Dashboard Features:** Live events-per-minute timeline, real-time alert table, top source IPs, and instant full-text/IP search.

---

## Russell Mitchell Dataset Support

LightSIEM natively supports the multi-host [Russell Mitchell Cyber Attack Dataset](https://www.ait.ac.at/) (AECID/AIT), parsing logs across directory structures like `gather/<host>/logs/` with associated `labels/` ground truth.

> **Tip:** If your path contains spaces, always wrap it in quotation marks: `"/run/media/.../russellmitchell"`.

### Inspect Available Files
```bash
python lightsiem.py russell list "/path/to/russellmitchell"
```

### Ingest Logs (With Host or Type Filtering)
Since the full dataset is ~15 GB, you can ingest targeted subsets in seconds:
```bash
# Ingest only the target web server (recommended for quick demos)
python lightsiem.py russell ingest "/path/to/russellmitchell" --host intranet_server --db rm_demo.db --serve

# Ingest specific log types across all hosts (e.g., apache, auth, openvpn, dnsmasq)
python lightsiem.py russell ingest "/path/to/russellmitchell" --type apache --db rm_demo.db
```

### Evaluate Detection Accuracy
Score LightSIEM detections against ground-truth attack labels and the attacker action timeline:
```bash
python lightsiem.py russell evaluate "/path/to/russellmitchell" --db rm_demo.db --out results_russell.json
```
Reports:
* **Ingestion Coverage**: Percentage of labelled lines successfully parsed.
* **IP-Level Attribution**: Precision, Recall, and F1-score for identifying attacker IPs (e.g. `172.19.131.174`).
* **Attack Phase Coverage**: Detection correlation with foothold, privilege escalation, and lateral movement.

---

## Detection Engines

### 1. Rule-Based Streaming Engine (`siem/detect.py`)
Processes events in chronological order with bounded per-IP sliding windows:
* **R1 `ssh_bruteforce`**: >= 8 failed SSH logins from one IP in 60 s
* **R1b `ssh_low_and_slow`**: >= 40 failed logins from one IP in 1 h
* **R2 `ssh_success_after_failures`**: Successful login after >= 5 failures in 5 min (possible account takeover)
* **R3 `web_scan`**: >= 25 HTTP 401/403/404 errors from one IP in 60 s (vulnerability scanning)
* **R4 `traffic_spike`**: Adaptive EWMA anomaly detection (alerts when traffic > mean + 4*std; excludes anomalous minutes from the baseline to prevent poisoning).

### 2. Machine Learning Engine (`siem/ml.py`)
Scores traffic behavior in 5-minute per-IP windows across 8 extracted behavioral features:
* `log(events)`, failed SSH logins, distinct usernames, HTTP request count, 4xx error ratio, distinct-URL ratio, 404 count, 5xx count.

Two interchangeable models:
* **Isolation Forest (Unsupervised)**: Learns what normal traffic looks like from baseline logs; flags anomalous deviations without needing prior attack labels.
* **Random Forest (Supervised)**: Learns distinct signatures of attack vs normal behavior; flags traffic with P(attack) >= 0.5.

```bash
# Train Isolation Forest on normal baseline logs:
python lightsiem.py train good_auth.log good_access.log --kind iforest --out model.pkl

# Train Random Forest with known attacker IP labels:
python lightsiem.py train auth.log access.log --kind rf --attackers attacker_ips.txt --out model.pkl

# Ingest logs using both rules AND machine learning:
python lightsiem.py ingest auth.log access.log --db siem.db --model model.pkl
```

---

## Advanced ML: Evasion-Aware Augmentation (v2)

Standard supervised classifiers fail when attackers slow down their request rate or dilute error codes with legitimate requests.
1. **Evasion-Aware Training (`--augment`)**: Synthesizes 11 disguised variations of attacker traffic during training (simulating 404 dilution and request rate throttling).
2. **Evidence Accumulation**: Strong confidence (`P > 0.8`) raises an immediate alert; weaker confidence (`P > 0.3`) requires persistence across 3 consecutive windows to eliminate false alarms from occasional user typos.

```bash
python lightsiem.py train auth.log access.log --kind rf --attackers attacker_ips.txt --augment --out model_v2.pkl
```

---

## Installation & Requirements

* **Python 3.9+**
* Pure Python standard library for basic rule ingestion and web UI.
* For AI/ML and Visualization features:
  ```bash
  pip install scikit-learn numpy matplotlib seaborn
  ```
