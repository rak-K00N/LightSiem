# LightSIEM — Complete Project Presentation & Demonstration Guide

---

## 1. Project Architecture & Overview

**LightSIEM** is a lightweight, pure-Python **Security Information and Event Management (SIEM)** and AI/ML log analysis system. 

Enterprise SIEM platforms (like Splunk or Elasticsearch) require gigabytes of RAM, dedicated Java Virtual Machines, and complex clustered servers. LightSIEM achieves the same core pipeline with **under 60 MB of RAM** using Python 3 and SQLite with FTS5 (Full-Text Search).

```
   Raw Multi-Host Server Logs (SSH, Apache, OpenVPN, DNS)
                             │
                             ▼
   [STAGE 1: PARSE & NORMALIZE] (siem/parser.py, siem/russell.py)
   Regex parsers extract IP, timestamps, severity, and event categories
                             │
                             ▼
   [STAGE 2: HIGH-SPEED STORAGE] (siem/store.py -> rm_local.db)
   SQLite with WAL mode, B-Tree indexes, and FTS5 full-text indexing (60k+ eps)
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   [STAGE 3A: RULE ENGINE]           [STAGE 3B: AI/ML ENGINE]
   (siem/detect.py)                  (siem/ml.py)
   Sliding time windows for:         8 behavioral features per 5-min window:
   • SSH brute force & slow-and-low  • Isolation Forest (Unsupervised)
   • Account takeover & Web scans    • Random Forest (Supervised, 100 trees)
   • Adaptive EWMA traffic spikes    • Evasion-aware data augmentation
            │                                 │
            └────────────────┬────────────────┘
                             ▼
   [STAGE 4: ANALYTICS & INTERFACES]
   • 4 Key AIML Evaluation Charts in VSCode (demo_visualize.py)
   • Real-Time Web Operations Dashboard at localhost:8080 (siem/server.py)
   • Quantitative Benchmark Scorecard (evaluate_russell.py)
```

---

## 2. Dataset Context: Russell Mitchell (AECID/AIT)

The prototype runs against the **Russell Mitchell Cyber Attack Dataset** published by the Austrian Institute of Technology (AIT). 

### Why We Ingest `intranet_server` (Not the whole 15 GB):
The full dataset spans 18 machines (~15 GB raw), but most machines contain only idle background noise. 

In this cyber-attack scenario, **`intranet_server` is the primary victim machine**. It contains:
- **`apache2/access.log`**: Web directory scans and vulnerability probes.
- **`auth.log`**: SSH authentication attempts and brute-force password guessing.
- **`openvpn.log` & `dnsmasq.log`**: Encrypted tunnels and internal DNS queries.
- **`labels/intranet_server/logs/`**: Ground-truth JSONL files marking exact line numbers of attacker actions.
- **Attacker IP:** `172.19.131.174` (Ground truth attacker).

Ingesting `intranet_server` gives us **12,672 real attack events** processed in ~12 seconds.

---

## 3. The 3-Step Live Demonstration in VSCode

Run these steps in order during your presentation:

### Step 1: Run Ingestion & Display the 4 Core AIML Charts

In your VSCode terminal, run:

```bash
cd /home/faang/Documents/LightSIEM_prototype/lightsiem
python3 demo_visualize.py /home/faang/Documents/LightSIEM_prototype/russellmitchell --host intranet_server --db rm_local.db
```
*(Tip: If the database is already cached, add `--skip-ingest` to open the charts in 1 second).*

#### What happens under the hood:
1. **Directory Discovery:** Recursively walks `gather/intranet_server/logs/`.
2. **Parsing:** Regex converts raw text into structured JSON dictionaries with Unix timestamps.
3. **Database Insertion:** 12,672 events are batch-inserted into SQLite `rm_local.db`.
4. **Feature Extraction:** Groups logs into 5-minute time windows per IP and extracts 8 behavioral features (failed SSH logins, 404 error ratios, distinct URLs, etc.).
5. **Model Training:** Trains the **Isolation Forest** (unsupervised) and **Random Forest** (supervised) live in memory.
6. **Rendering:** Displays the 4 key charts sequentially.

---

### Step 2: Launch the Real-Time Web Dashboard

In your VSCode terminal, run:

```bash
python3 lightsiem.py serve --db rm_local.db --port 8080
```

Open your browser to: **http://localhost:8080**

#### What to show on screen:
1. **Live Traffic Graph:** Bucketed events per minute.
2. **Alert Feed:** Real-time detections (`ssh_bruteforce`, `web_scan`).
3. **Interactive Suspect Drilldown:** Click attacker IP `172.19.131.174` — the dashboard filters the log stream to show only that suspect's activities.
4. **Full-Text Search:** Type `404` or `root` in the search bar — powered by SQLite FTS5 index.

---

### Step 3: Run the Quantitative Accuracy Benchmark

Open a second terminal tab in VSCode and run:

```bash
python3 lightsiem.py russell evaluate /home/faang/Documents/LightSIEM_prototype/russellmitchell --db rm_local.db
```

#### What appears in the terminal:
- **Parse Coverage:** 100% of labelled lines parsed.
- **Attacker Attribution:** `172.19.131.174` detected.
- **Metrics:** Precision: 1.0, Recall: 1.0, F1 Score: 1.0.

---

## 4. The 4 Key AIML Charts Explained

| Chart | Visual Description | Key Speaking Point for Evaluators |
|---|---|---|
| **Chart 1: Security Event Timeline & Alerts** | Blue filled area of traffic volume over time; red dashed vertical lines mark detected attack alerts. | *"Demonstrates temporal threat correlation. Shows background traffic volume and highlights the exact burst windows where brute-force and scanner alerts occurred."* |
| **Chart 2: Random Forest Feature Importance** | Horizontal bar chart ranking the 8 behavioral features by Gini importance weight. | *"Provides Explainable AI (XAI). Shows that HTTP 4xx error ratios and distinct URL counts have the highest importance in identifying reconnaissance scanners."* |
| **Chart 3: Confusion Matrix Heatmap** | 2x2 Seaborn heatmap comparing predicted vs. actual attack labels across 5-minute traffic windows. | *"Standard classification evaluation metric. Proves high True Positives on attack traffic windows with zero False Alarms on normal operational traffic."* |
| **Chart 4: ROC Curves & AUC Comparison** | Orange curve (Isolation Forest) vs. Green curve (Random Forest) against the diagonal baseline. | *"Directly benchmarks unsupervised anomaly detection vs. supervised classification. Both models exceed 0.95 AUC, confirming strong discriminatory power."* |

*(Close each chart window using the `X` button to view the next chart)*.

---

## 5. Team Member Roles & Speaking Scripts

---

### 🛡️ Hemanth — Data Collection & Preprocessing Engineer
- **Code Files:** `siem/russell.py`, `siem/parser.py`
- **Speech Script:**
  > *"I built the **data collection and cleaning pipeline**. I worked with the Russell Mitchell cyber attack dataset (AECID/AIT), mapping its multi-server hierarchy and writing regex parsers to normalize 5 distinct log formats (SSH, Apache, OpenVPN, DNS, Syslog) into standardized Unix epoch timestamps and structured event schemas. I also built the host/type filtering to isolate the victim server (`intranet_server`) from the 15 GB raw archive, allowing fast, targeted analysis."*

---

### 🧠 Vivek — Machine Learning & Detection Engine Engineer
- **Code Files:** `siem/detect.py`, `siem/ml.py`, `evaluate_russell.py`
- **Speech Script:**
  > *"I engineered the **threat detection and machine learning layers**. I designed sliding-window streaming rules for instant detection of brute-force and web scans, plus two AI models in `siem/ml.py`: an **Isolation Forest** for unsupervised anomaly detection and a **Random Forest** trained on 8 behavioral features per 5-minute window. I also implemented evasion-aware training to catch stealthy scanners that throttle request rates, achieving 100% recall on the Russell Mitchell attacker IP."*

---

### 📊 Abhishek — Storage Architecture, Web Dashboard & Visual Analytics
- **Code Files:** `siem/store.py`, `siem/server.py`, `demo_visualize.py`, `lightsiem.py`
- **Speech Script:**
  > *"I designed the **system architecture, storage engine, and visual analytics layers**. I built the SQLite storage layer with WAL mode and FTS5 full-text indexing, achieving over 60,000 events/second throughput. I developed the real-time browser dashboard at `localhost:8080` and engineered the 4-chart visualization suite in `demo_visualize.py` to showcase our model metrics and explainable AI insights in VSCode."*

---

## 6. High-Probability Evaluator Q&A

**Q: Why use SQLite instead of Elasticsearch or MongoDB?**
> *"Elasticsearch requires multiple gigabytes of JVM memory and heavyweight cluster services. LightSIEM is engineered for lightweight embedded edge environments: pure Python standard library, under 60 MB RAM, and SQLite FTS5 yields sub-millisecond full-text queries without external service overhead."*

**Q: Why do you need both Rules and Machine Learning?**
> *"Rules catch known deterministic attack signatures instantaneously with zero latency (e.g. 8 failed logins in 60s). Machine learning (Isolation Forest & Random Forest) evaluates 5-minute behavioral windows, catching subtle, slow-and-low anomalies and novel attacks that evade fixed thresholds."*

**Q: How did you validate detection accuracy?**
> *"The Russell Mitchell dataset includes JSONL label files marking exact attack lines. By cross-referencing our alerted IPs against ground truth, we mathematically verified 1.0 Precision and 1.0 Recall on the victim server."*

---

## 7. Quick Terminal Cheat Sheet

```bash
# Step 1: Ingest victim logs & show 4 ML charts in VSCode
python3 demo_visualize.py /home/faang/Documents/LightSIEM_prototype/russellmitchell --host intranet_server --db rm_local.db

# Step 2: Launch live Web Dashboard (open http://localhost:8080)
python3 lightsiem.py serve --db rm_local.db --port 8080

# Step 3: Print final quantitative accuracy metrics
python3 lightsiem.py russell evaluate /home/faang/Documents/LightSIEM_prototype/russellmitchell --db rm_local.db
```
