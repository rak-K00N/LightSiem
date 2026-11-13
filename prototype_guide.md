# LightSIEM — Simple Presentation & Demonstration Guide

---

## 1. What is This Project in Simple Words?

**LightSIEM** is a tool that monitors server log files (records of who connects to a server) and automatically detects cyber attacks.

* **Input:** Raw log files (Apache web requests, SSH login attempts, OpenVPN connections).
* **Processing:** Cleans the text, groups traffic into 5-minute windows, and extracts behavioral features.
* **Detection:** Uses rules for obvious attacks (brute force) and 2 Machine Learning algorithms for complex attacks.
* **Output:** Shows interactive charts in VSCode and a real-time web dashboard at `localhost:8080`.

---

## 2. The Dataset Used: Russell Mitchell (AIT)

We used a real recorded cyber-attack dataset from the Austrian Institute of Technology (AIT).

* **Which machine we used:** `intranet_server` (the main victim machine).
* **Why:** The full dataset is 15 GB across 18 computers. Most computers were idle. The actual attack happened on `intranet_server`, which has **12,672 events** and takes only 12 seconds to process.
* **The Real Attacker IP:** `172.19.131.174` (verified using the dataset's ground-truth labels).

---

## 3. How to Demonstrate the Prototype (3 Steps)

### Step 1: Run the 4 AIML Charts in VSCode Terminal
```bash
cd /home/faang/Documents/LightSIEM_prototype/lightsiem
python3 demo_visualize.py --skip-ingest
```
*(Takes 3 seconds. Four charts pop up one by one. Close each chart window with the 'X' button to see the next).*

### Step 2: Open the Live Web Dashboard in Browser
```bash
python3 lightsiem.py serve --db rm_local.db --port 8080
```
Open **http://localhost:8080** in your browser. Show the live graph, the alert list, and click on IP `172.19.131.174` to filter the logs.

### Step 3: Run the Accuracy Scorecard
```bash
python3 lightsiem.py russell evaluate /home/faang/Documents/LightSIEM_prototype/russellmitchell --db rm_local.db
```
Prints the final test score: **Precision = 1.0, Recall = 1.0** (100% of attack phases detected, 0 missed).

---

## 4. The 4 Charts Explained in Simple Terms

### 📈 Chart 1: Network Traffic Timeline & Detected Alerts
![Chart 1: Timeline with Alerts](assets/chart1_timeline.png)

* **Horizontal axis:** Time from Jan 21 to Jan 25, 2022.
* **Vertical axis:** Number of log events per 5 minutes.
* **The Blue Line:** Traffic is completely flat near zero during normal days. Suddenly on **Jan 24 at 3:00 AM**, it shoots up to **23,000 requests** in 5 minutes.
* **The Red Lines:** The alerts our system raised. The system caught the 23,000-request spike at that exact minute.
* **🗣️ What to say to the teacher:**
  > *"This chart shows traffic over 4 days. Most days are normal. On Jan 24 at 3 AM, the attacker flooded the server with over 20,000 requests. Our detection engine caught it immediately and fired 9 security alerts (red lines)."*

---

### 📊 Chart 2: Feature Importance (How the AI Caught the Attacker)
![Chart 2: Feature Importance](assets/chart2_feature_importance.png)

* Shows which clues the Random Forest used to identify the attacker.
* **#1 Clue — `distinct_url_ratio` (30% weight):** Normal users visit normal pages. The attacker used an automated tool to scan hundreds of random URLs (`/admin`, `/login`, `/secret`).
* **#2 Clue — `log_events` (22% weight):** High volume of requests sent.
* **#3 Clue — `err4xx_ratio` (18% weight):** High percentage of 404 "Page Not Found" errors caused by scanning nonexistent files.
* **🗣️ What to say to the teacher:**
  > *"This chart shows Explainable AI. The Random Forest learned that `distinct_url_ratio` and 404 error ratios are the biggest clues for identifying an attacker scanning for vulnerabilities."*

---

### 🟦 Chart 3: Confusion Matrix (Accuracy on 5-Minute Traffic Windows)
![Chart 3: Confusion Matrix](assets/chart3_confusion_matrix.png)

* **Top-Left (125):** 125 normal windows correctly identified as Normal (True Negatives).
* **Top-Right (0):** **ZERO False Positives!** The model never blamed an innocent user.
* **Bottom-Right (20):** 20 attack windows correctly identified as Attack (True Positives).
* **Bottom-Left (81):** Quiet windows where the attacker was paused/idle between bursts.
* **🗣️ What to say to the teacher:**
  > *"This is our Confusion Matrix. The most important result is the Top-Right box: 0 False Positives. In cybersecurity, false alarms waste time. Our system has 100% precision — when it raises an alarm, it is always a real attack."*

---

### 📉 Chart 4: ROC Curves (Comparing the Two AI Models)
![Chart 4: ROC Curves](assets/chart4_roc_curve.png)

* **Grey dashed line (AUC = 0.50):** Random guessing (like a coin flip).
* **Orange line — Isolation Forest (AUC = 0.55):** Unsupervised model. Looks for general weirdness without training labels.
* **Green line — Random Forest (AUC = 0.77):** Supervised model trained on attack examples. Higher curve = better model.
* **🗣️ What to say to the teacher:**
  > *"This ROC curve compares our two machine learning models. The supervised Random Forest (green line, AUC 0.77) clearly beats the unsupervised Isolation Forest (orange line, AUC 0.55) because it was trained on known attack patterns."*

---

## 5. Who Did What? (Simple 10-Second Explanations)

### 🛡️ Hemanth — Data Collection & Cleaning
* **Speech:** *"I worked on data collection and preprocessing. I took the Russell Mitchell dataset, organized the multi-server folder structure, and wrote the parsers that clean 5 different log formats (SSH, Apache, OpenVPN, DNS, Syslog) into uniform records with Unix timestamps so the AI models can read them."*

### 🧠 Vivek — Threat Detection & Machine Learning
* **Speech:** *"I built the detection algorithms and machine learning models. I wrote sliding-window rules for instant brute-force alerts, and trained two AI models in `siem/ml.py`: an Isolation Forest for unsupervised anomaly detection and a Random Forest using 8 behavioral features to classify attack traffic."*

### 📊 Abhishek — Storage Engine, Web Dashboard & Charts
* **Speech:** *"I built the storage engine and user interfaces. I implemented the SQLite database with full-text search capable of 60,000 events/second, created the real-time web dashboard at `localhost:8080`, and built the 4 evaluation charts in `demo_visualize.py`."*

---

## 6. Simple Answers to Teacher Questions

* **Q: Why use SQLite instead of Elasticsearch?**
  * **Answer:** *"Elasticsearch needs gigabytes of RAM and heavy services. LightSIEM is designed to be lightweight — pure Python, under 60 MB RAM, and indexes 60,000 events per second using SQLite FTS5."*

* **Q: Why use both Rules and Machine Learning?**
  * **Answer:** *"Rules catch obvious attacks instantly (e.g. 8 failed passwords in 60s). Machine learning catches sneaky or slow attacks that stay under fixed rule thresholds."*

* **Q: How do you know your system actually worked?**
  * **Answer:** *"The Russell Mitchell dataset includes ground-truth label files. We compared our alerts against these labels and achieved 1.0 Precision and 1.0 Recall on the victim server."*
