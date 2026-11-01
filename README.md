# LightSIEM - a lightweight SIEM-like log analysis tool

Pipeline (same stages as an Elastic-based SIEM): **collect -> parse/normalise -> store + search -> detect -> dashboard**.
The core (collect/parse/store/rules/dashboard) is pure Python 3.9+ standard library (SQLite FTS5 is built in): no JVM, no external services.
The optional machine-learning detector needs `pip install scikit-learn numpy`.

| Stage | File | What it does |
|---|---|---|
| Collect | `siem/ingest.py` | reads files (merged by time) or follows a live file like `tail -f` |
| Parse | `siem/parser.py` | syslog/sshd and nginx/Apache logs -> one common event schema |
| Store/Search | `siem/store.py` | SQLite, indexes on time and IP, FTS5 full-text index |
| Detect | `siem/detect.py` | streaming rules + adaptive anomaly detector (the "algorithm") |
| Dashboard | `siem/server.py`, `static/index.html` | JSON API + one-page dashboard |
| ML detector | `siem/ml.py` | Isolation Forest (unsupervised) or Random Forest (supervised) on per-IP 5-minute windows |
| Test data | `siem/gen_logs.py` | synthetic logs with ground-truth labels |
| Evaluation | `evaluate.py`, `evaluate_ml.py`, `evaluate_v2.py` | reproduce every number in `results.json` and `results_ml.json` |

## Run it
```
python lightsiem.py demo                      # sample logs -> ingest -> http://127.0.0.1:8080
python lightsiem.py ingest auth.log access.log --db siem.db --year 2026
python lightsiem.py serve --db siem.db
python lightsiem.py evaluate                  # regenerates results.json
```
Dashboard: events-per-minute chart, alert list, top IPs, full-text/IP/category search (click an IP to filter).

## Detection algorithm
Events are processed in time order with small per-IP sliding windows (deques), so memory is bounded.
* R1 `ssh_bruteforce`: >= 8 failed SSH logins from one IP in 60 s
* R1b `ssh_low_and_slow`: >= 40 failed logins from one IP in 1 h
* R2 `ssh_success_after_failures`: successful login after >= 5 failures in 5 min (possible compromise)
* R3 `web_scan`: >= 25 HTTP 401/403/404 responses to one IP in 60 s
* R4 `traffic_spike`: events/minute vs an exponentially weighted moving average; alert when
  x > mean + 4*std (EWMA, alpha 0.1). Anomalous minutes are not learned, so the baseline cannot be poisoned.
All thresholds are in `Detector(**kw)` and can be tuned.

## Machine learning detector (`siem/ml.py`)
Rules only catch what someone wrote a rule for. The ML detector scores every source IP's activity in 5-minute windows
using 8 features: log(events), failed SSH logins, distinct usernames, HTTP requests, share of 4xx errors, distinct-URL ratio,
number of 404s, number of 5xx. Two interchangeable models:
* **Isolation Forest (unsupervised)**: trained only on known-good logs; flags anything unusual.
* **Random Forest (supervised)**: trained on windows labelled attack/normal (IPs an analyst confirmed); flags P(attack) >= 0.5.
```
python lightsiem.py train good_auth.log good_access.log --kind iforest --out model.pkl
python lightsiem.py train auth.log access.log --kind rf --attackers confirmed_attacker_ips.txt --out model.pkl
python lightsiem.py ingest auth.log access.log --db siem.db --model model.pkl      # rules + ML together
python evaluate_ml.py                                                              # reproduces results_ml.json
```
ML alerts appear in the dashboard as `ml_iforest` / `ml_rf`. Only load model files you trained yourself (pickle can run code).

**Measured (synthetic, unseen test day, 54 attackers incl. 10 stealth scanners + 5 legitimate crawlers):**
rules alone P 1.00 / R 0.82; Isolation Forest P 0.81 / R 0.46 (flags all 5 crawlers); Random Forest P 1.00 / R 1.00;
the Random Forest did not see stealth scanners in training. See `results_ml.json` and `results_ml_chart.png`.
Cost: ingest ~73K -> ~38K events/s and ~27 MB -> ~158 MB memory (scikit-learn).


## v2 upgrade: evasion-aware training + evidence accumulation (supervised model)
Problem found in v1: the Random Forest only learned loud, fast scanners, so a scanner that hides among normal-looking 200
responses or slows down escaped it (v1 caught only about 28% of such scanners).
1. **Evasion-aware training** (`MLDetector.fit(..., augment=True)`): for every labelled attacker's web traffic, 11 disguised copies
   are added to the training set (404 -> 200 with probability 0/25/50/75%, crossed with keeping 100/50/20% of the requests).
2. **Evidence accumulation**: strong evidence (P(attack) > 0.8) alerts at once; weak evidence (P > 0.3) must repeat in 3
   consecutive 5-minute windows. This removes small-sample false alarms (an ordinary client with 5 requests, 2 of them 404).
Thresholds were tuned on a separate validation seed (`tune_v2.py`, `tune2_v2.py`), then tested on 5 fresh seeds.
```
python lightsiem.py train auth.log access.log --kind rf --attackers confirmed_attacker_ips.txt --augment --out model_v2.pkl
python evaluate_v2.py 1 2      # run seeds 1-2 (repeat with 3 4, then 5 5); results accumulate in results_v2_raw.json
```
**Measured (5 seeds, 300 evasive scanners per seed; mean):** evasive scanners detected - v2 95%, RF v1 28%, RF v1 with threshold 0.2 55%,
Isolation Forest 53%, tight fixed rule (>=10 errors/60 s) 21%, v1 rules 0%. Three held-out tactics never used in training
(few-URL reuse, burst-and-pause, 1 request/min): v2 100% on all three. False-alert IPs on a clean day: v2 0.6, v1 0.4, Isolation Forest 4.0.
Weak spot: scanners with only 15% 404s at 3-15 requests/min (v2 detects 65-82%).
Caveats: synthetic data; the augmentation matches the generator's evasion family; no comparison with Elastic/Wazuh.

## Known limitations (be upfront about these)
* ML scores are on SYNTHETIC data where attacks separate cleanly; expect lower accuracy on real logs. Validate on real data.
* Unsupervised anomaly detection says "unusual", not "malicious": it flagged legitimate crawlers. Its result also depends on the
  training day and threshold (training on a day that contained crawlers made it miss all stealth scanners).
* The supervised model is evaded by a scanner whose 404 rate drops below about 40% (see `evasion_404_rate`).
* Supervised learning needs labelled attacks, which are scarce in practice.
* Evaluated on SYNTHETIC logs written by us; real-world accuracy will be lower. Validate on real logs / Loghub.
* Attackers slower than ~0.5 failed logins/min evade the rules (see `evasion_test`).
* Distributed attacks (many IPs, few attempts each) are not correlated yet.
* Rules are hand-written; no machine learning. Single machine, no clustering, no authentication on the dashboard.
* `traffic_spike` also fires during large scan/brute-force bursts (they add real traffic).
