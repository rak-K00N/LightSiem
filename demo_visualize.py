#!/usr/bin/env python3
"""
LightSIEM – Visual Demo (runs in VSCode like your AIML lab programs)
=====================================================================
Shows 8 real AI/ML charts:
  Chart 1 – Event timeline with attack alerts overlaid
  Chart 2 – Bar chart: events per log category
  Chart 3 – Top 10 source IPs (attacker in red)
  Chart 4 – Feature importance (Random Forest)
  Chart 5 – Confusion Matrix (Random Forest, 5-min traffic windows)
  Chart 6 – ROC curve (Random Forest vs Isolation Forest with AUC)
  Chart 7 – Bar chart: Precision / Recall / F1 (Rules vs IF vs RF)
  Chart 8 – Anomaly score distribution (Isolation Forest)

Usage
-----
  # 1. Default (uses local dataset on intranet_server):
  python demo_visualize.py

  # 2. Fastest instant demo (synthetic logs, ~5 seconds):
  python demo_visualize.py --demo

  # 3. Specify custom host or path:
  python demo_visualize.py /home/faang/Documents/LightSIEM_prototype/russellmitchell --host intranet_server
"""

import argparse, os, sys, math, heapq, shutil, warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (confusion_matrix, roc_curve, roc_auc_score,
                             precision_score, recall_score, f1_score)

from siem.store import Store
from siem.detect import Detector
from siem.ml import MLDetector, FEATURES

sns.set_theme(style='darkgrid', palette='muted')

DEFAULT_DATASET = '/home/faang/Documents/LightSIEM_prototype/russellmitchell'

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
ap = argparse.ArgumentParser(description='LightSIEM – Visual Demo')
ap.add_argument('root', nargs='?', default=DEFAULT_DATASET,
                help=f'Path to Russell Mitchell dataset root (default: {DEFAULT_DATASET})')
ap.add_argument('--demo', action='store_true',
                help='Use built-in synthetic attack logs (~5 sec run, no dataset required)')
ap.add_argument('--host', action='append', dest='hosts', metavar='HOST',
                help='Filter by host (e.g. --host intranet_server).')
ap.add_argument('--type', action='append', dest='types', metavar='TYPE',
                help='Filter by log type (apache, auth, syslog …).')
ap.add_argument('--year', type=int, default=2022, help='Syslog year (default 2022)')
ap.add_argument('--db', default='rm_local.db',
                help='SQLite database path (default: rm_local.db)')
ap.add_argument('--skip-ingest', action='store_true',
                help='Skip log parsing and reuse existing database')
args = ap.parse_args()

def safe_metric(fn, yt, yp, **kw):
    try:
        return fn(yt, yp, **kw)
    except Exception:
        return 0.0

store = Store(args.db)

# ---------------------------------------------------------------------------
# Ingest / Data Prep
# ---------------------------------------------------------------------------
if args.demo:
    print('\n[MODE: Synthetic Demo] Generating attack logs …')
    from siem.gen_logs import generate
    import json as _json
    from siem.ingest import ingest, read_events as _re
    TMPDIR = '/tmp/lightsiem_demo_logs'
    shutil.rmtree(TMPDIR, ignore_errors=True)
    generate(TMPDIR, seed=7, scale=0.3, attacks=True, crawlers=True)
    truth = _json.load(open(f'{TMPDIR}/truth.json'))
    YEAR = 2026
    FILES = [f'{TMPDIR}/auth.log', f'{TMPDIR}/access.log']

    det = Detector()
    stats = ingest(FILES, store, det, YEAR)
    all_events = list(heapq.merge(*[_re(p, YEAR) for p in FILES], key=lambda e: e['ts']))
    ATTACK_TYPES = ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan')
    attacker_ips = {ip for k in ATTACK_TYPES for ip in truth.get(k, [])}
    print(f'      {stats["events"]:,} events  |  {store.stats()["alerts"]:,} rule alerts')
    print(f'      Attacker IPs: {len(attacker_ips)} unique IPs identified')

else:
    ROOT = args.root
    YEAR = args.year
    hosts = args.hosts or ['intranet_server']  # default to victim server for fast demo

    from siem.russell import collect_log_files, load_labels, ingest_dataset
    from siem.ingest import read_events as _re

    # Ingest if DB is empty or not skipped
    existing_events = store.stats()['events']
    if existing_events > 0 and args.skip_ingest:
        print(f'\n[1/4] Using cached database "{args.db}" ({existing_events:,} events, ingestion skipped)')
    else:
        print(f'\n[1/4] Ingesting logs from {ROOT} (Host: {", ".join(hosts)}) …')
        det = Detector()
        stats = ingest_dataset(ROOT, store, detector=det, year=YEAR,
                               host_filter=hosts, type_filter=args.types)
        rule_alerts_count = store.stats().get('alerts', 0)
        print(f'      {stats["events"]:,} events  |  {rule_alerts_count:,} alerts  |  {stats["events_per_sec"]:,.0f} eps')

    # Load labels for ground truth
    print('[2/4] Loading ground-truth labels …')
    all_labels = load_labels(ROOT)
    attacker_ips = set()
    for gather_path, line_map in all_labels.items():
        if not os.path.isfile(gather_path):
            continue
        attack_lines = {ln for ln, lbls in line_map.items()
                        if any('attacker' in l or 'escalat' in l or 'foothold' in l
                               or 'exfiltrat' in l or 'lateral' in l for l in lbls)}
        if not attack_lines:
            continue
        try:
            with open(gather_path, errors='replace') as fh:
                for lineno, raw in enumerate(fh, start=1):
                    if lineno in attack_lines:
                        from siem.parser import parse_line
                        e = parse_line(raw, YEAR)
                        if e and e.get('src_ip'):
                            attacker_ips.add(e['src_ip'])
        except OSError:
            pass

    print(f'      {len(attacker_ips)} attacker IP(s) in ground truth: {sorted(attacker_ips)}')

    # Load stream for ML window scoring
    files = collect_log_files(ROOT)
    if hosts:
        files = [(p, h, t) for p, h, t in files if h in hosts]
    if args.types:
        files = [(p, h, t) for p, h, t in files if t in args.types]

    hint_hosts   = {p: h for p, h, t in files}
    hint_sources = {p: t for p, h, t in files}
    all_events = list(heapq.merge(
        *[_re(p, YEAR, hint_host=hint_hosts.get(p),
              hint_source=hint_sources.get(p)) for p, _, _ in files],
        key=lambda e: e['ts']
    ))

# ---------------------------------------------------------------------------
# ML Training & Scoring
# ---------------------------------------------------------------------------
print('[3/4] Training Machine Learning Models (Isolation Forest & Random Forest) …')
iforest = MLDetector(kind='iforest', min_events=5)
iforest.fit(all_events)

rf = MLDetector(kind='rf', min_events=5)
rf.fit(all_events, attackers=attacker_ips if attacker_ips else None, augment=bool(attacker_ips))

print('[4/4] Scoring 5-minute traffic windows …')
def score_windows(ml_model, events):
    from siem.ml import _Win
    cur, wins, rows = None, {}, []
    for e in events:
        if not e['src_ip']:
            continue
        b = e['ts'] // ml_model.window
        if b != cur:
            if cur is not None:
                for ip, w in wins.items():
                    if w.n >= ml_model.min_events:
                        rows.append((ip, w.vector()))
            cur, wins = b, {}
        wins.setdefault(e['src_ip'], _Win()).add(e)
    if cur is not None:
        for ip, w in wins.items():
            if w.n >= ml_model.min_events:
                rows.append((ip, w.vector()))
    if not rows:
        return np.array([]), np.array([])
    ips, vecs = zip(*rows)
    X = np.array(vecs)
    if ml_model.kind == 'rf':
        scores = ml_model.model.predict_proba(X)[:, 1]
    else:
        scores = -ml_model.model.score_samples(X)
    y_true = np.array([ip.split('~')[0] in attacker_ips for ip in ips])
    return y_true, scores

y_true_if, scores_if = score_windows(iforest, all_events)
y_true_rf, scores_rf = score_windows(rf, all_events)

y_pred_if = (scores_if > iforest.threshold).astype(int) if len(scores_if) else np.array([])
y_pred_rf = (scores_rf > rf.threshold).astype(int) if len(scores_rf) else np.array([])

rule_alerts = store.alerts(limit=1_000_000)
rule_alerted = {a['src_ip'] for a in rule_alerts if a['src_ip']}
db_stats = store.stats()

print('\n======================================================')
print(' Displaying 8 AIML Charts (Close each window to see next)')
print('======================================================\n')

# ── Chart 1: Event Timeline ──────────────────────────────────────────────────
print('Plotting Chart 1: Event Timeline …')
timeline = store.timeline(bucket=300)
if timeline:
    import datetime
    ts_vals = [datetime.datetime.utcfromtimestamp(r['t']) for r in timeline]
    n_vals  = [r['n'] for r in timeline]
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.fill_between(ts_vals, n_vals, alpha=0.35, color='steelblue')
    ax.plot(ts_vals, n_vals, color='steelblue', linewidth=1, label='Events / 5 min')
    if rule_alerts:
        atimes = [datetime.datetime.utcfromtimestamp(a['ts']) for a in rule_alerts]
        for at in atimes:
            ax.axvline(at, color='red', alpha=0.25, linewidth=0.8)
        ax.axvline(atimes[0], color='red', alpha=0.7, linewidth=1,
                   label=f'Rule alerts ({len(atimes)} total)')
    ax.set_title('LightSIEM — Event Timeline with Rule-Based Alerts', fontsize=13)
    ax.set_xlabel('Time (UTC)'); ax.set_ylabel('Events per 5-min bucket')
    ax.legend(); fig.tight_layout(); plt.show()

# ── Chart 2: Events by Category ─────────────────────────────────────────────
print('Plotting Chart 2: Events by Category …')
cats = db_stats.get('categories', {})
if cats:
    lbls_c = sorted(cats, key=cats.get, reverse=True)
    vals_c = [cats[k] for k in lbls_c]
    fig, ax = plt.subplots(figsize=(9, 4))
    bars = ax.bar(lbls_c, vals_c, color=sns.color_palette('muted', len(lbls_c)))
    ax.bar_label(bars, fmt='%d', padding=3, fontsize=8)
    ax.set_title('Events Ingested — Breakdown by Log Category')
    ax.set_xlabel('Category'); ax.set_ylabel('Event Count')
    ax.set_yscale('log')
    plt.xticks(rotation=30, ha='right'); fig.tight_layout(); plt.show()

# ── Chart 3: Top 10 Source IPs ───────────────────────────────────────────────
print('Plotting Chart 3: Top Source IPs …')
top_ips = store.top_ips(limit=10)
if top_ips:
    ip_lbs = [r['ip'] for r in top_ips]
    ip_cnt = [r['n']  for r in top_ips]
    colors = ['#e74c3c' if ip in attacker_ips else '#3498db' for ip in ip_lbs]
    fig, ax = plt.subplots(figsize=(9, 4))
    bars = ax.barh(ip_lbs[::-1], ip_cnt[::-1], color=colors[::-1])
    ax.bar_label(bars, fmt='%d', padding=3, fontsize=8)
    ax.set_title('Top 10 Source IPs  (red = confirmed attacker)')
    ax.set_xlabel('Total Events'); fig.tight_layout(); plt.show()

# ── Chart 4: Feature Importance (Random Forest) ──────────────────────────────
print('Plotting Chart 4: Feature Importance …')
imps   = rf.model.feature_importances_
order  = np.argsort(imps)
fig, ax = plt.subplots(figsize=(8, 4))
ax.barh([FEATURES[i] for i in order], imps[order],
        color=sns.color_palette('viridis', len(FEATURES)))
ax.set_title('Random Forest — Feature Importances\n(which network behaviour signals "attack"?)')
ax.set_xlabel('Importance'); fig.tight_layout(); plt.show()

# ── Chart 5: Confusion Matrix (Random Forest) ────────────────────────────────
print('Plotting Chart 5: Confusion Matrix …')
if len(y_true_rf) > 0 and len(np.unique(y_true_rf)) > 1:
    cm_rf = confusion_matrix(y_true_rf, y_pred_rf)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm_rf, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'], ax=ax)
    ax.set_title('Random Forest — Confusion Matrix\n(5-minute traffic windows)')
    ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
    fig.tight_layout(); plt.show()
else:
    print('      (Skipping CM — only one class in ground truth for this slice)')

# ── Chart 6: ROC Curve (IF vs RF) ────────────────────────────────────────────
print('Plotting Chart 6: ROC Curves …')
fig, ax = plt.subplots(figsize=(7, 6))
ax.plot([0, 1], [0, 1], linestyle='--', color='grey', label='Random baseline')
drawn = False
for label, yt, ys in [('Isolation Forest (unsupervised)', y_true_if, scores_if),
                       ('Random Forest  (supervised)',     y_true_rf, scores_rf)]:
    if len(yt) == 0 or len(np.unique(yt)) < 2:
        continue
    mn, mx = ys.min(), ys.max()
    ys_n = (ys - mn) / (mx - mn + 1e-9)
    fpr, tpr, _ = roc_curve(yt, ys_n)
    auc = roc_auc_score(yt, ys_n)
    ax.plot(fpr, tpr, lw=2, label=f'{label}  (AUC = {auc:.2f})')
    drawn = True
if drawn:
    ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate (Recall)')
    ax.set_title('ROC Curve — Isolation Forest vs Random Forest')
    ax.legend(loc='lower right'); fig.tight_layout(); plt.show()
else:
    print('      (Skipping ROC — single class in ground truth)')
    plt.close(fig)

# ── Chart 7: Precision / Recall / F1 ─────────────────────────────────────────
print('Plotting Chart 7: Precision / Recall / F1 …')
all_known_ips = rule_alerted | attacker_ips
ip_list = sorted(all_known_ips)
yt_rule = np.array([ip in attacker_ips for ip in ip_list])
yp_rule = np.array([ip in rule_alerted for ip in ip_list])

metrics = {
    'Rules only':       [safe_metric(precision_score, yt_rule,  yp_rule,  zero_division=0),
                         safe_metric(recall_score,    yt_rule,  yp_rule,  zero_division=0),
                         safe_metric(f1_score,        yt_rule,  yp_rule,  zero_division=0)],
    'Isolation Forest': [safe_metric(precision_score, y_true_if, y_pred_if, zero_division=0),
                         safe_metric(recall_score,    y_true_if, y_pred_if, zero_division=0),
                         safe_metric(f1_score,        y_true_if, y_pred_if, zero_division=0)],
    'Random Forest':    [safe_metric(precision_score, y_true_rf, y_pred_rf, zero_division=0),
                         safe_metric(recall_score,    y_true_rf, y_pred_rf, zero_division=0),
                         safe_metric(f1_score,        y_true_rf, y_pred_rf, zero_division=0)],
}
x_pos = np.arange(3); bar_w = 0.25
fig, ax = plt.subplots(figsize=(9, 5))
for i, (name, vals) in enumerate(metrics.items()):
    ax.bar(x_pos + i * bar_w, vals, bar_w,
           label=name, color=['#2ecc71','#3498db','#e74c3c'][i], alpha=0.85)
    for j, v in enumerate(vals):
        ax.text(x_pos[j] + i * bar_w, v + 0.01, f'{v:.2f}',
                ha='center', va='bottom', fontsize=8)
ax.set_xticks(x_pos + bar_w)
ax.set_xticklabels(['Precision', 'Recall', 'F1 Score'])
ax.set_ylim(0, 1.15)
ax.set_title('Detection Performance — Rules vs Isolation Forest vs Random Forest')
ax.set_ylabel('Score'); ax.legend(); fig.tight_layout(); plt.show()

# ── Chart 8: Anomaly Score Distribution (Isolation Forest) ───────────────────
print('Plotting Chart 8: Anomaly Score Distribution …')
if len(scores_if) > 0:
    fig, ax = plt.subplots(figsize=(8, 4))
    if len(np.unique(y_true_if)) > 1:
        ax.hist(scores_if[y_true_if == 0], bins=40, alpha=0.65,
                color='steelblue', label='Normal windows')
        ax.hist(scores_if[y_true_if == 1], bins=20, alpha=0.80,
                color='tomato',    label='Attack windows')
    else:
        ax.hist(scores_if, bins=40, alpha=0.65, color='steelblue', label='All windows')
    ax.axvline(iforest.threshold, color='black', linestyle='--', linewidth=1.5,
               label=f'Detection threshold ({iforest.threshold:.3f})')
    ax.set_title('Isolation Forest — Anomaly Score Distribution\n(windows right of threshold are flagged suspicious)')
    ax.set_xlabel('Anomaly Score')
    ax.set_ylabel('5-min Windows Count')
    ax.legend(); fig.tight_layout(); plt.show()

print('\n✓ Demonstration complete!')
