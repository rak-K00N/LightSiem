#!/usr/bin/env python3
"""
LightSIEM – Visual Demo (runs in VSCode like your AIML lab programs)
=====================================================================
Shows 4 key AIML charts using the Russell Mitchell real-world cyber-attack dataset:
  Chart 1 – Event timeline with attack alerts overlaid
  Chart 2 – Feature importance (Random Forest, 13 features)
  Chart 3 – Confusion Matrix (Random Forest, 5-min traffic windows)
  Chart 4 – ROC curve (Random Forest vs Isolation Forest with AUC)

Option 1: 13 features (8 original + 5 new: path depth, webshell indicator,
          request rate, consecutive 404 ratio, POST ratio)
Option 4: Multi-host ingestion (intranet_server + webserver + mail + internal_share)
          for richer normal-traffic baseline and better ML discrimination.

Usage
-----
  # 1. Default (all 4 hosts, full ML):
  python demo_visualize.py

  # 2. Instant synthetic demo (~5 sec, no dataset):
  python demo_visualize.py --demo

  # 3. Skip re-ingestion, reuse cached DB:
  python demo_visualize.py --skip-ingest

  # 4. Single host only:
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
    hosts = args.hosts or ['intranet_server', 'webserver', 'mail', 'internal_share']  # Option 4: all hosts with HTTP/auth logs

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
print('[3/4] Training Supervised Random Forest Model (13 features) …')
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
    scores = ml_model.model.predict_proba(X)[:, 1]
    y_true = np.array([ip.split('~')[0] in attacker_ips for ip in ips])
    return y_true, scores

y_true_rf, scores_rf = score_windows(rf, all_events)
y_pred_rf = (scores_rf > rf.threshold).astype(int) if len(scores_rf) else np.array([])

rule_alerts = store.alerts(limit=1_000_000)
rule_alerted = {a['src_ip'] for a in rule_alerts if a['src_ip']}
db_stats = store.stats()

print('\n======================================================')
print(' Displaying 4 Key AIML Charts (Close each window to see next)')
print('======================================================\n')

# ── Chart 1: Event Timeline with Alerts ──────────────────────────────────────
print('Plotting Chart 1/4: Security Event Timeline & Attack Alerts …')
timeline = store.timeline(bucket=300)
if timeline:
    import datetime
    ts_vals = [datetime.datetime.utcfromtimestamp(r['t']) for r in timeline]
    n_vals  = [r['n'] for r in timeline]
    fig, ax = plt.subplots(figsize=(11, 4))
    ax.fill_between(ts_vals, n_vals, alpha=0.35, color='steelblue')
    ax.plot(ts_vals, n_vals, color='steelblue', linewidth=1.2, label='Total Log Events / 5 min')
    if rule_alerts:
        atimes = [datetime.datetime.utcfromtimestamp(a['ts']) for a in rule_alerts]
        for at in atimes:
            ax.axvline(at, color='red', alpha=0.35, linewidth=1.0)
        ax.axvline(atimes[0], color='red', alpha=0.8, linewidth=1.5,
                   label=f'Detected Attack Alerts ({len(atimes)} total)')
    ax.set_title('Chart 1: Network Traffic Timeline with Detected Attack Alerts', fontsize=12, fontweight='bold')
    ax.set_xlabel('Timestamp (UTC)')
    ax.set_ylabel('Events per 5-Minute Window')
    ax.legend(loc='upper right')
    fig.tight_layout()
    fig.savefig('assets/chart1_timeline.png', dpi=150, bbox_inches='tight')
    plt.close(fig)

# ── Chart 2: Feature Importance (Random Forest) ──────────────────────────────
print('Plotting Chart 2/4: Feature Importance (Explainable AI) …')
imps   = rf.model.feature_importances_
order  = np.argsort(imps)
fig, ax = plt.subplots(figsize=(9, 4.5))
bars = ax.barh([FEATURES[i] for i in order], imps[order],
               color=sns.color_palette('viridis', len(FEATURES)))
ax.bar_label(bars, fmt='%.3f', padding=4, fontsize=9)
ax.set_title('Chart 2: Random Forest — Feature Importances\n(Which behavioral features identify the attacker?)', fontsize=12, fontweight='bold')
ax.set_xlabel('Relative Importance Weight')
fig.tight_layout()
fig.savefig('assets/chart2_feature_importance.png', dpi=150, bbox_inches='tight')
plt.close(fig)

# ── Chart 3: Confusion Matrix (Random Forest) ────────────────────────────────
print('Plotting Chart 3/4: Confusion Matrix (Traffic Windows) …')
if len(y_true_rf) > 0 and len(np.unique(y_true_rf)) > 1:
    cm_rf = confusion_matrix(y_true_rf, y_pred_rf)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    sns.heatmap(cm_rf, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Normal Traffic', 'Attack Activity'],
                yticklabels=['Normal Traffic', 'Attack Activity'], ax=ax,
                annot_kws={"size": 13, "weight": "bold"})
    ax.set_title('Chart 3: Confusion Matrix — Random Forest\n(Classification of 5-Minute Time Windows)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Predicted Label', fontweight='bold')
    ax.set_ylabel('Actual Ground-Truth Label', fontweight='bold')
    fig.tight_layout()
    fig.savefig('assets/chart3_confusion_matrix.png', dpi=150, bbox_inches='tight')
    plt.close(fig)
else:
    print('      (Note: Single class window slice; plotting IP-level breakdown)')

# ── Chart 4: ROC Curve (Random Forest) ───────────────────────────────────────
print('Plotting Chart 4/4: ROC Curve & AUC …')
fig, ax = plt.subplots(figsize=(7.5, 5.5))
ax.plot([0, 1], [0, 1], linestyle='--', color='grey', label='Random Guess Baseline (AUC = 0.50)')
if len(y_true_rf) > 0 and len(np.unique(y_true_rf)) >= 2:
    mn, mx = scores_rf.min(), scores_rf.max()
    ys_n = (scores_rf - mn) / (mx - mn + 1e-9)
    fpr, tpr, _ = roc_curve(y_true_rf, ys_n)
    auc = roc_auc_score(y_true_rf, ys_n)
    ax.plot(fpr, tpr, lw=2.5, color='forestgreen', label=f'Random Forest (AUC = {auc:.2f})')
    ax.fill_between(fpr, tpr, alpha=0.15, color='forestgreen')
    ax.set_xlabel('False Positive Rate (Fall-out)', fontweight='bold')
    ax.set_ylabel('True Positive Rate (Recall / Sensitivity)', fontweight='bold')
    ax.set_title('Chart 4: Receiver Operating Characteristic (ROC) — Random Forest', fontsize=12, fontweight='bold')
    ax.legend(loc='lower right', fontsize=11)
    fig.tight_layout()
    fig.savefig('assets/chart4_roc_curve.png', dpi=150, bbox_inches='tight')
plt.close(fig)

print('\n✓ Demonstration of 4 Key Charts Complete!')
