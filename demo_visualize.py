#!/usr/bin/env python3
"""
LightSIEM – Visual Demo  (matplotlib charts, runs inline in VSCode)
====================================================================
THREE ways to run — pick the fastest one for your situation:

  MODE A – Built-in synthetic logs (FASTEST, ~5 seconds, no real data needed)
  -------------------------------------------------------------------------
  python demo_visualize.py --demo

  MODE B – Use an already-ingested database (FAST, skips all ingestion)
  -------------------------------------------------------------------------
  python demo_visualize.py --db rm.db --skip-ingest

  MODE C – Ingest a small slice of the Russell Mitchell dataset first
  -------------------------------------------------------------------------
  python demo_visualize.py "/run/media/faang/UBUNTU 26_0/lightsiem data/russellmitchell" \\
      --host intranet_server --db rm_demo.db

  Tip: run MODE C once to build the .db file, then use MODE B every time after.

Charts produced (same style as your AIML lab programs):
  1  Event timeline with alert markers
  2  Events per log category  (bar chart)
  3  Top 10 source IPs  (horizontal bar, attackers in red)
  4  Feature importance  (Random Forest)
  5  Confusion Matrix    (Random Forest)
  6  ROC Curve           (Isolation Forest vs Random Forest)
  7  Precision / Recall / F1  (Rules vs IF vs RF)
  8  Anomaly score distribution  (Isolation Forest)
"""

import argparse, os, sys, shutil, heapq, warnings
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

# ─────────────────────────── CLI ────────────────────────────────────────────
ap = argparse.ArgumentParser(description='LightSIEM – Visual Demo')
ap.add_argument('root', nargs='?',
                help='Russell Mitchell dataset root (optional; omit with --demo)')
ap.add_argument('--demo',  action='store_true',
                help='Use built-in synthetic logs — no real dataset needed')
ap.add_argument('--db',    default=':memory:',
                help='SQLite database (default: in-memory). '
                     'Point to an existing .db file with --skip-ingest to avoid re-ingesting.')
ap.add_argument('--skip-ingest', action='store_true',
                help='Do NOT ingest; use whatever is already in --db. '
                     'Great for re-running charts after a previous ingest.')
ap.add_argument('--host',  action='append', dest='hosts',  metavar='HOST')
ap.add_argument('--type',  action='append', dest='types',  metavar='TYPE')
ap.add_argument('--year',  type=int, default=2022)
args = ap.parse_args()

# ─────────────────────────── helpers ────────────────────────────────────────
def safe_metric(fn, yt, yp, **kw):
    try:
        return fn(yt, yp, **kw)
    except Exception:
        return 0.0


def score_windows(ml_model, all_events, attacker_ips):
    """Return y_true and suspicion scores for every 5-min window."""
    from siem.ml import _Win
    cur, wins, rows = None, {}, []
    for e in all_events:
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


# ════════════════════════════════════════════════════════════════════════════
#  STEP 1 – Get events into the Store
# ════════════════════════════════════════════════════════════════════════════
store = Store(args.db)

# ── MODE A: synthetic logs ───────────────────────────────────────────────────
if args.demo:
    print('\n[MODE A] Generating synthetic attack logs …')
    from siem.gen_logs import generate
    import json as _json
    TMPDIR = '/tmp/lightsiem_demo_logs'
    shutil.rmtree(TMPDIR, ignore_errors=True)
    generate(TMPDIR, seed=7, scale=0.3, attacks=True, crawlers=True)
    truth = _json.load(open(f'{TMPDIR}/truth.json'))
    YEAR  = 2026
    FILES = [f'{TMPDIR}/auth.log', f'{TMPDIR}/access.log']

    from siem.ingest import ingest, read_events as _re
    det   = Detector()
    stats = ingest(FILES, store, det, YEAR)
    all_events = list(heapq.merge(*[_re(p, YEAR) for p in FILES],
                                  key=lambda e: e['ts']))

    ATTACK_TYPES = ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan')
    attacker_ips = {ip for k in ATTACK_TYPES for ip in truth.get(k, [])}
    print(f'      {stats["events"]:,} events  |  {store.stats()["alerts"]:,} rule alerts')
    print(f'      Ground-truth attacker IPs ({len(attacker_ips)}): {sorted(attacker_ips)[:5]} …')

# ── MODE B: re-use existing DB, skip ingest ──────────────────────────────────
elif args.skip_ingest:
    if args.db == ':memory:':
        sys.exit('ERROR: --skip-ingest requires --db pointing to an existing file, not :memory:')
    db_stats = store.stats()
    if db_stats['events'] == 0:
        sys.exit(f'ERROR: database "{args.db}" is empty. Run without --skip-ingest first.')
    print(f'\n[MODE B] Using existing database "{args.db}"')
    print(f'         {db_stats["events"]:,} events  |  {db_stats["alerts"]:,} alerts already stored')

    # We still need an event stream for ML — re-read from whatever files we can find.
    # For MODE B we train on stored events by reconstructing from the DB.
    # (Simplified: use all stored events as proxies for window building.)
    all_events = store.search(limit=2_000_000)   # list of dicts from DB
    # DB rows don't have 'raw' but MLDetector._Win only uses ts/src_ip/category/status/msg
    attacker_ips = set()   # unknown without labels — charts will show scores only
    YEAR = args.year
    print('      NOTE: attacker IPs unknown in MODE B (no label files). '
          'Confusion matrix / ROC skipped; all other charts shown.')

# ── MODE C: ingest a Russell slice ───────────────────────────────────────────
else:
    if not args.root:
        ap.error('Provide a dataset root path, or use --demo / --skip-ingest')

    from siem.russell import collect_log_files, load_labels, ingest_dataset
    from siem.ingest import read_events as _re

    # Check if DB already has data to avoid re-ingesting accidentally
    existing = store.stats()['events']
    if existing > 0 and args.db != ':memory:':
        print(f'\n[MODE C] Database "{args.db}" already has {existing:,} events.')
        ans = input('         Skip ingestion and use existing data? [Y/n]: ').strip().lower()
        if ans in ('', 'y', 'yes'):
            args.skip_ingest = True

    YEAR = args.year

    if not args.skip_ingest:
        print(f'\n[MODE C] Ingesting Russell Mitchell slice …')
        det   = Detector()
        stats = ingest_dataset(args.root, store, detector=det, year=YEAR,
                               host_filter=args.hosts, type_filter=args.types)
        print(f'      {stats["events"]:,} events  |  {store.stats()["alerts"]:,} rule alerts  '
              f'|  {stats["events_per_sec"]:,.0f} eps')

    # Build event stream for ML
    files = collect_log_files(args.root)
    if args.hosts:
        files = [(p, h, t) for p, h, t in files if h in args.hosts]
    if args.types:
        files = [(p, h, t) for p, h, t in files if t in args.types]
    hint_hosts   = {p: h for p, h, t in files}
    hint_sources = {p: t for p, h, t in files}
    all_events = list(heapq.merge(
        *[_re(p, YEAR, hint_host=hint_hosts.get(p),
              hint_source=hint_sources.get(p)) for p, _, _ in files],
        key=lambda e: e['ts']))

    # Ground-truth attacker IPs from label files
    all_labels   = load_labels(args.root)
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
    print(f'      {len(attacker_ips)} attacker IP(s): {sorted(attacker_ips)}')


# ════════════════════════════════════════════════════════════════════════════
#  STEP 2 – Train ML models  (always fast: runs on in-memory windows)
# ════════════════════════════════════════════════════════════════════════════
print('\n[ML] Training Isolation Forest (unsupervised) …')
iforest = MLDetector(kind='iforest', min_events=5)
iforest.fit(all_events)

print('[ML] Training Random Forest (supervised) …')
rf = MLDetector(kind='rf', min_events=5)
rf.fit(all_events, attackers=attacker_ips if attacker_ips else None, augment=bool(attacker_ips))

print('[ML] Scoring 5-minute traffic windows …')
y_true_if, scores_if = score_windows(iforest, all_events, attacker_ips)
y_true_rf, scores_rf = score_windows(rf,       all_events, attacker_ips)

y_pred_if = (scores_if > iforest.threshold).astype(int) if len(scores_if) else np.array([])
y_pred_rf = (scores_rf > rf.threshold).astype(int)      if len(scores_rf) else np.array([])

rule_alerts  = store.alerts(limit=1_000_000)
rule_alerted = {a['src_ip'] for a in rule_alerts if a['src_ip']}
db_stats     = store.stats()


# ════════════════════════════════════════════════════════════════════════════
#  STEP 3 – CHARTS
# ════════════════════════════════════════════════════════════════════════════
total_charts = 8
print(f'\nShowing {total_charts} charts — close each window to see the next.\n')

# ── Chart 1: Event Timeline ──────────────────────────────────────────────────
print('Chart 1/8 – Event Timeline')
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
print('Chart 2/8 – Events by Category')
cats = db_stats.get('categories', {})
if cats:
    lbls_c = sorted(cats, key=cats.get, reverse=True)
    vals_c = [cats[k] for k in lbls_c]
    fig, ax = plt.subplots(figsize=(9, 4))
    bars = ax.bar(lbls_c, vals_c, color=sns.color_palette('muted', len(lbls_c)))
    ax.bar_label(bars, fmt='%d', padding=3, fontsize=8)
    ax.set_title('Events Ingested — Breakdown by Log Category')
    ax.set_xlabel('Category'); ax.set_ylabel('Event Count (log scale)')
    ax.set_yscale('log')
    plt.xticks(rotation=30, ha='right'); fig.tight_layout(); plt.show()

# ── Chart 3: Top 10 Source IPs ───────────────────────────────────────────────
print('Chart 3/8 – Top Source IPs')
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
print('Chart 4/8 – Feature Importance')
imps   = rf.model.feature_importances_
order  = np.argsort(imps)
fig, ax = plt.subplots(figsize=(8, 4))
ax.barh([FEATURES[i] for i in order], imps[order],
        color=sns.color_palette('viridis', len(FEATURES)))
ax.set_title('Random Forest — Feature Importances\n(which network behaviour signals "attack"?)')
ax.set_xlabel('Importance'); fig.tight_layout(); plt.show()

# ── Chart 5: Confusion Matrix (Random Forest) ────────────────────────────────
print('Chart 5/8 – Confusion Matrix')
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
    print('      (Skipped — need both attacker and normal windows to draw CM)')

# ── Chart 6: ROC Curve (IF vs RF) ────────────────────────────────────────────
print('Chart 6/8 – ROC Curves')
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
    print('      (Skipped — need labelled attacker data for ROC)')
    plt.close(fig)

# ── Chart 7: Precision / Recall / F1 ─────────────────────────────────────────
print('Chart 7/8 – Precision / Recall / F1')
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
print('Chart 8/8 – Anomaly Score Distribution')
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
    ax.set_title('Isolation Forest — Anomaly Score Distribution\n'
                 '(windows to the right of the threshold are flagged as suspicious)')
    ax.set_xlabel('Anomaly Score  (higher = more suspicious)')
    ax.set_ylabel('Number of 5-minute Windows')
    ax.legend(); fig.tight_layout(); plt.show()

print('\n✓ All charts done!')
if args.db != ':memory:':
    print(f'  Database saved at: {args.db}')
    print(f'  Next time, run:  python demo_visualize.py --db {args.db} --skip-ingest')
