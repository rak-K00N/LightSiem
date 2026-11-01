#!/usr/bin/env python3
"""ML evaluation. Train on a known-good day, test on a DIFFERENT day (different seed, new IPs), plus a clean control day."""
import json, os, sys, shutil, subprocess, heapq, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from siem.gen_logs import generate
from siem.ingest import read_events
from siem.detect import Detector
from siem.ml import MLDetector

D = 'eval_ml'; shutil.rmtree(D, ignore_errors=True)
SETS = {'train_plain': dict(seed=11, attacks=False), 'train_crawl': dict(seed=11, attacks=False, crawlers=True),
        'train_labelled': dict(seed=11, attacks=True, crawlers=True),   # standard attacks + crawlers, but NO stealth scanners
        'test': dict(seed=7, hard=True), 'control': dict(seed=13, attacks=False, crawlers=True)}
for n, kw in SETS.items(): generate(f'{D}/{n}', **kw)
P = lambda d: [f'{D}/{d}/auth.log', f'{D}/{d}/access.log']
ev = lambda d: heapq.merge(*[read_events(p, 2026) for p in P(d)], key=lambda e: e['ts'])
truth = json.load(open(f'{D}/test/truth.json'))
TYPES = ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan', 'stealth_scan')
pos = {ip for k in TYPES for ip in truth[k]}; crawlers = set(truth['legit_crawlers'])

def alert_ips(det_factory, day):
    det, out = det_factory(), []
    for e in ev(day): out += det.process(e)
    out += det.finish(); return {a['src_ip'] for a in out if a['src_ip']}, out
def prf(pred):
    tp, fp, fn = len(pred & pos), len(pred - pos), len(pos - pred); p = tp / (tp + fp) if tp + fp else 0.0; r = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, precision=round(p, 3), recall=round(r, 3), f1=round(2 * p * r / (p + r), 3) if p + r else 0.0, crawlers_flagged=len(pred & crawlers))
rec = lambda s: {k: f'{len(set(truth[k]) & s)}/{len(truth[k])}' for k in TYPES}

rules_ips, _ = alert_ips(Detector, 'test')
VARIANTS = {'A: Isolation Forest (unsupervised), plain normal day': ('train_plain', 5, 'iforest'), 'B: Isolation Forest, normal day incl. crawlers': ('train_crawl', 5, 'iforest'),
            'C: Random Forest (supervised), labelled day': ('train_labelled', 5, 'rf')}
res = dict(test_set=dict(events=sum(1 for _ in ev('test')), attackers=len(pos), stealth_scanners_invisible_to_rules=10, legit_crawlers=len(crawlers)),
           rules_only=dict(prf(rules_ips), recall_by_type=rec(rules_ips)), variants={})
models = {}
for name, (tr, me, kind) in VARIANTS.items():
    bad = None
    if kind == 'rf':
        t = json.load(open(f'{D}/{tr}/truth.json')); bad = {ip for k in ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan') for ip in t[k]}
    m = MLDetector(min_events=me, kind=kind); t0 = time.perf_counter(); info = m.fit(ev(tr), bad); info['training_seconds'] = round(time.perf_counter() - t0, 1)
    def clone(m=m):
        d = MLDetector(min_events=m.min_events, kind=m.kind); d.model, d.threshold = m.model, m.threshold; return d
    ml_ips, _ = alert_ips(clone, 'test'); ctl_ips, ctl_alerts = alert_ips(clone, 'control')
    res['variants'][name] = dict(training=info, ml_only=dict(prf(ml_ips), recall_by_type=rec(ml_ips)),
                                 rules_plus_ml=dict(prf(rules_ips | ml_ips), recall_by_type=rec(rules_ips | ml_ips)),
                                 control_day_false_alert_ips=len(ctl_ips), control_day_events=sum(1 for _ in ev('control')))
    models[name] = m
# ---- evasion test: a scanner that lowers its 404 rate to blend in (15 req/min for 20 min, distinct URLs) ----
import random
def mimic(ratio):
    R, evs = random.Random(1), []
    for k in range(300):
        st = 404 if R.random() < ratio else 200
        evs.append(dict(ts=1789430400 + k * 4, host='web', source='nginx', category='http', severity='info', src_ip='9.9.9.9', user=None, status=st, msg=f'GET /p{R.randint(0, 9999)} {st}', raw=''))
    return evs
def detects(det, evs):
    out = []
    for e in evs: out += det.process(e)
    return bool(out + det.finish())
fin = models['C: Random Forest (supervised), labelled day']; ia = models['A: Isolation Forest (unsupervised), plain normal day']
def cl(m):
    d = MLDetector(min_events=m.min_events, kind=m.kind); d.model, d.threshold = m.model, m.threshold; return d
res['evasion_404_rate'] = {f'{int(r*100)}% 404s': dict(rules=detects(Detector(), mimic(r)), isolation_forest=detects(cl(ia), mimic(r)), random_forest=detects(cl(fin), mimic(r))) for r in (0.85, 0.6, 0.4, 0.25, 0.15, 0.08)}
FINAL = list(VARIANTS)[int(os.environ.get('FINAL', 2))]; models[FINAL].save(f'{D}/model.pkl')

def run(db, model=None):
    cmd = [sys.executable, 'lightsiem.py', 'ingest', *P('test'), '--db', f'{D}/{db}'] + (['--model', f'{D}/model.pkl'] if model else [])
    return json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1])
res['final_variant'] = FINAL; res['performance'] = dict(rules_only=run('r.db'), rules_plus_ml=run('m.db', True))
json.dump(res, open('results_ml.json', 'w'), indent=1); print(json.dumps(res, indent=1))
