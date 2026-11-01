#!/usr/bin/env python3
"""v2 benchmark: does evasion-aware training make the supervised detector better?
For each random seed: train on separate days, test on an unseen day into which 300 EVASIVE scanners are injected
(5 error-rate levels x 3 request-rate levels x 20 scanners), plus the original 54-attacker test and a clean control day.
Usage: python evaluate_v2.py [n_seeds]  or  python evaluate_v2.py FIRST LAST  (results accumulate in results_v2_raw.json)"""
import json, os, sys, shutil, heapq, random, time, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from siem.gen_logs import generate, SCAN
from siem.ingest import read_events
from siem.detect import Detector
from siem.ml import MLDetector

A, B = 1, 1
RATIOS = (0.85, 0.60, 0.40, 0.25, 0.15); RATES = (3, 6, 15)          # share of 404s ; requests per minute
D = 'eval_v2'
STD = ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan', 'stealth_scan')

def load(d): return list(heapq.merge(*[read_events(f'{D}/{d}/{f}', 2026) for f in ('auth.log', 'access.log')], key=lambda e: e['ts']))
def stream(factory, events):
    det, ips = factory(), set()
    for e in events:
        for a in det.process(e):
            if a['src_ip']: ips.add(a['src_ip'])
    for a in det.finish():
        if a['src_ip']: ips.add(a['src_ip'])
    return ips
def prf(pred, pos, universe):
    pred = pred & universe; tp, fp, fn = len(pred & pos), len(pred - pos), len(pos - pred)
    p = tp / (tp + fp) if tp + fp else 0.0; r = tp / (tp + fn) if tp + fn else 0.0
    return dict(precision=p, recall=r, f1=2 * p * r / (p + r) if p + r else 0.0, fp=fp)
def inject(base, seed):
    """Evasive scanners. 'grid' = dilution x slow-down (the kind augmentation covers).
    HELD-OUT tactics the augmentation never generates: 'reuse' (probes only 5 URLs, so few distinct URLs),
    'burst' (20 requests in 20 s, then silence for 4+ minutes) and 'ultraslow' (1 request/min)."""
    R, used, ev, meta, k = random.Random(seed), {e['src_ip'] for e in base if e['src_ip']}, [], {}, [0]
    def new_ip():
        k[0] += 1; ip = f'150.{k[0] // 250}.{k[0] % 250}.{(k[0] * 7) % 250 + 1}'; assert ip not in used; return ip
    def req(ip, t, ratio, path):
        st = 404 if R.random() < ratio else 200
        ev.append(dict(ts=t, host='web', source='nginx', category='http', severity='info', src_ip=ip, user=None, status=st, msg=f'GET {path} {st}', raw=''))
    rpath = lambda: '/' + R.choice(SCAN + ['x', 'a', 'q']) + str(R.randint(0, 9999))
    for ratio in RATIOS:
        for rate in RATES:
            for _ in range(20):
                ip = new_ip(); t0 = 1789430400 + R.randint(3600, 80000); meta[ip] = ('grid', ratio, rate)
                for j in range(int(rate * 20)): req(ip, t0 + int(j * 60 / rate) + R.randint(0, 2), ratio, rpath())
    for ratio in (0.85, 0.60, 0.40):                                   # reuse: only 5 distinct URLs
        for _ in range(20):
            ip = new_ip(); t0 = 1789430400 + R.randint(3600, 80000); meta[ip] = ('reuse', ratio, 15); paths = [rpath() for _ in range(5)]
            for j in range(300): req(ip, t0 + j * 4, ratio, R.choice(paths))
    for ratio in (0.85, 0.60):                                         # burst and pause
        for _ in range(20):
            ip = new_ip(); t0 = 1789430400 + R.randint(3600, 80000); meta[ip] = ('burst', ratio, 4)
            for burst in range(6):
                for j in range(20): req(ip, t0 + burst * 300 + j, ratio, rpath())
    for _ in range(20):                                                # ultra slow
        ip = new_ip(); t0 = 1789430400 + R.randint(3600, 80000); meta[ip] = ('ultraslow', 0.85, 1)
        for j in range(40): req(ip, t0 + j * 60, 0.85, rpath())
    return sorted(base + ev, key=lambda e: e['ts']), meta

