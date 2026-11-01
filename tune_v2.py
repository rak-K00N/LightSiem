import json, os, sys, shutil, heapq, itertools, time
sys.path.insert(0, '.')
import numpy as np
from siem.gen_logs import generate
from siem.ml import MLDetector, _Win
from v2lib import inject, load, D, STD
SEED = 6
shutil.rmtree(D, ignore_errors=True)
for name, kw in (('train_lab', dict(seed=SEED, attacks=True, crawlers=True)), ('test', dict(seed=SEED + 100, hard=True)), ('control', dict(seed=SEED + 200, attacks=False, crawlers=True))):
    generate(f'{D}/{name}', **kw)
tl = json.load(open(f'{D}/train_lab/truth.json')); bad = {ip for k in STD[:4] for ip in tl[k]}
tt = json.load(open(f'{D}/test/truth.json')); pos = {ip for k in STD for ip in tt[k]}
lab, base, ctl = load('train_lab'), load('test'), load('control'); test, meta = inject(base, SEED)
m = MLDetector(kind='rf'); m.fit(lab, bad, augment=True)

def window_probs(events):
    """[(ip, bucket, P(attack))] for every scored window"""
    out, cur, wins = [], None, {}
    def close():
        items = [(ip, w) for ip, w in wins.items() if w.n >= m.min_events]
        if items:
            p = m._suspicion(np.array([w.vector() for _, w in items]))
            out.extend((ip, cur, float(x)) for (ip, _), x in zip(items, p))
    for e in events:
        if not e['src_ip']: continue
        b = e['ts'] // m.window
        if cur is None: cur = b
        elif b != cur: close(); wins = {}; cur = b
        wins.setdefault(e['src_ip'], _Win()).add(e)
    close(); return out
def flagged(wp, thr, persist):
    by = {}
    for ip, b, p in wp:
        if p >= thr: by.setdefault(ip, []).append(b)
    res = set()
    for ip, bs in by.items():
        bs = sorted(bs); run = 1
        if persist <= 1: res.add(ip); continue
        for a, c in zip(bs, bs[1:]):
            run = run + 1 if c == a + 1 else 1
            if run >= persist: res.add(ip); break
    return res
wt, wc = window_probs(test), window_probs(ctl)
cr_ctl = set(json.load(open(f'{D}/control/truth.json'))['legit_crawlers']); crawlers = set(tt['legit_crawlers'])
uni = {e['src_ip'] for e in base if e['src_ip']}
grid = [ip for ip, v in meta.items() if v[0] == 'grid']; held = [ip for ip, v in meta.items() if v[0] != 'grid']
print(f'{"thr":>5} {"persist":>7} | grid-recall held-recall | test FP (legit IPs) | control FP | orig recall')
rows = []
for thr, per in itertools.product((0.5, 0.6, 0.7, 0.8, 0.9), (1, 2, 3)):
    a = flagged(wt, thr, per); c = flagged(wc, thr, per)
    g = sum(ip in a for ip in grid) / len(grid); h = sum(ip in a for ip in held) / len(held)
    fp_t = len((a & uni) - pos); fp_c = len(c); orig = len(a & pos) / len(pos)
    rows.append((thr, per, g, h, fp_t, fp_c, orig)); print(f'{thr:5.1f} {per:7d} | {g:11.3f} {h:11.3f} | {fp_t:18d} | {fp_c:10d} | {orig:.3f}')
json.dump(rows, open('tune_v2.json', 'w'))
