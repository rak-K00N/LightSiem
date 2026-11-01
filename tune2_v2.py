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

def flagged2(wp, lo, hi, persist=2):
    """strong evidence (P>=hi) alerts at once; weaker evidence (P>=lo) needs `persist` consecutive windows"""
    res, by = set(), {}
    for ip, b, p in wp:
        if p >= hi: res.add(ip)
        if p >= lo: by.setdefault(ip, []).append(b)
    for ip, bs in by.items():
        bs = sorted(set(bs)); run = 1
        for a, c in zip(bs, bs[1:]):
            run = run + 1 if c == a + 1 else 1
            if run >= persist: res.add(ip); break
    return res
wt, wc = window_probs(test), window_probs(ctl)
uni = {e['src_ip'] for e in base if e['src_ip']}
grid = [ip for ip, v in meta.items() if v[0] == 'grid']; held = [ip for ip, v in meta.items() if v[0] != 'grid']
print(f'{"lo":>4} {"hi":>4} {"persist":>7} | grid held | testFP ctlFP | orig-recall')
out = []
for lo, hi, per in [(0.5,1.01,1),(0.6,1.01,1)] + [(lo, hi, per) for per in (2, 3) for lo in (0.3, 0.4, 0.5, 0.6) for hi in (0.8, 0.9)]:
    a = flagged2(wt, lo, hi, per); c = flagged2(wc, lo, hi, per)
    g = sum(ip in a for ip in grid) / len(grid); h = sum(ip in a for ip in held) / len(held)
    fp_t = len((a & uni) - pos); fp_c = len(c); orig = len(a & pos) / len(pos); out.append((lo, hi, per, g, h, fp_t, fp_c, orig))
    print(f'{lo:4.1f} {min(hi,1):4.2f} {per:7d} | {g:.3f} {h:.3f} | {fp_t:6d} {fp_c:5d} | {orig:.3f}')
json.dump(out, open('tune2_v2.json', 'w'))
