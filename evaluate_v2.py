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

A, B = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) > 2 else (1, int(sys.argv[1]) if len(sys.argv) > 1 else 3)   # seeds A..B; raw results accumulate
RATIOS = (0.85, 0.60, 0.40, 0.25, 0.15); RATES = (3, 6, 15)          # share of 404s ; requests per minute
D = 'eval_v2'; shutil.rmtree(D, ignore_errors=True)
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

results = json.load(open('results_v2_raw.json')) if A > 1 and os.path.exists('results_v2_raw.json') else []
for s in range(A, B + 1):
    t_start = time.time()
    for name, kw in (('train_plain', dict(seed=s, attacks=False)), ('train_lab', dict(seed=s, attacks=True, crawlers=True)),
                     ('test', dict(seed=s + 100, hard=True)), ('control', dict(seed=s + 200, attacks=False, crawlers=True))):
        generate(f'{D}/{name}', **kw)
    tl = json.load(open(f'{D}/train_lab/truth.json')); bad = {ip for k in STD[:4] for ip in tl[k]}
    tt = json.load(open(f'{D}/test/truth.json')); pos = {ip for k in STD for ip in tt[k]}; crawlers = set(tt['legit_crawlers'])
    plain, lab = load('train_plain'), load('train_lab'); base, ctl = load('test'), load('control')
    test, meta = inject(base, s)
    models = {}
    m = MLDetector(kind='iforest'); m.fit(plain); models['Isolation Forest'] = m
    m = MLDetector(kind='rf'); m.fit(lab, bad); models['Random Forest (v1)'] = m
    m1 = models['Random Forest (v1)']
    m = MLDetector(kind='rf'); m.fit(lab, bad, augment=True); models['Random Forest + evasion-aware (v2)'] = m
    def cl(m, thr=None):
        def make():
            d = MLDetector(kind=m.kind, min_events=m.min_events); d.model = m.model
            if thr is None: d.threshold, d.weak, d.persist = m.threshold, m.weak, m.persist
            else: d.threshold, d.weak, d.persist = thr, None, 1
            return d
        return make
    facts = {'Rules (v1)': Detector, 'Tight fixed rule (>=10 errors/60 s)': lambda: Detector(web_n=10)}
    facts.update({k: cl(v) for k, v in models.items()}); facts['Random Forest (v1, threshold 0.2)'] = cl(m1, 0.2)
    uni_orig = {e['src_ip'] for e in base if e['src_ip']}; ctl_crawlers = set(json.load(open(f'{D}/control/truth.json'))['legit_crawlers'])
    row = {}
    for name, f in facts.items():
        ips = stream(f, test); cips = stream(f, ctl)
        orig = prf(ips, pos, uni_orig)
        grid = {ip: v for ip, v in meta.items() if v[0] == 'grid'}
        ev_rate = {f'{int(r*100)}%/{q}': sum(1 for ip, v in grid.items() if v[1:] == (r, q) and ip in ips) / 20 for r in RATIOS for q in RATES}
        held = {t: sum(1 for ip, v in meta.items() if v[0] == t and ip in ips) / sum(1 for v in meta.values() if v[0] == t) for t in ('reuse', 'burst', 'ultraslow')}
        row[name] = dict(orig=orig, evasive_recall=sum(1 for ip in grid if ip in ips) / len(grid), by_cell=ev_rate, heldout=held,
                         crawlers_flagged=len(ips & crawlers), control_false_ips=len(cips), control_crawlers_flagged=len(cips & ctl_crawlers))
    # hybrids
    for hname, a, b in (('Rules + RF (v1)', 'Rules (v1)', 'Random Forest (v1)'), ('Rules + RF evasion-aware (v2)', 'Rules (v1)', 'Random Forest + evasion-aware (v2)')):
        ips = stream(facts[a], test) | stream(facts[b], test); cips = stream(facts[a], ctl) | stream(facts[b], ctl)
        grid = [ip for ip, v in meta.items() if v[0] == 'grid']
        row[hname] = dict(orig=prf(ips, pos, uni_orig), evasive_recall=sum(1 for ip in grid if ip in ips) / len(grid),
                          heldout={t: sum(1 for ip, v in meta.items() if v[0] == t and ip in ips) / sum(1 for v in meta.values() if v[0] == t) for t in ('reuse', 'burst', 'ultraslow')},
                          crawlers_flagged=len(ips & crawlers), control_false_ips=len(cips), control_crawlers_flagged=len(cips & ctl_crawlers))
    results.append(row); print(f'seed {s} done in {time.time()-t_start:.0f}s', flush=True)
    json.dump(results, open('results_v2_raw.json', 'w'))

# aggregate mean +- std
agg = {}
for name in results[0]:
    g = lambda f: [f(r[name]) for r in results]; ms = lambda xs: (round(statistics.mean(xs), 3), round(statistics.pstdev(xs), 3))
    agg[name] = dict(evasive_recall=ms(g(lambda x: x['evasive_recall'])), orig_precision=ms(g(lambda x: x['orig']['precision'])), orig_recall=ms(g(lambda x: x['orig']['recall'])),
                     orig_f1=ms(g(lambda x: x['orig']['f1'])), crawlers_flagged=ms(g(lambda x: x['crawlers_flagged'])), control_false_ips=ms(g(lambda x: x['control_false_ips'])))
    agg[name]['control_crawlers_flagged'] = ms(g(lambda x: x['control_crawlers_flagged']))
    agg[name]['heldout'] = {t: ms([r[name]['heldout'][t] for r in results]) for t in ('reuse', 'burst', 'ultraslow')}
    if 'by_cell' in results[0][name]:
        agg[name]['by_cell'] = {c: round(statistics.mean(r[name]['by_cell'][c] for r in results), 2) for c in results[0][name]['by_cell']}
json.dump(dict(seeds=len(results), grid=dict(ratios=RATIOS, rates=RATES, scanners_per_cell=20), aggregate=agg), open('results_v2.json', 'w'), indent=1)
for k, d in agg.items(): print(f"{k:40s} grid-recall {d['evasive_recall'][0]:.3f}  held-out {[d['heldout'][t][0] for t in ('reuse','burst','ultraslow')]}  orig P/R {d['orig_precision'][0]:.2f}/{d['orig_recall'][0]:.2f}  ctl-FP {d['control_false_ips'][0]} (crawlers {d['control_crawlers_flagged'][0]})  test-crawlers {d['crawlers_flagged'][0]}")
