#!/usr/bin/env python3
"""Reproducible evaluation: detection quality, comparison with a naive baseline, speed, memory, search latency."""
import json, os, subprocess, sys, time, resource, statistics, shutil
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from siem.gen_logs import generate
from siem.store import Store
from siem.ingest import read_events

D = 'eval_data'; DB = os.path.join(D, 'eval.db')
shutil.rmtree(D, ignore_errors=True)
info = generate(D, seed=7, scale=1.0)
truth = json.load(open(os.path.join(D, 'truth.json')))
auth, acc = os.path.join(D, 'auth.log'), os.path.join(D, 'access.log')

# 1) ingest in a SEPARATE process so memory/throughput are those of the SIEM alone
r = subprocess.run([sys.executable, 'lightsiem.py', 'ingest', auth, acc, '--db', DB, '--year', '2026'], capture_output=True, text=True, check=True)
ing = json.loads(r.stdout.strip().splitlines()[-1])
ing['db_size_mb'] = round(os.path.getsize(DB) / 1e6, 1)
ing['raw_log_mb'] = round((os.path.getsize(auth) + os.path.getsize(acc)) / 1e6, 1)

st = Store(DB)
alerts = st.alerts(100000)

def prf(pred, pos, universe):
    tp, fp, fn = len(pred & pos), len(pred - pos), len(pos - pred)
    p = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, precision=round(p, 3), recall=round(rc, 3), f1=round(2 * p * rc / (p + rc), 3) if p + rc else 0.0)

pos = {ip for k in ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan') for ip in truth[k]}
ours_ips = {a['src_ip'] for a in alerts if a['src_ip']}
first_alert = {}
for a in sorted(alerts, key=lambda a: a['ts']):
    if a['src_ip']: first_alert.setdefault(a['src_ip'], a['ts'])
start = {ip: t for k in ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan') for ip, t in truth[k].items()}
delays = [first_alert[i] - start[i] for i in pos if i in first_alert]

# 2) naive baseline = what a simple script would do: count per-IP totals over the whole file, fixed threshold
ssh_tot, err_tot, lines = defaultdict(int), defaultdict(int), []
for p in (auth, acc):
    for e in read_events(p, 2026):
        lines.append((e['ts'], e['raw']))
        if e['category'] in ('ssh_fail', 'ssh_invalid_user'): ssh_tot[e['src_ip']] += 1
        elif e['category'] == 'http' and e['status'] in (401, 403, 404): err_tot[e['src_ip']] += 1
naive_ips = {i for i, n in ssh_tot.items() if n >= 8} | {i for i, n in err_tot.items() if n >= 25}
lines.sort()

# per-attack-type recall for our detector
by_type = {k: round(len(set(truth[k]) & ours_ips) / len(truth[k]), 3) for k in ('ssh_bruteforce', 'ssh_slow', 'ssh_compromise', 'web_scan')}
compromise_flagged = {a['src_ip'] for a in alerts if a['rule'] == 'ssh_success_after_failures'}

# 3) traffic-spike detector
spike = [a for a in alerts if a['rule'] == 'traffic_spike']
t0, t1 = truth['spike']
spike_tp = [a for a in spike if t0 - 60 <= a['ts'] <= t1 + 60]
spike_res = dict(alerts_total=len(spike), true_alert=bool(spike_tp), false_alerts=len(spike) - len(spike_tp),
                 delay_s=(spike_tp[0]['ts'] - t0) if spike_tp else None)

# 3b) CONTROL RUN: same normal traffic, NO attacks -> every alert is a false positive
from siem.detect import Detector
generate(D + '_ctl', seed=7, scale=1.0, attacks=False)
det, ctl = Detector(), []
import heapq
for ev in heapq.merge(read_events(D + '_ctl/auth.log', 2026), read_events(D + '_ctl/access.log', 2026), key=lambda x: x['ts']):
    ctl += det.process(ev)
ctl += det.finish()
control = dict(events=det.count, false_alerts=len(ctl), by_rule={r: sum(a['rule'] == r for a in ctl) for r in {a['rule'] for a in ctl}})
shutil.rmtree(D + '_ctl', ignore_errors=True)
flood_only = [a for a in spike if t0 - 60 <= a['ts'] <= t1 + 60]
attack_windows = [(s - 60, s + d + 60) for k, d in (('ssh_bruteforce', 120), ('ssh_slow', 7300), ('ssh_compromise', 120), ('web_scan', 180)) for s in truth[k].values()]
spike_res['other_spike_alerts_inside_attack_windows'] = sum(any(a_ <= a['ts'] <= b_ for a_, b_ in attack_windows) for a in spike if a not in flood_only)

# 3c) EVASION TEST: how slow must an SSH attacker be to avoid detection? (2 h of attempts at a fixed rate)
evasion = {}
for per_min in (20, 10, 5, 2, 1, 0.75, 0.5, 0.25):
    d, hit = Detector(), None
    for k in range(int(per_min * 120)):
        t = int(k * 60 / per_min)
        out = d.process(dict(ts=t, category='ssh_fail', src_ip='9.9.9.9', user='root', status=None))
        if out and hit is None: hit = (out[0]['rule'], t)
    evasion[f'{per_min}/min'] = dict(detected=bool(hit), rule=hit[0] if hit else None, after_s=hit[1] if hit else None)

# 4) search latency: indexed store vs linear scan of the raw logs (what grep/manual analysis does)
ip0 = sorted(truth['ssh_bruteforce'])[0]
def timeit(fn, n=15):
    ts = []
    for _ in range(n):
        a = time.perf_counter(); fn(); ts.append((time.perf_counter() - a) * 1000)
    return round(statistics.median(ts), 2)
Q = {
 'text "Failed password"': (lambda: st.count(q='Failed password'), lambda: sum('Failed password' in l for _, l in lines)),
 'all events from one IP': (lambda: st.count(ip=ip0), lambda: sum((ip0 + ' ') in l for _, l in lines)),
 'text "404" in 1-hour window': (lambda: st.count(q='404', t0=truth['spike'][0] - 7200, t1=truth['spike'][0] - 3600),
                                 lambda: sum(('404' in l) and (truth['spike'][0] - 7200 <= t <= truth['spike'][0] - 3600) for t, l in lines)),
}
assert st.count(q='Failed password') == sum('Failed password' in l for _, l in lines)  # same answers, both methods
lat = {k: {'indexed_ms': timeit(a), 'linear_scan_ms': timeit(b, 5)} for k, (a, b) in Q.items()}
for v in lat.values(): v['speedup_x'] = round(v['linear_scan_ms'] / max(v['indexed_ms'], 0.01))

res = dict(dataset=dict(info, events=ing['events'], attackers=len(pos), legit_ips_with_noise='10 SSH users with 10-18 typos/day + heavy web clients with ~4% 404s'),
           ours=prf(ours_ips, pos, None), baseline_naive_totals=prf(naive_ips, pos, None),
           recall_by_attack_type=by_type, compromise_detected=f'{len(compromise_flagged & set(truth["ssh_compromise"]))}/{len(truth["ssh_compromise"])}',
           detection_delay_s=dict(median=statistics.median(delays), p90=sorted(delays)[int(.9 * len(delays)) - 1], max=max(delays)),
           traffic_spike=spike_res, control_run_no_attacks=control, evasion_test=evasion, performance=ing, search_latency=lat)
json.dump(res, open('results.json', 'w'), indent=1)
print(json.dumps(res, indent=1))
