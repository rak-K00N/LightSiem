"""Stage 4: streaming detection engine (the project's 'algorithm').

Events are processed one by one in time order, using small per-IP sliding windows (deques), so memory stays
bounded and alerts are raised while the log is still being read.  Four detectors:

 R1  ssh_bruteforce       >= N1 failed SSH logins from one IP inside a SHORT window (default 8 in 60 s)
 R1b ssh_low_and_slow     >= N2 failed SSH logins from one IP inside a LONG window (default 40 in 1 h)
 R2  ssh_success_after_failures  successful login from an IP that failed >= 5 times in the last 5 min
 R3  web_scan             >= N3 HTTP 401/403/404 responses to one IP inside 60 s (directory/vuln scanning)
 R4  traffic_spike        adaptive anomaly detector: events-per-minute compared with an EWMA baseline
                          (mean + k*std); the baseline adapts to daily load so no fixed threshold is needed.
Using time windows (instead of whole-file totals) is what removes false positives from normal users whose
occasional typos/404s add up over a day.
"""
import math
from collections import defaultdict, deque


class Detector:
    def __init__(self, **kw):
        c = dict(ssh_n=8, ssh_win=60, slow_n=40, slow_win=3600, comp_n=5, comp_win=300,
                 web_n=25, web_win=60, cooldown=600,
                 rate_alpha=0.1, rate_k=4.0, rate_warm=30, rate_floor=50)
        c.update(kw)
        self.c = c
        self.ssh = defaultdict(deque)
        self.web = defaultdict(deque)
        self.last = {}
        self.count = 0
        # EWMA state for the rate detector
        self.cb = None; self.cc = 0; self.mean = 0.0; self.var = 0.0; self.nb = 0; self.in_spike = False

    # ---- helpers -------------------------------------------------------------------------------------
    def _emit(self, out, ts, rule, sev, ip, detail):
        key = (rule, ip)
        if ip is not None and ts - self.last.get(key, -10 ** 12) < self.c['cooldown']:
            return
        self.last[key] = ts
        out.append(dict(ts=ts, rule=rule, severity=sev, src_ip=ip, detail=detail))

    @staticmethod
    def _recent(dq, since):  # number of timestamps >= since (deque is time-ordered, scan from the right)
        n = 0
        for t in reversed(dq):
            if t < since:
                break
            n += 1
        return n

    # ---- main entry ----------------------------------------------------------------------------------
    def process(self, e):
        out, ts, c = [], e['ts'], self.c
        self.count += 1
        cat = e['category']
        if cat in ('ssh_fail', 'ssh_invalid_user') and e['src_ip']:
            dq = self.ssh[e['src_ip']]
            dq.append(ts)
            while dq and dq[0] < ts - c['slow_win']:
                dq.popleft()
            n = self._recent(dq, ts - c['ssh_win'])
            if n >= c['ssh_n']:
                self._emit(out, ts, 'ssh_bruteforce', 'high', e['src_ip'], f'{n} failed SSH logins in {c["ssh_win"]}s (user {e["user"]})')
            elif len(dq) >= c['slow_n']:
                self._emit(out, ts, 'ssh_low_and_slow', 'medium', e['src_ip'], f'{len(dq)} failed SSH logins in {c["slow_win"]//60} min')
        elif cat == 'ssh_ok' and e['src_ip'] in self.ssh:
            n = self._recent(self.ssh[e['src_ip']], ts - c['comp_win'])
            if n >= c['comp_n']:
                self._emit(out, ts, 'ssh_success_after_failures', 'critical', e['src_ip'],
                           f'login as {e["user"]} succeeded after {n} failures - possible compromise')
        elif cat == 'http' and e['status'] in (401, 403, 404):
            dq = self.web[e['src_ip']]
            dq.append(ts)
            while dq and dq[0] < ts - c['web_win']:
                dq.popleft()
            if len(dq) >= c['web_n']:
                self._emit(out, ts, 'web_scan', 'high', e['src_ip'], f'{len(dq)} client-error responses in {c["web_win"]}s (scanning)')
        out += self._rate(ts)
        if self.count % 20000 == 0:                       # bounded memory: forget idle IPs
            for d in (self.ssh, self.web):
                for k in [k for k, v in d.items() if not v or v[-1] < ts - c['slow_win']]:
                    del d[k]
        return out

    # ---- adaptive rate anomaly (R4) -------------------------------------------------------------------
    def _rate(self, ts):
        b = ts // 60
        if self.cb is None:
            self.cb, self.cc = b, 1
            return []
        if b == self.cb:
            self.cc += 1
            return []
        out = self._close(self.cb, self.cc)
        for g in range(min(b - self.cb - 1, 60)):          # empty minutes count as zero traffic
            self._close(self.cb + 1 + g, 0)
        self.cb, self.cc = b, 1
        return out

    def _close(self, bucket, x):
        c, out = self.c, []
        self.nb += 1
        if self.nb == 1:
            self.mean, self.var = float(x), 0.0
            return out
        std = max(math.sqrt(self.var), 1.0, 0.1 * self.mean)
        thr = self.mean + c['rate_k'] * std
        if self.nb > c['rate_warm'] and x > max(c['rate_floor'], thr):
            if not self.in_spike:                           # alert once, at the onset of a spike
                out.append(dict(ts=bucket * 60, rule='traffic_spike', severity='high', src_ip=None,
                                detail=f'{x} events/min vs baseline {self.mean:.0f} (threshold {thr:.0f})'))
            self.in_spike = True                            # do not learn from anomalous minutes
        else:
            self.in_spike = False
            d = x - self.mean
            self.mean += c['rate_alpha'] * d
            self.var = (1 - c['rate_alpha']) * (self.var + c['rate_alpha'] * d * d)
        return out

    def finish(self):
        return self._close(self.cb, self.cc) if self.cb is not None else []
