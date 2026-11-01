"""Machine-learning detector (unsupervised anomaly detection with an Isolation Forest).

IDEA: rules only catch attacks somebody wrote a rule for.  Instead of writing rules, we let a model learn what a
NORMAL 5-minute window of activity looks like for one source IP, and flag windows that look unlike anything seen
in normal traffic.  No labelled attacks are needed for training - only a period of known-good logs.

Features (per source IP per 5-minute window):
  log(events), failed SSH logins, distinct SSH usernames tried, HTTP requests, share of 4xx errors,
  distinct URLs / requests, number of 404s, number of 5xx.
Two interchangeable models (same features, same streaming code):
  kind='iforest'  UNSUPERVISED Isolation Forest. Learns 'normal' from known-good logs only; flags anything unusual.
                  Threshold = q-quantile of scores on the training windows (default 0.1%).
  kind='rf'       SUPERVISED Random Forest classifier. Learns 'attack vs normal' from labelled windows
                  (e.g. IPs an analyst already confirmed as attackers); flags windows with P(attack) >= 0.5.
v2 UPGRADE (supervised model): (1) evasion-aware training - disguised copies of known attackers are added to the training set so
the model also recognises scanners that dilute their error rate or slow down; (2) evidence accumulation - strong evidence
(P(attack) > 0.8) alerts at once, weak evidence (P > 0.3) must repeat in 3 consecutive windows, which removes the small-sample
false alarms of ordinary clients whose few requests happened to include a couple of 404s.
Unsupervised can say "unusual" but not "malicious" (e.g. a legitimate crawler looks unusual); supervised can tell the
two apart but only knows what the labels taught it.  Windows are scored as soon as their 5-minute bucket closes.
"""
import math, pickle
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

FEATURES = ['log_events', 'ssh_fail', 'distinct_users', 'http_requests', 'err4xx_ratio', 'distinct_url_ratio', 'n404', 'n5xx']


class _Win:
    __slots__ = ('n', 'ssh', 'users', 'http', 'e4', 'paths', 'e404', 'e5')

    def __init__(self):
        self.n = self.ssh = self.http = self.e4 = self.e404 = self.e5 = 0
        self.users, self.paths = set(), set()

    def add(self, e):
        self.n += 1
        c = e['category']
        if c in ('ssh_fail', 'ssh_invalid_user'):
            self.ssh += 1
            if e['user']: self.users.add(e['user'])
        elif c == 'http':
            self.http += 1
            st = e['status']
            if 400 <= st < 500: self.e4 += 1
            if st == 404: self.e404 += 1
            if st >= 500: self.e5 += 1
            parts = e['msg'].split(' ', 2)
            if len(parts) > 1: self.paths.add(parts[1])

    def vector(self):
        h = self.http
        return [math.log1p(self.n), self.ssh, len(self.users), h, self.e4 / h if h else 0.0,
                len(self.paths) / h if h else 0.0, self.e404, self.e5]


class MLDetector:
    def __init__(self, window=300, min_events=5, quantile=0.001, n_trees=100, cooldown=900, seed=0, kind='iforest'):
        self.window, self.min_events, self.quantile, self.n_trees, self.cooldown, self.seed, self.kind = window, min_events, quantile, n_trees, cooldown, seed, kind
        self.model = None; self.threshold = None
        self.weak = None; self.persist = 1; self.streak = {}; self.last_weak = {}
        self.cur = None; self.wins = {}; self.last = {}

    # ---- training ---------------------------------------------------------------------------------
    def _windows(self, events):
        cur, wins = None, {}
        for e in events:
            if not e['src_ip']:
                continue
            b = e['ts'] // self.window
            if b != cur:
                for ip, w in wins.items():
                    if w.n >= self.min_events: yield ip, w.vector()
                cur, wins = b, {}
            wins.setdefault(e['src_ip'], _Win()).add(e)
        for ip, w in wins.items():
            if w.n >= self.min_events: yield ip, w.vector()

    AUGMENT = tuple((p, k) for p in (0.0, 0.25, 0.5, 0.75) for k in (1.0, 0.5, 0.2) if (p, k) != (0.0, 1.0))

    def _augment(self, events, attackers, spec):
        """EVASION-AWARE AUGMENTATION (the v2 upgrade). A supervised model only learns the attackers it is shown, and
        shown loud, fast scanners it learns 'many 404s per window = attack'. A careful attacker can (a) hide among normal-looking
        200 responses and (b) slow down. So for every labelled attacker's HTTP traffic we add disguised copies: with probability p
        a 404 becomes a 200 (dilution) and each request is kept with probability k (thinning). Copies get new IPs and the attack label."""
        import random
        R, extra, new_att = random.Random(self.seed), [], set(attackers)
        web = [e for e in events if e['src_ip'] in attackers and e['category'] == 'http']
        ips = {e['src_ip'] for e in web}
        for vi, (p, k) in enumerate(spec):
            for e in web:
                if R.random() > k:
                    continue
                v = dict(e); v['src_ip'] = f"{e['src_ip']}~a{vi}"
                if v['status'] == 404 and R.random() < p:
                    v['status'] = 200; v['msg'] = v['msg'].rsplit(' ', 1)[0] + ' 200'
                extra.append(v)
            new_att |= {f"{ip}~a{vi}" for ip in ips}
        return sorted(events + extra, key=lambda e: e['ts']), new_att

    def fit(self, events, attackers=None, augment=False):
        """iforest: events only (known-good).  rf: also `attackers` = set of IPs labelled malicious;
        augment=True adds evasion-aware training copies of the labelled web attackers (rf only)."""
        if self.kind == 'rf' and augment:
            events, attackers = self._augment(list(events), set(attackers), self.AUGMENT if augment is True else augment)
        pairs = list(self._windows(events)); X = np.array([v for _, v in pairs])
        if self.kind == 'rf':
            y = np.array([ip in attackers for ip, _ in pairs])
            self.model = RandomForestClassifier(n_estimators=self.n_trees, class_weight='balanced', min_samples_leaf=2, random_state=self.seed).fit(X, y)
            if augment:      # evidence accumulation; values chosen on a separate validation seed (tune2_v2.py)
                self.threshold, self.weak, self.persist = 0.8, 0.3, 3
            else:
                self.threshold, self.weak, self.persist = 0.5, None, 1
            return {'training_windows': int(len(X)), 'attack_windows': int(y.sum()), 'model': 'RandomForest'}
        self.model = IsolationForest(n_estimators=self.n_trees, random_state=self.seed, contamination='auto').fit(X)
        self.train_scores = self.model.score_samples(X)
        self.threshold = float(-np.quantile(self.train_scores, self.quantile))      # suspicion = -score
        return {'training_windows': int(len(X)), 'model': 'IsolationForest', 'threshold': round(self.threshold, 4)}

    def _suspicion(self, X):  # higher = more suspicious, for both model kinds
        return self.model.predict_proba(X)[:, 1] if self.kind == 'rf' else -self.model.score_samples(X)

    def save(self, path):
        pickle.dump({'m': self.model, 't': self.threshold, 'weak': self.weak, 'persist': self.persist, 'cfg': (self.window, self.min_events, self.quantile, self.n_trees, self.cooldown, self.seed, self.kind)}, open(path, 'wb'))

    @classmethod
    def load(cls, path):
        d = pickle.load(open(path, 'rb'))  # only load model files you trained yourself (pickle can run code)
        o = cls(*d['cfg']); o.model, o.threshold = d['m'], d['t']; o.weak, o.persist = d.get('weak'), d.get('persist', 1)
        return o

    # ---- streaming scoring ------------------------------------------------------------------------
    def process(self, e):
        if not e['src_ip']:
            return []
        b, out = e['ts'] // self.window, []
        if self.cur is None:
            self.cur = b
        elif b != self.cur:
            out = self._close()
            self.cur = b
        self.wins.setdefault(e['src_ip'], _Win()).add(e)
        return out

    def _close(self):
        items = [(ip, w) for ip, w in self.wins.items() if w.n >= self.min_events]
        ts, out = self.cur * self.window, []
        if items:
            X = np.array([w.vector() for _, w in items])
            for (ip, w), s in zip(items, self._suspicion(X)):
                fire = s > self.threshold
                if not fire and self.weak is not None and s > self.weak:       # weak evidence must repeat
                    run = self.streak.get(ip, 0) + 1 if self.last_weak.get(ip) == self.cur - 1 else 1
                    self.streak[ip], self.last_weak[ip] = run, self.cur
                    fire = run >= self.persist
                if fire and ts - self.last.get(ip, -10 ** 12) >= self.cooldown:
                    self.last[ip] = ts
                    out.append(dict(ts=ts, rule='ml_' + self.kind, severity='medium', src_ip=ip,
                                    detail=f'ML {self.kind} suspicion {s:.2f}: {w.n} events, {w.ssh} failed SSH, '
                                           f'{w.http} HTTP, {100 * w.e4 / max(w.http, 1):.0f}% 4xx, {len(w.paths)} distinct URLs'))
        self.wins = {}
        return out

    def finish(self):
        return self._close() if self.cur is not None else []
