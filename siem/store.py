"""Stage 3: storage and search. SQLite with indexes on time and source IP, plus an FTS5 full-text index."""
import sqlite3, threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts INTEGER, host TEXT, source TEXT, category TEXT,
  severity TEXT, src_ip TEXT, user TEXT, status INTEGER, msg TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ip ON events(src_ip, ts);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(msg, content='events', content_rowid='id');
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts INTEGER, rule TEXT, severity TEXT, src_ip TEXT, detail TEXT);
"""
COLS = ('ts', 'host', 'source', 'category', 'severity', 'src_ip', 'user', 'status', 'msg', 'raw')


def fts_query(q):  # quote every token so user input can never break the FTS syntax
    return ' '.join('"' + t.replace('"', '') + '"' for t in q.split())


class Store:
    def __init__(self, path=':memory:'):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=OFF')
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    def insert_events(self, events):
        if not events:
            return
        with self.lock:
            cur = self.db.cursor()
            last = cur.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0]
            cur.executemany('INSERT INTO events(%s) VALUES(%s)' % (','.join(COLS), ','.join('?' * len(COLS))),
                            [tuple(e[c] for c in COLS) for e in events])
            cur.execute('INSERT INTO events_fts(rowid,msg) SELECT id,msg FROM events WHERE id>?', (last,))
            self.db.commit()

    def insert_alerts(self, alerts):
        if not alerts:
            return
        with self.lock:
            self.db.executemany('INSERT INTO alerts(ts,rule,severity,src_ip,detail) VALUES(?,?,?,?,?)',
                                [(a['ts'], a['rule'], a['severity'], a['src_ip'], a['detail']) for a in alerts])
            self.db.commit()

    def _where(self, q, ip, category, t0, t1, severity=None):
        sql, where, args = ' FROM events e', [], []
        if q:
            sql += ' JOIN events_fts ON events_fts.rowid=e.id'
            where.append('events_fts MATCH ?'); args.append(fts_query(q))
        for cond, val in (('e.src_ip=?', ip), ('e.category=?', category), ('e.ts>=?', t0), ('e.ts<=?', t1),
                          ('e.severity=?', severity)):
            if val not in (None, ''):
                where.append(cond); args.append(val)
        return sql + (' WHERE ' + ' AND '.join(where) if where else ''), args

    def search(self, q=None, ip=None, category=None, t0=None, t1=None, severity=None, limit=100):
        sql, args = self._where(q, ip, category, t0, t1, severity)
        cur = self.db.execute('SELECT e.ts,e.host,e.category,e.severity,e.src_ip,e.user,e.status,e.msg' + sql +
                              ' ORDER BY e.ts DESC LIMIT ?', args + [int(limit)])
        keys = ('ts', 'host', 'category', 'severity', 'src_ip', 'user', 'status', 'msg')
        return [dict(zip(keys, r)) for r in cur]

    def count(self, q=None, ip=None, category=None, t0=None, t1=None, severity=None):
        sql, args = self._where(q, ip, category, t0, t1, severity)
        return self.db.execute('SELECT COUNT(*)' + sql, args).fetchone()[0]

    def alerts(self, limit=200):
        cur = self.db.execute('SELECT ts,rule,severity,src_ip,detail FROM alerts ORDER BY ts DESC LIMIT ?', (limit,))
        return [dict(zip(('ts', 'rule', 'severity', 'src_ip', 'detail'), r)) for r in cur]

    def timeline(self, bucket=60, t0=None, t1=None):
        w, a = [], []
        for c, v in (('ts>=?', t0), ('ts<=?', t1)):
            if v not in (None, ''):
                w.append(c); a.append(v)
        sql = 'SELECT ts/?*? AS t, COUNT(*) FROM events' + (' WHERE ' + ' AND '.join(w) if w else '') + ' GROUP BY t ORDER BY t'
        return [{'t': t, 'n': n} for t, n in self.db.execute(sql, [bucket, bucket] + a)]

    def top_ips(self, category=None, limit=10):
        sql = 'SELECT src_ip, COUNT(*) c FROM events WHERE src_ip IS NOT NULL' + (' AND category=?' if category else '') + \
              ' GROUP BY src_ip ORDER BY c DESC LIMIT ?'
        return [{'ip': i, 'n': n} for i, n in self.db.execute(sql, ([category] if category else []) + [limit])]

    def stats(self):
        tot = self.db.execute('SELECT COUNT(*), MIN(ts), MAX(ts) FROM events').fetchone()
        cats = dict(self.db.execute('SELECT category, COUNT(*) FROM events GROUP BY category'))
        al = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        return {'events': tot[0], 'first_ts': tot[1], 'last_ts': tot[2], 'categories': cats, 'alerts': al}
