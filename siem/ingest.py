"""Stage 1: collection. Reads one or more log files (merged in time order), parses, detects, stores."""
import heapq, time, os
from .parser import parse_line
from .detect import Detector


def read_events(path, year):
    with open(path, errors='replace') as f:
        for line in f:
            e = parse_line(line, year)
            if e:
                yield e


def ingest(paths, store, detector=None, year=2026, batch=5000, ml=None):
    detector = detector or Detector()
    stream = heapq.merge(*[read_events(p, year) for p in paths], key=lambda e: e['ts'])
    buf, alerts, n, t0 = [], [], 0, time.perf_counter()
    for e in stream:
        buf.append(e); n += 1
        alerts += detector.process(e)
        if ml: alerts += ml.process(e)
        if len(buf) >= batch:
            store.insert_events(buf); store.insert_alerts(alerts); buf, alerts = [], []
    alerts += detector.finish()
    if ml: alerts += ml.finish()
    store.insert_events(buf); store.insert_alerts(alerts)
    dt = time.perf_counter() - t0
    return {'events': n, 'seconds': round(dt, 3), 'events_per_sec': round(n / dt) if dt else 0}


def follow(path, store, detector, year=2026, poll=1.0):
    """Live mode: like `tail -f`; new lines are parsed, checked and stored as they arrive."""
    det = detector or Detector()
    with open(path, errors='replace') as f:
        f.seek(0, os.SEEK_END)
        while True:
            lines = f.readlines()
            evs = [e for e in (parse_line(l, year) for l in lines) if e]
            al = []
            for e in evs:
                al += det.process(e)
            store.insert_events(evs); store.insert_alerts(al)
            time.sleep(poll)
