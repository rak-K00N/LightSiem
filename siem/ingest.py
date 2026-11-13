"""Stage 1: collection. Reads one or more log files (merged in time order), parses, detects, stores."""
import heapq, time, os
from .parser import parse_line
from .detect import Detector


def read_events(path, year, hint_host=None, hint_source=None):
    """Yield parsed events from *path*.

    Parameters
    ----------
    hint_host   : str | None  Override the ``host`` field for every event in this file
                              (used by the Russell Mitchell dataset loader which knows
                              the hostname from the directory structure).
    hint_source : str | None  Hint the parser about the log type ('apache', 'openvpn',
                              'dnsmasq', …) so it can try the right sub-parser first.
    """
    with open(path, errors='replace') as f:
        for line in f:
            e = parse_line(line, year, hint_host=hint_host, hint_source=hint_source)
            if e:
                yield e


def ingest(paths, store, detector=None, year=2026, batch=5000, ml=None,
           _hint_hosts=None, _hint_sources=None):
    """Ingest *paths* into *store*, applying rule-based and optional ML detection.

    Parameters
    ----------
    paths         : list[str]  Log file paths (time-merged across all files).
    store         : Store      SQLite store.
    detector      : Detector | None
    year          : int        Calendar year for syslog-format timestamps.
    batch         : int        SQLite insert batch size.
    ml            : MLDetector | None
    _hint_hosts   : dict | None  ``{path: host_name}`` overrides (internal; used by
                                 :func:`siem.russell.ingest_dataset`).
    _hint_sources : dict | None  ``{path: log_type}`` overrides (internal).
    """
    detector = detector or Detector()
    _hint_hosts = _hint_hosts or {}
    _hint_sources = _hint_sources or {}

    def _events(p):
        return read_events(p, year,
                           hint_host=_hint_hosts.get(p),
                           hint_source=_hint_sources.get(p))

    stream = heapq.merge(*[_events(p) for p in paths], key=lambda e: e['ts'])
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
