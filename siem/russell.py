"""Russell Mitchell dataset support.

Understands the ``gather/<host>/logs/`` directory layout used by the
AI-based Cyber Attack Dataset (russellmitchell) published by AECID/AIT.

Directory layout (abbreviated)::

    <root>/
        dataset.yaml            # scenario metadata
        gather/
            <host>/
                logs/
                    auth.log[.N]           -> syslog / auth
                    apache2/*access*.log*  -> Apache Combined Log Format
                    apache2/*error*.log*   -> Apache error log (skipped)
                    openvpn.log*           -> OpenVPN native log
                    dnsmasq.log*           -> dnsmasq (syslog-wrapped)
                    audit/audit.log*       -> auditd (skipped - binary/complex)
                    syslog[.N]             -> generic syslog
        labels/
            <host>/
                logs/
                    <same filenames>       -> JSONL ground-truth label files

The module exposes:

* :func:`collect_log_files`   – walk ``gather/`` and return a list of
  ``(path, host, log_type)`` triples the ingest pipeline can consume.
* :func:`load_labels`         – return ``{abs_log_path: {line_no: [labels]}}``
  for every label file found under ``labels/``.
* :func:`ingest_dataset`      – convenience wrapper: ingest all logs from a
  Russell Mitchell root directory, optionally filtering by host/log-type.
"""

import os, json, fnmatch
from .parser import parse_line
from .ingest import ingest

# ---------------------------------------------------------------------------
# Log-type classification
# ---------------------------------------------------------------------------

#: Glob patterns mapped to log type names understood by parse_line
_TYPE_MAP = [
    ('*access*.log*',  'apache'),
    ('*error*.log*',   'apache_error'),   # skipped during ingest
    ('auth.log*',      'auth'),
    ('syslog*',        'syslog'),
    ('openvpn.log*',   'openvpn'),
    ('dnsmasq.log*',   'dnsmasq'),
    ('audit.log*',     'audit'),          # skipped – complex auditd format
    ('attacks.log',    'attacks'),        # attacker ground-truth timeline
    ('*.log*',         'generic'),
]

#: Log types we can actually parse (others are silently skipped)
PARSEABLE = {'apache', 'auth', 'syslog', 'openvpn', 'dnsmasq', 'generic'}


def _classify(filename):
    """Return a log-type string for a given *basename*."""
    for pat, ltype in _TYPE_MAP:
        if fnmatch.fnmatch(filename, pat):
            return ltype
    return 'generic'


# ---------------------------------------------------------------------------
# Directory walker
# ---------------------------------------------------------------------------

def collect_log_files(root):
    """Walk ``<root>/gather/`` and return a list of ``(path, host, log_type)``.

    Only files whose log type is in :data:`PARSEABLE` are returned; audit,
    Apache error logs, and attacker timeline files are excluded.

    Parameters
    ----------
    root : str
        Path to the Russell Mitchell dataset root (the directory that contains
        ``gather/``, ``labels/``, ``dataset.yaml`` …).

    Returns
    -------
    list of (str, str, str)
        ``(absolute_path, host_name, log_type)`` triples, sorted by path so
        rotated logs (``.1``, ``.2`` …) are read in chronological order
        (oldest rotation first).
    """
    gather = os.path.join(root, 'gather')
    if not os.path.isdir(gather):
        raise FileNotFoundError(f'No gather/ directory found under {root!r}')

    result = []
    for host in sorted(os.listdir(gather)):
        host_logs = os.path.join(gather, host, 'logs')
        if not os.path.isdir(host_logs):
            continue
        for dirpath, _dirs, files in os.walk(host_logs):
            for fname in sorted(files):
                ltype = _classify(fname)
                if ltype not in PARSEABLE:
                    continue
                result.append((os.path.join(dirpath, fname), host, ltype))
    return result


# ---------------------------------------------------------------------------
# Label loader
# ---------------------------------------------------------------------------

def load_labels(root):
    """Load ground-truth labels for all log files under ``<root>/labels/``.

    Each label file is a JSONL where every line corresponds to a source log
    line and looks like::

        {"line": 145, "labels": ["attacker_change_user", "escalate"], "rules": {...}}

    *line* is **1-based**.

    Returns
    -------
    dict
        ``{abs_gather_path: {line_number: list_of_label_strings}}``
        where *abs_gather_path* is the corresponding path under ``gather/``.
    """
    labels_root = os.path.join(root, 'labels')
    gather_root = os.path.join(root, 'gather')
    if not os.path.isdir(labels_root):
        return {}

    out = {}
    for dirpath, _dirs, files in os.walk(labels_root):
        for fname in files:
            label_path = os.path.join(dirpath, fname)
            # Map label path -> gather path by replacing the prefix
            rel = os.path.relpath(label_path, labels_root)
            gather_path = os.path.join(gather_root, rel)

            line_labels = {}
            try:
                with open(label_path, errors='replace') as fh:
                    for raw in fh:
                        raw = raw.strip()
                        if not raw:
                            continue
                        try:
                            obj = json.loads(raw)
                            lineno = obj.get('line')
                            lbls = obj.get('labels', [])
                            if lineno and lbls:
                                line_labels[int(lineno)] = lbls
                        except (json.JSONDecodeError, TypeError):
                            pass
            except OSError:
                pass

            if line_labels:
                out[gather_path] = line_labels
    return out


# ---------------------------------------------------------------------------
# Convenience ingest wrapper
# ---------------------------------------------------------------------------

def ingest_dataset(root, store, detector=None, year=2022, batch=5000, ml=None,
                   host_filter=None, type_filter=None):
    """Ingest every parseable log in a Russell Mitchell dataset root.

    Parameters
    ----------
    root        : str   Path to the dataset root (must contain ``gather/``).
    store       : Store SQLite store to write events and alerts into.
    detector    : Detector | None   Rule-based detector; created if None.
    year        : int   Calendar year for syslog timestamps (default 2022).
    batch       : int   Insert batch size (passed through to :func:`ingest`).
    ml          : MLDetector | None   Optional ML detector.
    host_filter : list[str] | None   Only ingest logs for these hosts.
    type_filter : list[str] | None   Only ingest logs of these types.

    Returns
    -------
    dict
        Ingest statistics from :func:`~siem.ingest.ingest`.
    """
    files = collect_log_files(root)

    if host_filter:
        files = [(p, h, t) for p, h, t in files if h in host_filter]
    if type_filter:
        files = [(p, h, t) for p, h, t in files if t in type_filter]

    if not files:
        return {'events': 0, 'seconds': 0, 'events_per_sec': 0}

    paths = [p for p, _h, _t in files]
    return ingest(paths, store, detector=detector, year=year, batch=batch, ml=ml,
                  _hint_hosts={p: h for p, h, _ in files},
                  _hint_sources={p: t for p, h, t in files})


# ---------------------------------------------------------------------------
# Rotated-log ordering helper (oldest rotation = highest number)
# ---------------------------------------------------------------------------

def rotation_key(path):
    """Sort key so ``.log`` < ``.log.1`` < ``.log.2`` (oldest first)."""
    import re
    m = re.search(r'\.(\d+)$', path)
    return int(m.group(1)) if m else -1
