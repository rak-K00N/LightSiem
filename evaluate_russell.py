#!/usr/bin/env python3
"""Evaluation script for the Russell Mitchell (AECID) dataset.

Usage (via lightsiem.py)::

    python lightsiem.py russell ingest /path/to/russellmitchell --db rm.db
    python lightsiem.py russell evaluate /path/to/russellmitchell --db rm.db

Or directly::

    python evaluate_russell.py /path/to/russellmitchell --db rm.db --out results_russell.json

What it measures
----------------
The Russell Mitchell label files mark individual *log lines* as belonging to
one or more attack phases (e.g. ``attacker_http``, ``escalate``,
``service_scan``).  LightSIEM raises *alerts* at the IP level, not at the line
level, so we score at two granularities:

**IP-level** (primary)
    Is the attacker IP flagged by at least one rule-based alert?

**Rule-label correlation** (secondary)
    For each label family (foothold / escalate / service_scan / …) we check
    whether lines belonging to that family were parsed and stored (ingestion
    coverage), and whether any alert was raised around the same timeframe.

Additionally the script reports:
* How many labelled lines were actually *parsed* (ingestion coverage).
* The distribution of alerts by rule.
* Attack timeline from ``attacker_*/logs/attacks.log``.
"""

import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siem.store import Store
from siem.russell import collect_log_files, load_labels
from siem.ingest import read_events

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ATTACK_LABEL_GROUPS = {
    'foothold':      lambda ls: any('foothold' in l or 'attacker_http' in l or 'service_scan' in l for l in ls),
    'escalate':      lambda ls: any('escalate' in l or 'attacker_change_user' in l for l in ls),
    'exfiltrate':    lambda ls: any('exfiltrate' in l or 'dnssteal' in l for l in ls),
    'lateral':       lambda ls: any('lateral' in l for l in ls),
    'any_attacker':  lambda ls: any('attacker' in l or 'escalat' in l or 'foothold' in l
                                    or 'exfiltrat' in l or 'lateral' in l for l in ls),
}


def _load_attacks_log(root):
    """Return list of (epoch_ts, action_name) from attacker_*/logs/attacks.log files."""
    import datetime
    gather = os.path.join(root, 'gather')
    events = []
    for host in os.listdir(gather):
        alog = os.path.join(gather, host, 'logs', 'attacks.log')
        if not os.path.isfile(alog):
            continue
        with open(alog, errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                try:
                    dt_str = parts[0]        # e.g. "2022-01-24"
                    tm_str = parts[1].split()[0]  # e.g. "03:01:00.063877+00:00"
                    action = ' '.join(parts[1].split()[1:]) if len(parts[1].split()) > 1 else parts[1]
                    # datetime string is "YYYY-MM-DD HH:MM:SS.ffffff+TZ"
                    full = f'{dt_str} {tm_str}'
                    # strip microseconds and tz for simple parsing
                    full_base = full.split('.')[0]
                    dt = datetime.datetime.strptime(full_base, '%Y-%m-%d %H:%M:%S')
                    ts = int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
                    events.append((ts, action.strip()))
                except (ValueError, IndexError):
                    pass
    return sorted(events)


def _attacker_ips_from_labels(root, all_labels):
    """Collect every src_ip that appears in a labelled line (attacker lines)."""
    # We cross-reference label line numbers against the parsed events stored in
    # the SIEM database; this avoids re-reading every log file at eval time.
    # Return a set of attacker IPs from lines that carry attack labels.
    attacker_ips = set()
    for gather_path, line_map in all_labels.items():
        attack_lines = {ln for ln, lbls in line_map.items()
                        if ATTACK_LABEL_GROUPS['any_attacker'](lbls)}
        if not attack_lines:
            continue
        # Re-read the log file to find the src_ip on those line numbers
        if not os.path.isfile(gather_path):
            continue
        # Determine year from filename path (default 2022)
        year = 2022
        try:
            with open(gather_path, errors='replace') as fh:
                for lineno, raw in enumerate(fh, start=1):
                    if lineno in attack_lines:
                        from siem.parser import parse_line
                        e = parse_line(raw, year)
                        if e and e.get('src_ip'):
                            attacker_ips.add(e['src_ip'])
        except OSError:
            pass
    return attacker_ips


def _ingestion_coverage(root, all_labels, year=2022):
    """Return stats on how many labelled lines were successfully parsed."""
    total_labelled = 0
    total_parsed = 0
    by_label = {}

    for gather_path, line_map in all_labels.items():
        if not os.path.isfile(gather_path):
            continue
        try:
            parsed_linenos = set()
            with open(gather_path, errors='replace') as fh:
                for lineno, raw in enumerate(fh, start=1):
                    if lineno not in line_map:
                        continue
                    from siem.parser import parse_line
                    e = parse_line(raw, year)
                    if e:
                        parsed_linenos.add(lineno)
            for lineno, lbls in line_map.items():
                total_labelled += 1
                parsed = lineno in parsed_linenos
                if parsed:
                    total_parsed += 1
                for lbl in lbls:
                    if lbl not in by_label:
                        by_label[lbl] = {'labelled': 0, 'parsed': 0}
                    by_label[lbl]['labelled'] += 1
                    if parsed:
                        by_label[lbl]['parsed'] += 1
        except OSError:
            pass

    return {
        'total_labelled_lines': total_labelled,
        'total_parsed_lines': total_parsed,
        'parse_coverage_pct': round(100 * total_parsed / total_labelled, 1) if total_labelled else 0,
        'by_label': {k: dict(v, coverage_pct=round(100 * v['parsed'] / v['labelled'], 1))
                     for k, v in sorted(by_label.items())},
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def evaluate(root, db_path, out_path, year=2022):
    t0 = time.perf_counter()

    # 1) Load labels
    print('Loading label files …', flush=True)
    all_labels = load_labels(root)
    n_label_files = len(all_labels)
    n_label_lines = sum(len(v) for v in all_labels.values())
    print(f'  {n_label_files} label files, {n_label_lines} labelled lines total')

    # 2) Ingestion coverage (how many labelled lines did the parser understand?)
    print('Measuring ingestion coverage …', flush=True)
    coverage = _ingestion_coverage(root, all_labels, year=year)
    print(f'  Parse coverage: {coverage["parse_coverage_pct"]}% '
          f'({coverage["total_parsed_lines"]}/{coverage["total_labelled_lines"]} labelled lines)')

    # 3) Load alerts from the SIEM database
    print(f'Loading alerts from {db_path} …', flush=True)
    st = Store(db_path)
    alerts = st.alerts(limit=1_000_000)
    db_stats = st.stats()
    print(f'  {db_stats["events"]} events, {db_stats["alerts"]} alerts in DB')

    # 4) Determine attacker IPs from labels
    print('Identifying attacker IPs from labels …', flush=True)
    attacker_ips = _attacker_ips_from_labels(root, all_labels)
    print(f'  {len(attacker_ips)} unique attacker IP(s) found in labelled lines')

    # 5) IP-level detection scoring
    alerted_ips = {a['src_ip'] for a in alerts if a['src_ip']}
    tp = attacker_ips & alerted_ips
    fp_ips = alerted_ips - attacker_ips
    fn_ips = attacker_ips - alerted_ips
    prec = len(tp) / len(alerted_ips) if alerted_ips else 0.0
    rec  = len(tp) / len(attacker_ips) if attacker_ips else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    ip_score = dict(
        attacker_ips=sorted(attacker_ips),
        alerted_ips=sorted(alerted_ips),
        tp=sorted(tp), fp=sorted(fp_ips), fn=sorted(fn_ips),
        precision=round(prec, 3), recall=round(rec, 3), f1=round(f1, 3),
    )

    # 6) Alert breakdown by rule
    rule_counts = {}
    for a in alerts:
        rule_counts[a['rule']] = rule_counts.get(a['rule'], 0) + 1

    # 7) Attack timeline
    print('Loading attacker action timeline …', flush=True)
    attack_timeline = _load_attacks_log(root)
    action_counts = {}
    for _, action in attack_timeline:
        action_counts[action] = action_counts.get(action, 0) + 1

    # 8) Label-group timing: for each attack phase, was an alert raised within ±5 min?
    phase_detection = {}
    for group, fn in ATTACK_LABEL_GROUPS.items():
        phase_lines = set()
        for gather_path, line_map in all_labels.items():
            for ln, lbls in line_map.items():
                if fn(lbls):
                    phase_lines.add((gather_path, ln))

        if not phase_lines:
            phase_detection[group] = 'no labelled lines'
            continue

        # Find timestamps of labelled lines by re-reading (sample – first 500 only)
        timestamps = []
        seen = 0
        for gather_path, lineno in sorted(phase_lines):
            if seen >= 500:
                break
            if not os.path.isfile(gather_path):
                continue
            try:
                with open(gather_path, errors='replace') as fh:
                    for cur, raw in enumerate(fh, start=1):
                        if cur == lineno:
                            from siem.parser import parse_line
                            e = parse_line(raw, year)
                            if e:
                                timestamps.append(e['ts'])
                            break
                seen += 1
            except OSError:
                pass

        if not timestamps:
            phase_detection[group] = 'no parseable lines'
            continue

        t_min, t_max = min(timestamps), max(timestamps)
        window_alerts = [a for a in alerts if t_min - 300 <= a['ts'] <= t_max + 300]
        phase_detection[group] = {
            'labelled_lines': len(phase_lines),
            'time_range': [t_min, t_max],
            'alerts_in_window': len(window_alerts),
            'detected': len(window_alerts) > 0,
            'alert_rules': list({a['rule'] for a in window_alerts}),
        }

    elapsed = round(time.perf_counter() - t0, 1)

    result = dict(
        dataset=dict(root=os.path.abspath(root), label_files=n_label_files,
                     labelled_lines=n_label_lines, year=year),
        db=dict(path=db_path, events=db_stats['events'], alerts=db_stats['alerts'],
                categories=db_stats['categories']),
        ingestion_coverage=coverage,
        ip_level_detection=ip_score,
        alerts_by_rule=rule_counts,
        attack_phase_detection=phase_detection,
        attack_timeline_summary=dict(total_actions=len(attack_timeline),
                                     action_counts=action_counts),
        elapsed_s=elapsed,
    )

    with open(out_path, 'w') as fh:
        json.dump(result, fh, indent=2)
    print(json.dumps(result, indent=2))
    print(f'\nResults written to {out_path}  ({elapsed}s)')
    return result


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Evaluate LightSIEM on the Russell Mitchell dataset')
    ap.add_argument('root', help='Path to the Russell Mitchell dataset root')
    ap.add_argument('--db', default='rm.db', help='SIEM database to load alerts from')
    ap.add_argument('--out', default='results_russell.json', help='Output JSON scorecard')
    ap.add_argument('--year', type=int, default=2022, help='Syslog year (default 2022)')
    x = ap.parse_args()
    evaluate(x.root, x.db, x.out, year=x.year)
