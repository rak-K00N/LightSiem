#!/usr/bin/env python3
"""LightSIEM command line.
  python lightsiem.py demo                       generate sample logs, ingest them, open the dashboard
  python lightsiem.py ingest auth.log access.log --db siem.db --year 2026
  python lightsiem.py train normal_auth.log normal_access.log --out model.pkl     (learn 'normal' from clean logs)
  python lightsiem.py ingest auth.log access.log --db siem.db --model model.pkl  (rules + ML)
  python lightsiem.py follow /var/log/auth.log --db siem.db      (live tail)
  python lightsiem.py serve --db siem.db --port 8080
  python lightsiem.py evaluate                    reproduce the evaluation scorecard

Russell Mitchell dataset:
  python lightsiem.py russell ingest /path/to/russellmitchell --db rm.db
  python lightsiem.py russell ingest /path/to/russellmitchell --db rm.db --host intranet_server --host inet-firewall
  python lightsiem.py russell evaluate /path/to/russellmitchell --db rm.db
"""
import argparse, json, os, sys, subprocess
from siem.store import Store
from siem.ingest import ingest, follow
from siem.detect import Detector
from siem.server import serve


def peak_mb():
    """Peak resident memory of THIS process (VmHWM resets on exec, unlike ru_maxrss)."""
    try:
        for l in open('/proc/self/status'):
            if l.startswith('VmHWM'):
                return round(int(l.split()[1]) / 1024, 1)
    except OSError:
        pass
    import resource
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)


def main():
    ap = argparse.ArgumentParser(description='LightSIEM')
    sub = ap.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('ingest'); a.add_argument('files', nargs='+'); a.add_argument('--db', default='siem.db'); a.add_argument('--year', type=int, default=2026); a.add_argument('--model', help='ML model file (see train)')
    t = sub.add_parser('train'); t.add_argument('files', nargs='+'); t.add_argument('--out', default='model.pkl'); t.add_argument('--year', type=int, default=2026); t.add_argument('--kind', choices=['iforest', 'rf'], default='iforest'); t.add_argument('--attackers', help='text file of confirmed-attacker IPs (needed for --kind rf)'); t.add_argument('--augment', action='store_true', help='evasion-aware training (rf only)')
    f = sub.add_parser('follow'); f.add_argument('file'); f.add_argument('--db', default='siem.db'); f.add_argument('--year', type=int, default=2026)
    s = sub.add_parser('serve'); s.add_argument('--db', default='siem.db'); s.add_argument('--port', type=int, default=8080)
    d = sub.add_parser('demo'); d.add_argument('--port', type=int, default=8080)
    sub.add_parser('evaluate')

    # -- Russell Mitchell subcommand ---------------------------------------------------
    rm = sub.add_parser('russell', help='Work with the Russell Mitchell dataset')
    rm_sub = rm.add_subparsers(dest='rm_cmd', required=True)

    rm_ing = rm_sub.add_parser('ingest', help='Ingest a Russell Mitchell dataset root')
    rm_ing.add_argument('root', help='Path to the dataset root (contains gather/, labels/)')
    rm_ing.add_argument('--db', default='rm.db', help='SQLite output database')
    rm_ing.add_argument('--year', type=int, default=2022,
                        help='Calendar year for syslog timestamps (default: 2022)')
    rm_ing.add_argument('--host', action='append', dest='hosts', metavar='HOST',
                        help='Only ingest logs for HOST (repeatable). Omit to ingest all hosts.')
    rm_ing.add_argument('--type', action='append', dest='types', metavar='TYPE',
                        help='Only ingest logs of TYPE (apache, auth, syslog, openvpn, dnsmasq). '
                             'Omit to ingest all parseable types.')
    rm_ing.add_argument('--model', help='ML model file (see train)')
    rm_ing.add_argument('--serve', action='store_true',
                        help='Launch the web dashboard after ingestion')
    rm_ing.add_argument('--port', type=int, default=8080)

    rm_eval = rm_sub.add_parser('evaluate',
                                help='Evaluate LightSIEM detections against Russell Mitchell labels')
    rm_eval.add_argument('root', help='Path to the dataset root')
    rm_eval.add_argument('--db', default='rm.db',
                         help='Existing SQLite database (created by "russell ingest")')
    rm_eval.add_argument('--out', default='results_russell.json',
                         help='Where to write the JSON scorecard')

    rm_ls = rm_sub.add_parser('list', help='List log files in a Russell Mitchell dataset')
    rm_ls.add_argument('root', help='Path to the dataset root')

    x = ap.parse_args()

    if x.cmd == 'ingest':
        ml = None
        if x.model:
            from siem.ml import MLDetector
            ml = MLDetector.load(x.model)
        r = ingest(x.files, Store(x.db), Detector(), x.year, ml=ml)
        r['peak_rss_mb'] = peak_mb()
        print(json.dumps(r))

    elif x.cmd == 'train':
        import heapq
        from siem.ml import MLDetector
        from siem.ingest import read_events
        m = MLDetector(kind=x.kind); bad = set(open(x.attackers).read().split()) if x.attackers else None
        info = m.fit(heapq.merge(*[read_events(p, x.year) for p in x.files], key=lambda e: e['ts']), bad, augment=x.augment)
        m.save(x.out); print(json.dumps(info), '-> saved', x.out)

    elif x.cmd == 'follow':
        follow(x.file, Store(x.db), Detector(), x.year)

    elif x.cmd == 'serve':
        serve(Store(x.db), x.port)

    elif x.cmd == 'demo':
        from siem.gen_logs import generate
        os.makedirs('demo_data', exist_ok=True)
        generate('demo_data', seed=7, scale=0.3)
        if os.path.exists('demo.db'):
            os.remove('demo.db')
        st = Store('demo.db')
        print(ingest(['demo_data/auth.log', 'demo_data/access.log'], st, Detector(), 2026))
        serve(st, x.port)

    elif x.cmd == 'evaluate':
        sys.exit(subprocess.call([sys.executable, 'evaluate.py']))

    elif x.cmd == 'russell':
        from siem.russell import collect_log_files, ingest_dataset

        if x.rm_cmd == 'list':
            files = collect_log_files(x.root)
            print(f'{"HOST":<25} {"TYPE":<14} PATH')
            print('-' * 80)
            for path, host, ltype in files:
                rel = os.path.relpath(path, x.root)
                print(f'{host:<25} {ltype:<14} {rel}')
            print(f'\n{len(files)} parseable log file(s) found.')

        elif x.rm_cmd == 'ingest':
            ml = None
            if x.model:
                from siem.ml import MLDetector
                ml = MLDetector.load(x.model)
            st = Store(x.db)
            r = ingest_dataset(x.root, st, year=x.year,
                               host_filter=x.hosts, type_filter=x.types, ml=ml)
            r['peak_rss_mb'] = peak_mb()
            r['db'] = x.db
            print(json.dumps(r, indent=2))
            if x.serve:
                serve(st, x.port)

        elif x.rm_cmd == 'evaluate':
            sys.exit(subprocess.call([sys.executable, 'evaluate_russell.py',
                                      x.root, '--db', x.db, '--out', x.out]))


if __name__ == '__main__':
    main()
