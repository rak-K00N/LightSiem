"""Stage 1-2: parse raw log lines into one common event schema (dict).

Supported: Linux syslog/auth.log (sshd + other daemons) and nginx/Apache 'combined' access logs.
Common schema: ts (epoch s), host, source, category, severity, src_ip, user, status, msg, raw
"""
import re, calendar

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
SYSLOG = re.compile(r'^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+([\w\-/.]+)(?:\[\d+\])?:\s+(.*)$')
FAILED = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')
INVALID = re.compile(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)')
ACCEPT = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')
NGINX = re.compile(r'^(\d+\.\d+\.\d+\.\d+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+|-)')


def _nginx_ts(s):                      # 15/Sep/2026:12:00:01 +0000
    t = calendar.timegm((int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]), int(s[12:14]), int(s[15:17]), int(s[18:20])))
    if len(s) > 21:                    # apply timezone offset -> UTC
        off = (int(s[22:24]) * 3600 + int(s[24:26]) * 60) * (1 if s[21] == '+' else -1)
        t -= off
    return t


def parse_line(line, year):
    line = line.rstrip('\n')
    m = SYSLOG.match(line)
    if m:
        mon, day, H, M, S, host, prog, msg = m.groups()
        ts = calendar.timegm((year, MONTHS.get(mon, 1), int(day), int(H), int(M), int(S)))
        ev = dict(ts=ts, host=host, source=prog, category='other', severity='info',
                  src_ip=None, user=None, status=None, msg=msg, raw=line)
        if prog == 'sshd':
            f = FAILED.search(msg)
            if f:
                ev.update(category='ssh_fail', severity='warning', user=f.group(1), src_ip=f.group(2))
            else:
                a = ACCEPT.search(msg)
                if a:
                    ev.update(category='ssh_ok', user=a.group(1), src_ip=a.group(2))
                else:
                    i = INVALID.search(msg)
                    if i:
                        ev.update(category='ssh_invalid_user', severity='warning', user=i.group(1), src_ip=i.group(2))
        return ev
    n = NGINX.match(line)
    if n:
        ip, user, tstr, method, path, status, _ = n.groups()
        st = int(status)
        sev = 'warning' if st >= 500 else 'info'
        return dict(ts=_nginx_ts(tstr), host='web', source='nginx', category='http', severity=sev, src_ip=ip,
                    user=None if user == '-' else user, status=st, msg=f'{method} {path} {st}', raw=line)
    return None
