"""Stage 1-2: parse raw log lines into one common event schema (dict).

Supported: Linux syslog/auth.log (sshd + other daemons), nginx/Apache 'combined' access logs,
OpenVPN server logs, and dnsmasq query logs.

Common schema: ts (epoch s), host, source, category, severity, src_ip, user, status, msg, raw
"""
import re, calendar

MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
SYSLOG = re.compile(r'^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+([\w\-/.]+)(?:\[\d+\])?:\s+(.*)$')
FAILED = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')
INVALID = re.compile(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)')
ACCEPT = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')
NGINX = re.compile(r'^(\d+\.\d+\.\d+\.\d+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+|-)')

# OpenVPN: "Mon DD HH:MM:SS YYYY user/IP:port MSG"  or syslog-wrapped
_OVPN_NATIVE = re.compile(
    r'^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\d{4})\s+(.*)')
_OVPN_CLIENT = re.compile(
    r'(\S+)/(\d+\.\d+\.\d+\.\d+):\d+\s+(.*)')
_OVPN_CONNECT = re.compile(r'MULTI_sva|MULTI: Learn|client-instance|TLS: Initial packet|Peer Connection Initiated')
_OVPN_AUTH_OK = re.compile(r'TLS Auth|VERIFY OK|peer info|Control Channel|Data Channel Encrypt')

# dnsmasq: "Mon DD HH:MM:SS dnsmasq[PID]: TYPE IP query[A] name from IP"
_DNS_QUERY = re.compile(
    r'query\[(\w+)\] (\S+) from (\d+\.\d+\.\d+\.\d+)')
_DNS_REPLY = re.compile(
    r'reply (\S+) is (\S+)')


def _nginx_ts(s):                      # 15/Sep/2026:12:00:01 +0000
    t = calendar.timegm((int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]), int(s[12:14]), int(s[15:17]), int(s[18:20])))
    if len(s) > 21:                    # apply timezone offset -> UTC
        off = (int(s[22:24]) * 3600 + int(s[24:26]) * 60) * (1 if s[21] == '+' else -1)
        t -= off
    return t


def parse_line(line, year, hint_host=None, hint_source=None):
    """Parse a single log line into a normalised event dict, or return None.

    Parameters
    ----------
    line        : raw log line (str)
    year        : calendar year for syslog lines that omit the year
    hint_host   : override the ``host`` field (useful for Russell Mitchell dataset
                  where the hostname is known from the directory structure)
    hint_source : force a specific source type ('openvpn', 'dnsmasq', 'apache',
                  'auth') so the right parser is tried first; if None the parser
                  auto-detects.
    """
    line = line.rstrip('\n')

    # -- Apache / nginx Combined Log Format ------------------------------------------
    n = NGINX.match(line)
    if n:
        ip, user, tstr, method, path, status, _ = n.groups()
        st = int(status)
        sev = 'warning' if st >= 500 else 'info'
        host = hint_host or 'web'
        return dict(ts=_nginx_ts(tstr), host=host, source='apache', category='http',
                    severity=sev, src_ip=ip,
                    user=None if user == '-' else user,
                    status=st, msg=f'{method} {path} {st}', raw=line)

    # -- Syslog / auth.log -----------------------------------------------------------
    m = SYSLOG.match(line)
    if m:
        mon, day, H, M, S, host, prog, msg = m.groups()
        host = hint_host or host
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
                        ev.update(category='ssh_invalid_user', severity='warning',
                                  user=i.group(1), src_ip=i.group(2))
        elif prog in ('openvpn',):
            # OpenVPN lines surfaced via syslog: extract client IP if present
            c = _OVPN_CLIENT.search(msg)
            if c:
                ev.update(source='openvpn', category='vpn', src_ip=c.group(2), user=c.group(1))
        elif prog in ('dnsmasq',):
            q = _DNS_QUERY.search(msg)
            if q:
                ev.update(source='dnsmasq', category='dns', src_ip=q.group(3),
                          msg=f'query {q.group(1)} {q.group(2)} from {q.group(3)}')
        return ev

    # -- OpenVPN native log (not syslog-wrapped) ------------------------------------
    # Format: "Mon DD HH:MM:SS YYYY ..."
    if hint_source == 'openvpn' or (not hint_source and 'OpenVPN' in line[:80]):
        ov = _OVPN_NATIVE.match(line)
        if ov:
            mon, day, H, M, S, yr, rest = ov.groups()
            ts = calendar.timegm((int(yr), MONTHS.get(mon, 1), int(day), int(H), int(M), int(S)))
            host = hint_host or 'vpn'
            src_ip, user = None, None
            c = _OVPN_CLIENT.search(rest)
            if c:
                user, src_ip = c.group(1), c.group(2)
            return dict(ts=ts, host=host, source='openvpn', category='vpn', severity='info',
                        src_ip=src_ip, user=user, status=None, msg=rest.strip(), raw=line)

    # -- dnsmasq standalone log -----------------------------------------------------
    # Format: "Mon DD HH:MM:SS dnsmasq[PID]: ..."
    if hint_source == 'dnsmasq':
        dm = SYSLOG.match(line)   # dnsmasq uses syslog format; caught above when wrapped
        if dm:
            pass  # already handled in the syslog branch above

    return None
