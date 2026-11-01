"""Synthetic log generator with GROUND TRUTH labels (so detection can be scored).

Produces auth.log (syslog/sshd) and access.log (nginx combined) for one day, with:
 - normal users: SSH logins with occasional typos, web clients with ~4% 404s, daily load cycle
 - 20 SSH brute-force bursts, 5 low-and-slow SSH attackers, 4 'brute-force then success' compromises
 - 15 web scanners (hundreds of 404s in 2 minutes)
 - one 10-minute traffic flood (DoS-like) from 5 IPs
All data is synthetic; attacker IPs come from a separate address range so labels are exact.
"""
import random, math, calendar, json, os, time

MON = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
PATHS = ['/', '/index.html', '/login', '/api/items', '/api/user', '/static/app.js', '/static/site.css', '/about', '/contact', '/products', '/cart']
SCAN = ['/wp-admin', '/.env', '/phpmyadmin', '/admin.php', '/.git/config', '/backup.zip', '/config.json', '/server-status', '/xmlrpc.php', '/shell.php']
USERS = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi']
ATK_USERS = ['root', 'admin', 'oracle', 'test', 'ubuntu', 'postgres', 'user', 'guest']
UA = 'Mozilla/5.0'


def _sys(ts, prog, msg, pid):
    g = time.gmtime(ts)
    return f'{MON[g.tm_mon-1]} {g.tm_mday:2d} {g.tm_hour:02d}:{g.tm_min:02d}:{g.tm_sec:02d} web01 {prog}[{pid}]: {msg}'


def _ngx(ts, ip, path, st, size):
    g = time.gmtime(ts)
    return f'{ip} - - [{g.tm_mday:02d}/{MON[g.tm_mon-1]}/{g.tm_year}:{g.tm_hour:02d}:{g.tm_min:02d}:{g.tm_sec:02d} +0000] "GET {path} HTTP/1.1" {st} {size} "-" "{UA}"'


def generate(outdir, seed=7, scale=1.0, attacks=True, hard=False, crawlers=None):
    if crawlers is None: crawlers = hard
    R = random.Random(seed)
    T0 = calendar.timegm((2026, 9, 15, 0, 0, 0))
    ips_used = set()

    def ip(lo, hi):
        while True:
            a = f'{R.randint(lo, hi)}.{R.randint(0, 255)}.{R.randint(0, 255)}.{R.randint(1, 254)}'
            if a not in ips_used:
                ips_used.add(a); return a

    def when():  # daily load cycle: busy by day, quiet at night (rejection sampling)
        while True:
            t = R.random() * 86400
            if R.random() < 0.6 + 0.4 * math.sin(2 * math.pi * (t - 9 * 3600) / 86400):
                return T0 + int(t)

    auth, web, truth = [], [], {'ssh_bruteforce': {}, 'ssh_slow': {}, 'ssh_compromise': {}, 'web_scan': {}, 'stealth_scan': {}, 'legit_crawlers': []}
    # ---- normal web traffic -------------------------------------------------------------------
    clients = [ip(11, 99) for _ in range(int(2000 * max(scale, .2)))]
    weights = [1 / (i + 1) ** 0.9 for i in range(len(clients))]           # a few heavy clients
    for _ in range(int(150000 * scale)):
        c = R.choices(clients, weights)[0]; r = R.random()
        st = 200 if r < .87 else 304 if r < .93 else 404 if r < .97 else 301 if r < .995 else 500
        web.append((when(), _ngx(0, c, R.choice(PATHS), st, R.randint(200, 9000))))
    # ---- normal ssh (typos accumulate over the day for some users) -----------------------------
    for k in range(60):
        u, i = R.choice(USERS), '192.168.%d.%d' % (R.randint(0, 9), R.randint(2, 250)); ips_used.add(i)
        typos = R.randint(10, 18) if k < 10 else R.randint(0, 2)           # 10 'forgetful' users
        for _ in range(R.randint(15, 30)):
            t = when(); fails = 1 if typos > 0 and R.random() < .5 else 0
            if fails:
                typos -= 1; auth.append((t, _sys(t, 'sshd', f'Failed password for {u} from {i} port {R.randint(30000,60000)} ssh2', R.randint(1000, 9999)))); t += R.randint(5, 20)
            auth.append((t, _sys(t, 'sshd', f'Accepted password for {u} from {i} port {R.randint(30000,60000)} ssh2', R.randint(1000, 9999))))
    for _ in range(int(15000 * scale)):                                    # background noise
        t = when(); auth.append((t, _sys(t, 'CRON', 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)', R.randint(1000, 9999))))
    # ---- attacks ------------------------------------------------------------------------------
    def fail_line(t, a, user):
        inv = 'invalid user ' if user not in ('root',) else ''
        return (t, _sys(t, 'sshd', f'Failed password for {inv}{user} from {a} port {R.randint(30000,60000)} ssh2', R.randint(1000, 9999)))
    A = 1 if attacks else 0
    for _ in range(20 * A):                                                # brute-force bursts
        a, s = ip(101, 199), T0 + R.randint(3600, 80000); truth['ssh_bruteforce'][a] = s
        for _ in range(R.randint(30, 80)):
            t = s + R.randint(0, 90); auth.append(fail_line(t, a, R.choice(ATK_USERS)))
    for _ in range(5 * A):                                                 # low-and-slow
        a, s = ip(101, 199), T0 + R.randint(3600, 60000); truth['ssh_slow'][a] = s
        for k in range(180):
            auth.append(fail_line(s + k * 40 + R.randint(0, 5), a, R.choice(ATK_USERS)))
    for _ in range(4 * A):                                                 # brute-force then success
        a, s = ip(101, 199), T0 + R.randint(3600, 80000); truth['ssh_compromise'][a] = s
        for _ in range(12):
            auth.append(fail_line(s + R.randint(0, 60), a, 'admin'))
        t = s + 75; auth.append((t, _sys(t, 'sshd', f'Accepted password for admin from {a} port 40022 ssh2', 4242)))
    for _ in range(15 * A):                                                # web scanners
        a, s = ip(101, 199), T0 + R.randint(3600, 80000); truth['web_scan'][a] = s
        for _ in range(300):
            t = s + R.randint(0, 120); web.append((t, _ngx(0, a, R.choice(SCAN) + str(R.randint(0, 99)), 404 if R.random() < .92 else 200, 153)))
    flood = [ip(101, 199) for _ in range(5)]; f0 = T0 + 14 * 3600; truth['spike'] = [f0, f0 + 600]
    for _ in range(int(30000 * scale) * A):                                # 10-minute flood
        web.append((f0 + R.randint(0, 599), _ngx(0, R.choice(flood), '/', 200, 5120)))
    # ---- HARD cases (only when hard=True; drawn last so earlier data is unchanged) ------------------
    if hard:
        for _ in range(10):      # stealth scanners: ~13 errors/min -> stays UNDER the web_scan rule (25 per 60 s)
            a, s = ip(101, 199), T0 + R.randint(3600, 80000); truth['stealth_scan'][a] = s
            for k in range(300):
                web.append((s + k * 4, _ngx(0, a, R.choice(SCAN) + str(R.randint(0, 999)), 404 if R.random() < .85 else 200, 153)))
    if crawlers:
        for _ in range(5):       # LEGITIMATE crawlers: many distinct URLs, ~8% 404s (hard negatives)
            a = ip(11, 99); truth['legit_crawlers'].append(a)
            for _ in range(6):
                s = T0 + R.randint(3600, 80000)
                for k in range(250):
                    web.append((s + k * 2, _ngx(0, a, f'/products/{R.randint(0, 5000)}', 404 if R.random() < .08 else 200, R.randint(500, 4000))))
    # ---- write (sorted; the nginx line needs its real timestamp) -------------------------------
    os.makedirs(outdir, exist_ok=True)
    auth.sort(key=lambda x: x[0])
    open(os.path.join(outdir, 'auth.log'), 'w').write('\n'.join(l for _, l in auth) + '\n')
    web.sort(key=lambda x: x[0])
    with open(os.path.join(outdir, 'access.log'), 'w') as f:
        for t, l in web:
            g = time.gmtime(t)
            head, rest = l.split(' [', 1)
            rest = rest.split('] ', 1)[1]
            f.write(f'{head} [{g.tm_mday:02d}/{MON[g.tm_mon-1]}/{g.tm_year}:{g.tm_hour:02d}:{g.tm_min:02d}:{g.tm_sec:02d} +0000] {rest}\n')
    json.dump(truth, open(os.path.join(outdir, 'truth.json'), 'w'), indent=1)
    return {'auth_lines': len(auth), 'web_lines': len(web)}
