"""Röktest som körs inne i en NetAtlas-container (startas av docker_smoke.sh):

    docker exec -i netatlas-test python - <fas> < tests/docker_smoke.py

Faser: seed (lägg in testdata), verify (finns datan kvar?), twofa (inloggning med kod), hostnet (full skanning).
Ansluter till appen i den egna containern på 127.0.0.1 och använder containerns testkonto (APP_USER/APP_PASSWORD).
Valfritt: SMOKE_PING_IP (en adress i nätet som ska svara) och SMOKE_CIDR (nät att skanna i hostnet-fasen)."""
import http.cookiejar
import importlib.util
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

PHASE = sys.argv[1] if len(sys.argv) > 1 else 'seed'
TLS = (os.environ.get('TLS') or 'on').lower() not in ('off', 'false', '0', 'no', 'nej')
B = f"{'https' if TLS else 'http'}://127.0.0.1:{os.environ.get('PORT') or '8770'}"
PING_IP, CIDR = os.environ.get('SMOKE_PING_IP', ''), os.environ.get('SMOKE_CIDR', '')
jar = http.cookiejar.CookieJar()
NoRedirect = type('NoRedirect', (urllib.request.HTTPRedirectHandler,), {'redirect_request': lambda *a, **k: None})
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
                                 urllib.request.HTTPCookieProcessor(jar), NoRedirect())
spec = importlib.util.spec_from_file_location('h', '/app/netatlas-helper.py')
H = importlib.util.module_from_spec(spec)
spec.loader.exec_module(H)
U, P = os.environ['APP_USER'], os.environ['APP_PASSWORD']
ok = fail = 0


def req(path, data=None, headers=None, raw=False):
    h = {'X-ITInv': '1', **(headers or {})}
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault('Content-Type', 'application/json')
    r = urllib.request.Request(B + path, data=body, headers=h, method='POST' if body is not None else 'GET')
    try:
        resp = op.open(r, timeout=60)
        code, hd, b = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        code, hd, b = e.code, e.headers, e.read()
    if raw:
        return code, hd, b
    try:
        return code, hd, json.loads(b or b'null')
    except ValueError:
        return code, hd, b


def check(name, cond, extra=''):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  {'OK ' if cond else 'FEL'}  {name} {'' if cond else extra}", flush=True)


def login():
    """Logga in; erbjuds tvåsteg (första gången, LOGIN_2FA=optional) hoppar vi över."""
    c, h, j = req('/login', {'user': U, 'pass': P})
    if c == 200 and isinstance(j, dict) and j.get('offer'):
        c, h, j = req('/login', {'user': U, 'pass': P, 'skip': True})
    return c, j


V1 = json.dumps({'app': 'netatlas', 'v': 1, 'salt': 'AA', 'iv': 'BB', 'ct': 'test-' + 'x' * 2000})
BLOB = b'{"v":1,"iv":"x","ct":"' + b'y' * 300000 + b'"}'

if PHASE == 'seed':
    c, h, j = req('/health'); check('health', c == 200 and j.get('db') == 'ok', j)
    c, h, j = req('/', raw=True); check('/ -> /login utan inloggning', c == 302 and h['Location'] == '/login', c)
    c, h, j = req('/login', {'user': U, 'pass': 'fel'}); check('fel lösenord nekas', c == 401, c)
    c, h, j = req('/login', {'user': U, 'pass': P}); check('första inloggningen erbjuder tvåsteg', c == 200 and j.get('offer'), (c, j))
    c, h, j = req('/login', {'user': U, 'pass': P, 'skip': True}); check('hoppa över -> inloggad', c == 200 and j.get('ok'), (c, j))
    c, h, j = req('/api/info'); check('appen vet att tvåsteg inte är aktiverat', j.get('login2fa') == {'mode': 'optional', 'enrolled': False}, j.get('login2fa'))
    jar.clear()
    c, j = login(); check('nästa inloggning utan fråga', c == 200 and j.get('ok'), (c, j))
    ck = [k for k in jar if k.name == 'netatlas_session']
    check('sessionskaka (Secure med TLS)', ck and (ck[0].secure or not TLS), ck)
    c, h, j = req('/', raw=True); check('appen levereras utan inbäddade planer', c == 200 and b'id="shell"' in j and b'<script id="housePlans"' not in j, c)
    c, h, j = req('/api/info'); check('serverläge', j.get('storage') == 'server', j)
    c, h, j = req('/api/vault', {'version': 0, 'data': V1}); check('valv sparat (version 1)', c == 200 and j.get('version') == 1, j)
    c, h, j = req('/api/vault/hint', {'hint': 'röktest'}); check('ledtråd sparad', c == 200)
    c, h, j = req('/api/file?id=smoketest1', BLOB, {'Content-Type': 'text/plain'}); check('bilaga 300 kB sparad', c == 200 and j.get('size') == len(BLOB), j)
    c, h, j = req('/api/backup', {'data': V1, 'keep': 5}); check('säkerhetskopia i /data/backups', c == 200 and j.get('dir') == '/data/backups' and j.get('filesCopied') == 1, j)
    c, h, j = req('/api/mfa/setup', {}); check('valvets tvåsteg: setup', c == 200 and j.get('kid'), j)
    c, h, j = req('/api/mfa/confirm', {'kid': j['kid'], 'code': H.totp_at(j['secret'], time.time())}); check('valvets tvåsteg: förseglat och bekräftat', c == 200 and j.get('key'), j)
    if PING_IP:
        c, h, j = req('/api/ping?ips=' + PING_IP); check(f'ping {PING_IP} från containern', c == 200 and j['status'].get(PING_IP) is True, j)
elif PHASE == 'verify':
    c, j = login(); check('inloggning efter omstart', c == 200 and j.get('ok'), (c, j))
    c, h, j = req('/api/vault'); check('valvet finns kvar (version 1, ledtråd)', j.get('version') == 1 and j.get('data') == V1 and j.get('hint') == 'röktest', {k: j.get(k) for k in ('version', 'hint')})
    c, h, j = req('/api/file?id=smoketest1', raw=True); check('bilagan finns kvar', c == 200 and j == BLOB, c)
    c, h, j = req('/api/backups'); check('säkerhetskopian finns kvar', c == 200 and len(j.get('backups', [])) >= 1, j)
elif PHASE == 'twofa':
    c, j = login(); check('tvåsteg på: QR-registrering', c == 200 and j.get('setup') and j.get('secret'), j)
    sec, tok = j['secret'], j['token']
    c, h, j = req('/login', {'user': U, 'pass': P, 'setup': tok, 'code': H.totp_at(sec, time.time())}); check('registrering med kod', c == 200 and j.get('ok'), j)
    jar.clear()
    c, j = login(); check('nästa inloggning kräver kod', c == 200 and j.get('needCode'), j)
    c, h, j = req('/login', {'user': U, 'pass': P, 'code': H.totp_at(sec, time.time() + 30)}); check('inloggning med kod', c == 200 and j.get('ok'), j)
    c, h, j = req('/api/vault'); check('valvet nås efter tvåstegsinloggning', j.get('version') == 1, j.get('version'))
elif PHASE == 'hostnet':
    c, j = login(); check('inloggning (host-nät)', c == 200 and j.get('ok'), (c, j))
    c, h, j = req('/api/info'); check('host-läge rapporteras', j.get('hostNet') is True, j)
    c, h, j = req('/api/vault'); check('valvet nås via 127.0.0.1', j.get('version') == 1, j.get('version'))
    if CIDR:
        t0 = time.time()
        c, h, j = req('/api/scan?cidr=' + CIDR)
        hosts = j.get('hosts', []) if isinstance(j, dict) else []
        withmac = [x for x in hosts if x.get('mac')]
        check(f'skanning av {CIDR} ({len(hosts)} svarade, {time.time() - t0:.0f} s)', c == 200 and len(hosts) > 1, (c, str(j)[:200]))
        check(f'MAC-adresser syns ({len(withmac)} av {len(hosts)})', len(withmac) >= 1)
    c, h, j = req('/api/mobile/share', {'html': '<html><body>test</body></html>', 'minutes': 1})
    check('mobildelning tillåten i host-läge', c == 200 and isinstance(j, dict) and 'urls' in j, j)
    req('/api/mobile/stop', {})
print(f'  -> {ok} OK, {fail} FEL')
sys.exit(1 if fail else 0)
