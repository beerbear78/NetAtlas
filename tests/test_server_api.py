"""API-test av serverläget (inloggning, tvåsteg, valv, bilagor, säkerhetskopior, spärrar).

    python tests/test_server_api.py

Körs lokalt utan Docker (se server_harness.py). Avslutas med felkod om något test misslyckas."""
import http.cookiejar
import json
import os
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request

os.environ['TEST_PORT'] = '8784'
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server_harness as hs  # noqa: E402

srv = hs.serve(8784)
threading.Thread(target=srv.serve_forever, daemon=True).start()
B = 'http://127.0.0.1:8784'
jar = http.cookiejar.CookieJar()
NoRedirect = type('NoRedirect', (urllib.request.HTTPRedirectHandler,), {'redirect_request': lambda *a, **k: None})
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
ok = fail = 0


def req(path, data=None, method=None, headers=None, raw=False):
    h = {'X-ITInv': '1', **(headers or {})}
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault('Content-Type', 'application/json')
    r = urllib.request.Request(B + path, data=body, method=method or ('POST' if body is not None else 'GET'), headers=h)
    try:
        resp = op.open(r)
        code, hdrs, b = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        code, hdrs, b = e.code, e.headers, e.read()
    if raw:
        return code, hdrs, b
    try:
        return code, hdrs, json.loads(b or b'null')
    except ValueError:
        return code, hdrs, b


def check(name, cond, extra=''):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(f"  {'OK ' if cond else 'FEL'}  {name} {'' if cond else extra}")


H = hs.sa.helper
U, P = os.environ['APP_USER'], os.environ['APP_PASSWORD']

c, h, j = req('/health'); check('health 200', c == 200 and j['db'] == 'ok', j)
c, h, j = req('/', raw=True); check('/ utan inloggning -> /login', c == 302 and h['Location'] == '/login', c)
c, h, j = req('/api/info'); check('API utan inloggning -> 401', c == 401 and j.get('login') is True, (c, j))
c, h, j = req('/login', raw=True); check('inloggningssidan', c == 200 and b'Logga in' in j, c)
c, h, j = req('/login', {'user': U, 'pass': 'fel'}); check('fel lösenord -> 401', c == 401, (c, j))
c, h, j = req('/login', {'user': U, 'pass': P}, headers={'Origin': 'http://evil.example'}); check('annan Origin -> 403', c == 403, (c, j))
c, h, j = req('/login', {'user': U, 'pass': P}); check('första inloggningen: tvåsteg erbjuds', c == 200 and j.get('offer') and not j.get('ok'), j)
check('ingen inloggning innan valet', not any(k.name == 'netatlas_session' for k in jar))
c, h, j = req('/login', {'user': U, 'pass': P, 'enroll': True}); check('"Aktivera nu" -> QR-registrering (frivillig)', c == 200 and j.get('setup') and j.get('optional'), j)
c, h, j = req('/login', {'user': U, 'pass': P, 'skip': True}); check('"Hoppa över" -> inloggad', c == 200 and j.get('ok'), j)
check('sessionskaka satt', any(k.name == 'netatlas_session' for k in jar))
c, h, j = req('/api/info'); check('appen ser att tvåsteg inte är aktiverat', j.get('login2fa') == {'mode': 'optional', 'enrolled': False}, j.get('login2fa'))
jar.clear()
c, h, j = req('/login', {'user': U, 'pass': P}); check('nästa inloggning frågar inte igen', c == 200 and j.get('ok'), j)
c, h, j = req('/api/info'); check('info: storage=server', c == 200 and j.get('storage') == 'server', j)
c, h, j = req('/', raw=True); check('/ inloggad -> appen', c == 200 and b'NetAtlas' in j, c)
c, h, j = req('/api/vault'); check('tomt valv', c == 200 and j['version'] == 0 and j['data'] is None, j)
c, h, j = req('/api/vault', {'version': 0, 'data': 'okrypterat'}); check('okrypterat valv nekas', c == 400, (c, j))
V1 = json.dumps({'app': 'netatlas', 'v': 1, 'salt': 'AA', 'iv': 'BB', 'ct': 'CC'})
c, h, j = req('/api/vault', {'version': 0, 'data': V1}); check('nytt valv -> version 1', c == 200 and j['version'] == 1, j)
c, h, j = req('/api/vault', {'version': 0, 'data': V1}); check('krock (version 0 igen) -> 409', c == 409 and j.get('conflict') and j['version'] == 1, j)
c, h, j = req('/api/vault', {'version': 1, 'data': V1.replace('CC', 'DD')}); check('spara version 1 -> 2', c == 200 and j['version'] == 2, j)
c, h, j = req('/api/vault/hint', {'hint': 'samma som NAS'}); check('ledtråd sparad', c == 200)
c, h, j = req('/api/vault'); check('valv + ledtråd läses', j['version'] == 2 and '"DD"' in j['data'] and j['hint'] == 'samma som NAS', j)
blob = b'{"v":1,"iv":"x","ct":"' + b'z' * 5000 + b'"}'
c, h, j = req('/api/file?id=abc123def', blob, headers={'Content-Type': 'text/plain'}); check('bilaga sparad', c == 200 and j['size'] == len(blob), j)
c, h, j = req('/api/file?id=abc123def', raw=True); check('bilaga läses', c == 200 and j == blob, c)
c, h, j = req('/api/file?id=../etc', raw=True); check('ogiltigt fil-id nekas', c == 400, c)
c, h, j = req('/api/backup', {'data': V1, 'keep': 5}); check('säkerhetskopia till /data/backups', c == 200 and j['filesCopied'] == 1 and j['dir'].endswith('backups'), j)
c, h, j = req('/api/backup', {'data': V1, 'keep': 5, 'dir': 'C:\\Windows\\Temp'}); check('egen mapp ignoreras på servern', c == 200 and j['dir'].endswith('backups'), j)
c, h, j = req('/api/backups'); check('lista kopior', c == 200 and len(j['backups']) >= 1, j)
c, h, j = req('/api/file-del?id=abc123def'); check('bilaga borttagen', c == 200)
c, h, j = req('/api/file?id=abc123def'); check('borttagen bilaga -> 404', c == 404, c)
c, h, j = req('/api/mfa/setup', {}); check('valvets tvåsteg: setup', c == 200 and j.get('kid') and j.get('secret'), j)
kid, msec = j['kid'], j['secret']
c, h, j = req('/api/mfa/confirm', {'kid': kid, 'code': H.totp_at(msec, time.time())}); check('valvets tvåsteg: bekräfta -> nyckeldel', c == 200 and j.get('key'), j)
raw_mfa = hs.sa.STORE.kv_get('mfa') or ''
check('tvåstegsnycklar förseglade i databasen', '"seal:' in raw_mfa and 'plain:' not in raw_mfa, raw_mfa[:80])
c, h, j = req('/api/mfa/unlock', {'kid': kid, 'code': H.totp_at(msec, time.time() + 30)}); check('valvets tvåsteg: lås upp', c == 200 and j.get('key'), j)
c, h, j = req('/api/action', {'action': 'ssh', 'ip': '192.168.1.10', 'user': 'root'}); check('SSH-knapp: tydligt fel på servern', c == 400 and 'server' in j.get('error', ''), j)
c, h, j = req('/api/mobile/share', {'html': '<html>x</html>', 'minutes': 5}); check('mobildelning kräver host-nätverk', c == 400 and 'host' in j.get('error', ''), j)
c, h, j = req('/api/info', headers={'Host': 'evil.example:8784'}); check('godtyckligt värdnamn ok utan ALLOWED_HOSTS', c == 200, c)
good = [k for k in jar if k.name == 'netatlas_session'][0]
v0 = good.value
good.value = v0[:-3] + ('AAA' if not v0.endswith('AAA') else 'BBB')
c, h, j = req('/api/info'); check('manipulerad kaka -> 401', c == 401, c)
good.value = v0

# ---- aktivera tvåsteg senare, inifrån appen (Inställningar → Säkerhet) ----
before = v0
c, h, j = req('/api/login2fa'); check('status: inte aktiverat', c == 200 and j == {'mode': 'optional', 'enrolled': False}, j)
c, h, j = req('/api/login2fa/setup', {}); check('aktivera från appen: QR-kod', c == 200 and j.get('secret') and j.get('token'), j)
tok, sec = j['token'], j['secret']
c, h, j = req('/api/login2fa/confirm', {'token': tok, 'code': '000000'}); check('fel kod -> 401', c == 401, j)
c, h, j = req('/api/login2fa/confirm', {'token': tok, 'code': H.totp_at(sec, time.time())}); check('rätt kod -> aktiverat', c == 200 and j.get('ok'), j)
c, h, j = req('/api/info'); check('den här enheten förblir inloggad', c == 200 and j['login2fa']['enrolled'] is True, (c, j))
cur = [k for k in jar if k.name == 'netatlas_session'][0]
after, cur.value = cur.value, before
c, h, j = req('/api/info'); check('andra inloggningar utan kod blir ogiltiga', c == 401, c)
cur.value = after
c, h, j = req('/api/login2fa/setup', {}); check('kan inte aktiveras två gånger', c == 400, j)
jar.clear()
c, h, j = req('/login', {'user': U, 'pass': P}); check('aktiverat: kräver kod', c == 200 and j.get('needCode'), j)
c, h, j = req('/login', {'user': U, 'pass': P, 'code': H.totp_at(sec, time.time())}); check('samma kod igen nekas (återanvändning)', c == 401, j)
c, h, j = req('/login', {'user': U, 'pass': P, 'code': H.totp_at(sec, time.time() + 30)}); check('nästa kod godkänns', c == 200 and j.get('ok'), j)
hs.sa._last_step[0] = 0  # testgenväg: tillåt ytterligare en kod inom samma 90 sekunder
c, h, j = req('/api/login2fa/disable', {'code': '000000'}); check('stänga av med fel kod nekas', c == 401, j)
c, h, j = req('/api/login2fa/disable', {'code': H.totp_at(sec, time.time())}); check('stänga av med rätt kod', c == 200 and j.get('ok'), j)
c, h, j = req('/api/login2fa'); check('status: av igen', j.get('enrolled') is False, j)
jar.clear()
c, h, j = req('/login', {'user': U, 'pass': P}); check('avstängt: inloggning utan kod', c == 200 and j.get('ok'), j)

# ---- lägena required och off ----
hs.sa.LOGIN_2FA = 'required'
c, h, j = req('/api/info'); check('required: inloggning utan tvåsteg blir ogiltig', c == 401, c)
jar.clear()
c, h, j = req('/login', {'user': U, 'pass': P}); check('required: registrering krävs', c == 200 and j.get('setup') and not j.get('optional'), j)
c, h, j = req('/login', {'user': U, 'pass': P, 'skip': True}); check('required: går inte att hoppa över', c == 200 and j.get('setup') and not j.get('ok'), j)
hs.sa.LOGIN_2FA = 'off'
c, h, j = req('/login', {'user': U, 'pass': P}); check('off: ingen fråga om tvåsteg', c == 200 and j.get('ok'), j)
c, h, j = req('/api/login2fa/setup', {}); check('off: kan inte aktiveras', c == 400, j)
hs.sa.LOGIN_2FA = 'optional'
c, h, j = req('/logout', raw=True); check('utloggning', c == 302 and 'Max-Age=0' in (h.get('Set-Cookie') or ''), (c, h.get('Set-Cookie')))
jar.clear()
c, h, j = req('/api/info'); check('efter utloggning -> 401', c == 401, c)
for i in range(5):
    req('/login', {'user': U, 'pass': 'fel'})
c, h, j = req('/login', {'user': U, 'pass': P}); check('spärr efter 5 fel', c == 429, (c, j))

print(f'\n{ok} OK, {fail} FEL')
srv.shutdown()
srv.server_close()
shutil.rmtree(hs.TMP, ignore_errors=True)
sys.exit(1 if fail else 0)
