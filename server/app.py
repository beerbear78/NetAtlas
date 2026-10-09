"""NetAtlas som server (Docker): WSGI-app för gunicorn.

Ovanpå netatlas-helper.py läggs inloggning (sessionskaka och valfri tvåstegskod), /health och lagring i
PostgreSQL. Alla befintliga API-anrop körs av hjälpprogrammets egen Handler via en WSGI-adapter, så
funktionerna är desamma som när NetAtlas körs lokalt i Windows.
"""
import base64
import email.message
import hashlib
import hmac
import importlib.util
import io
import json
import os
import secrets
import threading
import time
import traceback
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from urllib.parse import quote, urlparse

from . import config
from .store import Store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))

APP_USER = config.env('APP_USER', 'admin')
APP_PASSWORD = os.environ.get('APP_PASSWORD') or ''
APP_SECRET = config.APP_SECRET
LOGIN_2FA = config.flag('LOGIN_2FA')
SESSION_HOURS = float(config.env('SESSION_HOURS', '12') or 12)
TLS = config.env('TLS', 'on').lower() not in ('off', 'false', '0', 'no', 'nej')
CERT_FILE = config.env('TLS_CERT', os.path.join(config.DATA_DIR, 'certs', 'cert.pem'))

if len(APP_PASSWORD) < 8:
    raise SystemExit('APP_PASSWORD saknas eller är för kort (minst 8 tecken) – sätt det i .env')
if len(APP_SECRET) < 32:
    raise SystemExit('APP_SECRET saknas eller är för kort (minst 32 tecken) – skapa ett med: openssl rand -hex 32')

# hjälpprogrammet laddas som modul (filnamnet har bindestreck)
_spec = importlib.util.spec_from_file_location('netatlas_helper', os.path.join(ROOT, 'netatlas-helper.py'))
helper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helper)

STORE = Store(config.database_url(), APP_SECRET)
helper.STORE = STORE
helper.load_oui()

with open(os.path.join(HERE, 'login.html'), 'rb') as _f:
    LOGIN_HTML = _f.read()

SEC_HEADERS = [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'),
               ('Referrer-Policy', 'same-origin')]


# ---------- svar ----------
def _resp(code, body, ctype, extra=()):
    return code, [('Content-Type', ctype), *SEC_HEADERS, *extra], body


def _json(code, obj, extra=()):
    return _resp(code, json.dumps(obj, ensure_ascii=False).encode('utf-8'), 'application/json; charset=utf-8', extra)


def _redirect(location, extra=()):
    return 302, [('Location', location), *SEC_HEADERS, *extra], b''


# ---------- sessionskaka (signerad med APP_SECRET, inget lagras på servern) ----------
COOKIE = 'netatlas_session'
_SKEY = hmac.new(APP_SECRET.encode(), b'netatlas-session-v1', hashlib.sha256).digest()
_GEN = hashlib.sha256(f'{APP_USER}\0{APP_PASSWORD}'.encode()).hexdigest()[:16]  # nytt lösenord => gamla inloggningar ogiltiga


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def _sign(body):
    return _b64(hmac.new(_SKEY, body.encode(), hashlib.sha256).digest())


def make_session():
    body = _b64(json.dumps({'u': APP_USER, 'exp': int(time.time() + SESSION_HOURS * 3600), 'g': _GEN, 'm': LOGIN_2FA}).encode())
    return body + '.' + _sign(body)


def valid_session(token):
    """Inloggningens innehåll om kakan är äkta och giltig, annars None."""
    body, _, sig = (token or '').partition('.')
    if not body or not hmac.compare_digest(sig.encode(), _sign(body).encode()):
        return None
    try:
        p = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
    except ValueError:
        return None
    ok = p.get('g') == _GEN and p.get('exp', 0) > time.time() and (p.get('m') or not LOGIN_2FA)
    return p if ok else None


def _session_cookie(environ):
    try:
        c = SimpleCookie(environ.get('HTTP_COOKIE') or '')
    except CookieError:
        return ''
    return c[COOKIE].value if COOKIE in c else ''


def _set_cookie(environ, value, max_age=None):
    c = f'{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict'
    if environ.get('wsgi.url_scheme') == 'https':
        c += '; Secure'
    if max_age is not None:
        c += f'; Max-Age={max_age}'
    return ('Set-Cookie', c)


# ---------- spärr mot gissning av lösenord/koder ----------
_fails, _lock = {}, threading.Lock()


def _limited(ip):
    now = time.time()
    with _lock:
        for k in list(_fails):
            _fails[k] = [t for t in _fails[k] if now - t < 300]
            if not _fails[k]:
                del _fails[k]
        return len(_fails.get(ip, [])) >= 5 or sum(map(len, _fails.values())) >= 30


def _fail(ip):
    with _lock:
        _fails.setdefault(ip, []).append(time.time())


# ---------- tvåstegskod vid inloggning (TOTP, valfritt med LOGIN_2FA) ----------
_pending = {}       # engångstoken -> (hemlighet, skapad) under registreringen
_last_step = [0]    # senast godkända 30-sekundersfönster: samma kod kan inte användas två gånger


def _otpauth(secret):
    return f'otpauth://totp/NetAtlas:{quote(APP_USER)}?secret={secret}&issuer=NetAtlas&digits=6&period=30'


def _totp_ok(secret, code):
    code = ''.join(ch for ch in str(code or '') if ch.isdigit())
    if len(code) != 6:
        return False
    now = time.time()
    with _lock:
        for w in (-1, 0, 1):
            step = int((now + 30 * w) // 30)
            if step > _last_step[0] and hmac.compare_digest(helper.totp_at(secret, now + 30 * w), code):
                _last_step[0] = step
                return True
    return False


def _read_body(environ, limit):
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
    except ValueError:
        n = 0
    return environ['wsgi.input'].read(min(n, limit)) if n > 0 else b''


def _same_origin(environ):
    origin = environ.get('HTTP_ORIGIN')
    return not origin or urlparse(origin).netloc == environ.get('HTTP_HOST', '')


def login_post(environ):
    ip = environ.get('REMOTE_ADDR', '')
    if not _same_origin(environ) or 'json' not in (environ.get('CONTENT_TYPE') or ''):
        return _json(403, {'error': 'Ogiltig begäran.'})
    if _limited(ip):
        return _json(429, {'error': 'För många misslyckade försök – vänta några minuter och försök igen.'})
    try:
        j = json.loads(_read_body(environ, 8192) or b'{}')
    except ValueError:
        return _json(400, {'error': 'Ogiltig begäran.'})
    user, pw, code = str(j.get('user') or ''), str(j.get('pass') or ''), j.get('code')
    ok_user = hmac.compare_digest(user.encode(), APP_USER.encode())
    ok_pw = hmac.compare_digest(pw.encode(), APP_PASSWORD.encode())
    if not (ok_user and ok_pw):
        _fail(ip)
        return _json(401, {'error': 'Fel användarnamn eller lösenord.'})
    if LOGIN_2FA:
        sealed = STORE.kv_get('login_totp')
        if not sealed:
            # första inloggningen med tvåsteg påslaget: visa QR-kod och spara nyckeln när en kod stämmer
            token = str(j.get('setup') or '')
            with _lock:
                for k in [k for k, v in _pending.items() if time.time() - v[1] > 900]:
                    del _pending[k]
                pend = _pending.get(token)
                if not pend:
                    token = secrets.token_urlsafe(16)
                    pend = _pending[token] = (base64.b32encode(secrets.token_bytes(20)).decode().rstrip('='), time.time())
            setup = {'setup': True, 'token': token, 'secret': pend[0], 'uri': _otpauth(pend[0])}
            if not code:
                return _json(200, setup)
            if not _totp_ok(pend[0], code):
                _fail(ip)
                return _json(401, {**setup, 'error': 'Fel kod – kontrollera att du skannat rätt QR-kod och att telefonens klocka stämmer.'})
            STORE.kv_set('login_totp', STORE.seal(pend[0].encode()))
            with _lock:
                _pending.pop(token, None)
        else:
            if not code:
                return _json(200, {'needCode': True})
            if not _totp_ok(STORE.unseal(sealed).decode(), code):
                _fail(ip)
                return _json(401, {'needCode': True, 'error': 'Fel kod från autentiseringsappen.'})
    with _lock:
        _fails.pop(ip, None)
    return _json(200, {'ok': True}, [_set_cookie(environ, make_session())])


def health():
    try:
        STORE.ping()
    except Exception as e:  # databasen nere eller inte startad än
        return _json(503, {'status': 'error', 'db': 'down', 'error': type(e).__name__})
    return _json(200, {'status': 'ok', 'db': 'ok'})


def certificate():
    """Serverns publika certifikat, för att kunna lita på det i datorn/mobilen (innehåller inget hemligt)."""
    try:
        with open(CERT_FILE, 'rb') as f:
            body = f.read()
    except OSError:
        return _json(404, {'error': 'Inget certifikat (TLS är avstängt).'})
    return _resp(200, body, 'application/x-x509-ca-cert', [('Content-Disposition', 'attachment; filename="netatlas.crt"')])


# ---------- adapter: hjälpprogrammets Handler utan egen socket ----------
class _Request(helper.Handler):
    """En WSGI-förfrågan körd genom hjälpprogrammets Handler (do_GET/do_POST är oförändrade)."""

    def __init__(self, environ):  # anropar medvetet inte BaseHTTPRequestHandler.__init__ (ingen socket)
        self.command = environ['REQUEST_METHOD']
        qs = environ.get('QUERY_STRING')
        self.path = environ.get('RAW_URI') or quote(environ.get('PATH_INFO') or '/') + ('?' + qs if qs else '')
        self.request_version = environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
        self.client_address = (environ.get('REMOTE_ADDR', ''), 0)
        h = email.message.Message()
        for k, v in environ.items():
            if k.startswith('HTTP_'):
                h[k[5:].replace('_', '-')] = v
        for k in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
            if environ.get(k):
                h[k.replace('_', '-')] = environ[k]
        self.headers = h
        self.rfile = environ['wsgi.input']
        self.wfile = io.BytesIO()
        self.code, self.out = 500, []

    def send_response(self, code, message=None):
        self.code = code

    def send_header(self, keyword, value):
        self.out.append((keyword, str(value)))

    def end_headers(self):
        pass


def run_helper(environ):
    r = _Request(environ)
    method = getattr(r, 'do_' + r.command, None)
    if method is None:
        return _json(405, {'error': 'Metoden stöds inte.'})
    method()
    return r.code, r.out, r.wfile.getvalue()


# ---------- WSGI ----------
def app(environ, start_response):
    path = environ.get('PATH_INFO') or '/'
    method = environ.get('REQUEST_METHOD', 'GET')
    try:
        if path == '/health':
            code, headers, body = health()
        elif path == '/login':
            if method == 'POST':
                code, headers, body = login_post(environ)
            elif valid_session(_session_cookie(environ)):
                code, headers, body = _redirect('/')
            else:
                code, headers, body = _resp(200, LOGIN_HTML, 'text/html; charset=utf-8')
        elif path == '/logout':
            code, headers, body = _redirect('/login', [_set_cookie(environ, '', 0)])
        elif path == '/netatlas.crt':
            code, headers, body = certificate()
        else:
            sess = valid_session(_session_cookie(environ))
            if not sess:
                if path.startswith('/api/'):
                    code, headers, body = _json(401, {'error': 'Inloggningen har gått ut – logga in igen.', 'login': True})
                else:
                    code, headers, body = _redirect('/login')
            else:
                code, headers, body = run_helper(environ)
                if sess['exp'] - time.time() < SESSION_HOURS * 3600 - 600:  # glidande: förnya när den är äldre än 10 min
                    headers = [*headers, _set_cookie(environ, make_session())]
    except Exception:
        traceback.print_exc()
        code, headers, body = _json(500, {'error': 'Internt fel i servern – se loggen (docker compose logs app).'})
    if method == 'HEAD':
        body = b''
    headers = [(k, v) for k, v in headers if k.lower() != 'content-length'] + [('Content-Length', str(len(body)))]
    start_response(f'{code} {HTTPStatus(code).phrase}', headers)
    return [body]
