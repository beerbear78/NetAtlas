"""Kör NetAtlas-servern lokalt utan Docker: wsgiref + SQLite i stället för gunicorn + PostgreSQL.

    python tests/server_harness.py          # http://localhost:8783 (användare testare, se nedan)

Används av testerna och för att prova serverläget i webbläsaren. Data hamnar i en tillfällig mapp.
Lösenorden här är bara testvärden för den lokala testservern."""
import contextlib
import os
import socketserver
import sqlite3
import sys
import tempfile
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get('TEST_PORT') or 8783)
TMP = os.environ.get('NETATLAS_TEST_DIR') or tempfile.mkdtemp(prefix='netatlas-test-')
os.environ.setdefault('APP_USER', 'testare')
os.environ.setdefault('APP_PASSWORD', 'Tst-8783-lokal')
os.environ.setdefault('APP_SECRET', 'a' * 16 + '0123456789abcdef' * 3)
os.environ.setdefault('LOGIN_2FA', 'optional')
os.environ.setdefault('TLS', 'off')
os.environ.setdefault('NETATLAS_DATA_DIR', os.path.join(TMP, 'data'))
os.environ.setdefault('DATABASE_URL', 'sqlite-test')
os.makedirs(os.environ['NETATLAS_DATA_DIR'], exist_ok=True)
sys.dont_write_bytecode = True
sys.path.insert(0, PROJ)

DB = os.path.join(TMP, 'test.sqlite')


class _Cur:
    """psycopg-liknande markör ovanpå sqlite3 (%s -> ?)."""

    def __init__(self, c):
        self.c = c

    def execute(self, sql, args=()):
        self.c.execute(sql.replace('%s', '?'), tuple(args))

    def fetchone(self):
        return self.c.fetchone()

    def fetchall(self):
        return self.c.fetchall()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.c.close()


class _Conn:
    def __init__(self, con):
        self.con = con

    def cursor(self):
        return _Cur(self.con.cursor())


class FakePool:
    """Samma gränssnitt som psycopg_pool.ConnectionPool.connection(): commit vid lyckat block."""

    @contextlib.contextmanager
    def connection(self):
        con = sqlite3.connect(DB, timeout=10)
        try:
            yield _Conn(con)
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


class FakeAEAD:
    """Ersätter AES-GCM (paketet cryptography behövs inte för testerna). Inte säker – bara för test."""
    TAG = b'0123456789TAGTAG'

    def encrypt(self, nonce, data, aad):
        return bytes(b ^ 0x5A for b in data) + self.TAG

    def decrypt(self, nonce, ct, aad):
        assert ct.endswith(self.TAG)
        return bytes(b ^ 0x5A for b in ct[:-16])


import server.store as st  # noqa: E402
st._pg_pool = lambda conninfo: FakePool()
st._aead = lambda secret: FakeAEAD()
import server.app as sa  # noqa: E402


class TServer(socketserver.ThreadingMixIn, WSGIServer):
    daemon_threads = True


class Quiet(WSGIRequestHandler):
    def log_message(self, *a):
        pass


def serve(port=PORT):
    return make_server('127.0.0.1', port, sa.app, server_class=TServer, handler_class=Quiet)


if __name__ == '__main__':
    print(f'NetAtlas testserver på http://localhost:{PORT} (data i {TMP})', flush=True)
    serve().serve_forever()
