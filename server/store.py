"""PostgreSQL-lagring för NetAtlas på server.

Servern ser aldrig klartext: valvet och bilagorna krypteras i webbläsaren med huvudlösenordet och lagras
här som de är. Det enda som krypteras på servern (AES-GCM med nyckel från APP_SECRET) är serverns egna
hemligheter, t.ex. nycklarna för tvåstegsinloggning.

Tabeller (skapas automatiskt vid start):
  vault  – ett krypterat valv (en rad) med versionsnummer så att två fönster inte skriver över varandra
  files  – krypterade bilagor
  kv     – övrigt: ledtråd till huvudlösenordet, tvåstegsnycklar
"""
import base64
import os
from contextlib import contextmanager

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS vault (
        id smallint PRIMARY KEY CHECK (id = 1),
        version bigint NOT NULL,
        data text NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS files (
        id text PRIMARY KEY,
        data bytea NOT NULL,
        size integer NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS kv (
        key text PRIMARY KEY,
        value text NOT NULL,
        updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP)""",
)


class Conflict(Exception):
    """Valvet har sparats av någon annan sedan det lästes (fel versionsnummer)."""

    def __init__(self, version):
        super().__init__(f'konflikt (aktuell version {version})')
        self.version = version


def _pg_pool(conninfo):
    from psycopg_pool import ConnectionPool
    pool = ConnectionPool(conninfo, min_size=1, max_size=8, timeout=15, open=False)
    pool.open(wait=True, timeout=60)  # vänta in databasen vid start
    return pool


def _aead(secret):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b'netatlas', info=b'server-secrets-v1').derive(secret.encode())
    return AESGCM(key)


class Store:
    Conflict = Conflict

    def __init__(self, conninfo, secret, pool=None):
        self._pool = pool if pool is not None else _pg_pool(conninfo)
        self._aead = _aead(secret)
        with self.tx() as cur:
            for stmt in SCHEMA:
                cur.execute(stmt)

    @contextmanager
    def tx(self):
        """En transaktion: commit om blocket lyckas, annars rollback."""
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                yield cur

    def _one(self, sql, args=()):
        with self.tx() as cur:
            cur.execute(sql, args)
            return cur.fetchone()

    def ping(self):
        return self._one('SELECT 1')[0] == 1

    # ---------- valvet ----------
    def vault_get(self):
        with self.tx() as cur:
            cur.execute('SELECT version, data FROM vault WHERE id = 1')
            row = cur.fetchone()
            cur.execute("SELECT value FROM kv WHERE key = 'hint'")
            hint = cur.fetchone()
        return {'version': row[0] if row else 0, 'data': row[1] if row else None, 'hint': hint[0] if hint else ''}

    def vault_put(self, version, data):
        """Sparar om versionen stämmer (0 = nytt valv). Returnerar ny version, annars Conflict."""
        if not data or '"ct"' not in data:
            raise ValueError('Ingen krypterad data att spara.')
        with self.tx() as cur:
            if version:
                cur.execute('UPDATE vault SET data = %s, version = version + 1, updated_at = CURRENT_TIMESTAMP '
                            'WHERE id = 1 AND version = %s RETURNING version', (data, version))
            else:
                cur.execute('INSERT INTO vault (id, version, data) VALUES (1, 1, %s) ON CONFLICT (id) DO NOTHING RETURNING version', (data,))
            row = cur.fetchone()
            if row:
                return row[0]
            cur.execute('SELECT version FROM vault WHERE id = 1')
            now = cur.fetchone()
        raise Conflict(now[0] if now else 0)

    def vault_import(self, data, force=False):
        """För migreringsskriptet: lägg in ett valv, ersätt befintligt bara med force."""
        with self.tx() as cur:
            cur.execute('SELECT version FROM vault WHERE id = 1')
            row = cur.fetchone()
            if row and not force:
                raise Conflict(row[0])
            version = row[0] + 1 if row else 1
            cur.execute('INSERT INTO vault (id, version, data) VALUES (1, %s, %s) ON CONFLICT (id) DO UPDATE '
                        'SET data = EXCLUDED.data, version = EXCLUDED.version, updated_at = CURRENT_TIMESTAMP', (version, data))
            return version

    def vault_delete(self):
        with self.tx() as cur:
            cur.execute('DELETE FROM vault')
            cur.execute("DELETE FROM kv WHERE key = 'hint'")

    # ---------- bilagor ----------
    def file_get(self, fid):
        row = self._one('SELECT data FROM files WHERE id = %s', (fid,))
        return bytes(row[0]) if row else None

    def file_put(self, fid, data):
        with self.tx() as cur:
            cur.execute('INSERT INTO files (id, data, size) VALUES (%s, %s, %s) ON CONFLICT (id) DO UPDATE '
                        'SET data = EXCLUDED.data, size = EXCLUDED.size, updated_at = CURRENT_TIMESTAMP', (fid, bytes(data), len(data)))

    def file_delete(self, fid):
        with self.tx() as cur:
            cur.execute('DELETE FROM files WHERE id = %s', (fid,))

    def export_files(self, d):
        """Skriver bilagor som saknas i mappen d (används av säkerhetskopieringen)."""
        with self.tx() as cur:
            cur.execute('SELECT id FROM files')
            ids = [r[0] for r in cur.fetchall()]
        os.makedirs(d, exist_ok=True)
        n = 0
        for fid in ids:
            p = os.path.join(d, fid + '.bin')
            if not os.path.exists(p):
                data = self.file_get(fid)
                if data is not None:
                    with open(p, 'wb') as f:
                        f.write(data)
                    n += 1
        return n

    # ---------- nyckel/värde ----------
    def kv_get(self, key):
        row = self._one('SELECT value FROM kv WHERE key = %s', (key,))
        return row[0] if row else None

    def kv_set(self, key, value):
        with self.tx() as cur:
            cur.execute('INSERT INTO kv (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE '
                        'SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP', (key, value))

    def kv_delete(self, key):
        with self.tx() as cur:
            cur.execute('DELETE FROM kv WHERE key = %s', (key,))

    # ---------- serverns egna hemligheter ----------
    def seal(self, data):
        nonce = os.urandom(12)
        return 'seal:' + base64.b64encode(nonce + self._aead.encrypt(nonce, bytes(data), b'netatlas-v1')).decode()

    def unseal(self, text):
        raw = base64.b64decode(text.partition(':')[2])
        return self._aead.decrypt(raw[:12], raw[12:], b'netatlas-v1')

    def stats(self):
        with self.tx() as cur:
            cur.execute('SELECT version, length(data), updated_at FROM vault WHERE id = 1')
            v = cur.fetchone()
            cur.execute('SELECT count(*), coalesce(sum(size), 0) FROM files')
            f = cur.fetchone()
            cur.execute("SELECT count(*) FROM kv WHERE key = 'login_totp'")
            t = cur.fetchone()
        return {'vault_version': v[0] if v else 0, 'vault_bytes': v[1] if v else 0, 'vault_updated': str(v[2]) if v else '',
                'files': f[0], 'files_bytes': f[1], 'login_2fa_enrolled': bool(t[0])}
