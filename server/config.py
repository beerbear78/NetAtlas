"""Inställningar från miljövariabler (sätts i .env och docker-compose.yml)."""
import os


def env(name, default=''):
    return (os.environ.get(name) or default).strip()


def flag(name, default='false'):
    return env(name, default).lower() in ('1', 'true', 'yes', 'on', 'ja')


def database_url():
    """DATABASE_URL om den finns, annars byggd av POSTGRES_* (då behöver lösenordet inte URL-kodas)."""
    url = env('DATABASE_URL')
    if url:
        return url
    parts = {'host': env('POSTGRES_HOST', 'db'), 'port': env('POSTGRES_PORT', '5432'), 'dbname': env('POSTGRES_DB', 'netatlas'),
             'user': env('POSTGRES_USER', 'netatlas'), 'password': os.environ.get('POSTGRES_PASSWORD', '')}
    quote = lambda v: "'" + v.replace('\\', '\\\\').replace("'", "\\'") + "'"
    return ' '.join(f'{k}={quote(v)}' for k, v in parts.items())


DATA_DIR = env('NETATLAS_DATA_DIR', '/data')
APP_SECRET = os.environ.get('APP_SECRET') or ''
