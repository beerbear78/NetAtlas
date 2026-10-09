"""Gunicorn-inställningar för NetAtlas (läser miljövariabler från .env/docker-compose.yml)."""
import os

_port = int(os.environ.get('PORT') or 8770)
bind = [f'0.0.0.0:{_port}']

# En process med flera trådar: appen håller tillstånd i minnet (skanningslås, spärr mot gissade
# lösenord, delning till mobilen) som inte får delas upp på flera processer.
worker_class = 'gthread'
workers = 1
threads = int(os.environ.get('THREADS') or 8)
timeout = 180            # nätverksskanning och SSH-import kan ta en stund
graceful_timeout = 20
keepalive = 5

# långa frågesträngar (Live-ping av många IP-adresser) och HA-tokens i headers
limit_request_line = 8190
limit_request_field_size = 65536

errorlog = '-'
loglevel = os.environ.get('LOG_LEVEL') or 'info'
accesslog = '-' if (os.environ.get('ACCESS_LOG') or '').lower() in ('1', 'true', 'on', 'ja') else None

# bakom en reverse proxy (TLS=off): lita på X-Forwarded-Proto från dessa adresser
forwarded_allow_ips = os.environ.get('FORWARDED_ALLOW_IPS') or '127.0.0.1'

if (os.environ.get('TLS') or 'on').lower() not in ('off', 'false', '0', 'no', 'nej'):
    _certs = os.path.join(os.environ.get('NETATLAS_DATA_DIR') or '/data', 'certs')
    certfile = os.environ.get('TLS_CERT') or os.path.join(_certs, 'cert.pem')
    keyfile = os.environ.get('TLS_KEY') or os.path.join(_certs, 'key.pem')
