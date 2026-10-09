"""Hälsokontroll för Docker: anropar /health i den egna containern (exit 0 = frisk)."""
import os
import ssl
import sys
import urllib.request

port = os.environ.get('PORT') or '8770'
tls = (os.environ.get('TLS') or 'on').lower() not in ('off', 'false', '0', 'no', 'nej')
url = f"{'https' if tls else 'http'}://127.0.0.1:{port}/health"
try:
    # certifikatet är ofta självsignerat och gäller inte för 127.0.0.1 – här kontrolleras bara att appen svarar
    with urllib.request.urlopen(url, timeout=4, context=ssl._create_unverified_context() if tls else None) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception as e:
    print(f'NetAtlas svarar inte på {url}: {e}')
    sys.exit(1)
