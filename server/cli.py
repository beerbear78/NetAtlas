"""Administration av NetAtlas på servern.

    docker compose exec app python -m server.cli status
    docker compose exec app python -m server.cli reset-2fa   # tappad telefon: logga in utan kod och aktivera igen
"""
import sys

from . import config
from .store import Store


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd not in ('status', 'reset-2fa'):
        sys.exit(__doc__)
    store = Store(config.database_url(), config.APP_SECRET)
    if cmd == 'status':
        s = store.stats()
        print(f"Valv: version {s['vault_version']}, {s['vault_bytes'] / 1e6:.1f} MB, senast sparat {s['vault_updated'] or '–'}")
        print(f"Bifogade filer: {s['files']} st, {s['files_bytes'] / 1e6:.1f} MB")
        print(f"Tvåstegsinloggning för servern: {'registrerad' if s['login_2fa_enrolled'] else 'inte registrerad'}")
    else:
        store.kv_delete('login_totp')
        store.kv_delete('login_2fa_offered')
        print('Tvåstegsnyckeln för inloggningen är borttagen. Logga in med lösenordet – du får då välja att aktivera\n'
              'tvåstegsinloggning igen med en ny QR-kod (det går också under Inställningar → Säkerhet).')


if __name__ == '__main__':
    main()
