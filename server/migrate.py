"""Engångsflytt av data från NetAtlas på Windows till servern (PostgreSQL).

1. I Windows-versionen: Inställningar → Säkerhetskopiera nu (tvåstegsinloggning ska vara avstängd).
2. Kopiera den nya filen netatlas-ÅÅÅÅMMDD-HHMMSS.json från mappen backups, och mappen data\\files
   om du har bifogade filer, till  appdata/netatlas/app/import/  på servern.
3. Kör:  docker compose exec app python -m server.migrate

Datan är och förblir krypterad med ditt huvudlösenord – skriptet behöver inget lösenord.
"""
import argparse
import glob
import json
import os
import re
import sys

from . import config
from .store import Store

FILE_ID = re.compile(r'^[a-z0-9]{6,32}$')


def main():
    imp = os.path.join(config.DATA_DIR, 'import')
    ap = argparse.ArgumentParser(description='Flytta data från NetAtlas på Windows till servern.')
    ap.add_argument('vault', nargs='?', help=f'krypterad säkerhetskopia eller export (.json); standard: nyaste i {imp}')
    ap.add_argument('--files', default=os.path.join(imp, 'files'), help='mapp med bifogade filer (*.bin)')
    ap.add_argument('--hint', help='ledtråd till huvudlösenordet (visas vid upplåsning)')
    ap.add_argument('--force', action='store_true', help='ersätt data som redan finns på servern')
    a = ap.parse_args()

    path = a.vault
    if not path:
        cands = sorted(glob.glob(os.path.join(imp, '*.json')), key=os.path.getmtime)
        if not cands:
            sys.exit(f'Hittade ingen .json-fil i {imp}. Kopiera dit en säkerhetskopia från Windows-versionen.')
        path = cands[-1]
    with open(path, encoding='utf-8') as f:
        raw = f.read()
    try:
        v = json.loads(raw)
    except ValueError:
        sys.exit(f'{path} är inte en NetAtlas-fil (ogiltig JSON).')
    if not all(k in v for k in ('salt', 'iv', 'ct')):
        sys.exit(f'{path} är inte en krypterad NetAtlas-kopia.')
    if v.get('mfa'):
        sys.exit('Kopian är låst med tvåstegsinloggning, och den nyckeln kan inte flyttas från Windows.\n'
                 'Stäng av tvåstegsinloggningen i Windows-versionen, ta en ny säkerhetskopia och kör igen.\n'
                 'Slå sedan på tvåstegsinloggningen igen på servern.')

    store = Store(config.database_url(), config.APP_SECRET)
    try:
        version = store.vault_import(raw, force=a.force)
    except Store.Conflict as e:
        sys.exit(f'Det finns redan data på servern (version {e.version}). Kör med --force för att ersätta den.')

    n = size = 0
    for p in sorted(glob.glob(os.path.join(a.files, '*.bin'))):
        fid = os.path.basename(p)[:-4]
        if not FILE_ID.match(fid):
            continue
        with open(p, 'rb') as f:
            data = f.read()
        store.file_put(fid, data)
        n, size = n + 1, size + len(data)
    if a.hint is not None:
        store.kv_set('hint', a.hint.strip()[:200])

    print(f'Klart! Valvet från {os.path.basename(path)} är inläst (version {version}, {len(raw) / 1e6:.1f} MB).')
    print(f'Bifogade filer: {n} st ({size / 1e6:.1f} MB) från {a.files}' if n else f'Inga bifogade filer hittades i {a.files}.')
    print('Logga in på servern och lås upp med ditt vanliga huvudlösenord. Du kan sedan ta bort import-mappen.')


if __name__ == '__main__':
    main()
