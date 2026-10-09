# NetAtlas – anvisningar för Claude

- Svara på svenska. UI-texter, kodkommentarer och commit-meddelanden skrivs på svenska.
- Ägaren är IT-tekniker och kör NetAtlas på Unraid. Förklara kort, inte grundläggande saker.

## Två lägen i samma kod

- **Lokalt (Windows):** `netatlas-helper.py` på 127.0.0.1:8770 serverar `netatlas.html`; valvet ligger i webbläsarens
  localStorage. Startas med `Start NetAtlas.bat`.
- **Server (Docker):** `server/app.py` (WSGI under gunicorn) laddar hjälpprogrammet och sätter `helper.STORE`
  (PostgreSQL, `server/store.py`). Inloggning, sessionskaka och valfri TOTP ligger i `server/app.py`.
  Frontend vet läget via `HELPER.storage` / `onServer()` och laddar/sparar valvet via `/api/vault`.
- Ändringar i `netatlas.html` och `netatlas-helper.py` måste fungera i **båda** lägena.

## Regler

- `netatlas-helper.py` får bara använda Pythons standardbibliotek (körs på användarens dator utan pip).
  Serverns paket står i `requirements.txt`.
- `netatlas.html` är en enda fil utan byggsteg. Externa JS-bibliotek laddas bara vid behov från CDN med SRI
  (se `SRI` i filen).
- Känslig data krypteras i webbläsaren – servern och databasen får aldrig se klartext.
- Lägg aldrig in personliga data (planritningar, IP-listor, lösenord) eller `.env` i repot. Inbäddade planer
  (`<script id="housePlans">`) tas bort med `server/strip_plans.py`.
- Docker-filer måste ha LF (`.gitattributes` sköter det); `Start NetAtlas.bat` måste ha CRLF.

## Test

- **Rör aldrig port 8770** – där ligger användarens riktiga data. Rensa localStorage bara på testportar.
- Lokalt läge: förhandsgranskningen `inventarie` i `.claude/launch.json` (port 8771).
- Serverläge utan Docker: `python tests/test_server_api.py`, `python tests/test_server_misc.py` och
  förhandsgranskningen `netatlas-server` (port 8783, testkonto i `tests/server_harness.py`, TOTP-kod räknas
  fram med `totp_at` i hjälpprogrammet).
- Docker finns inte på utvecklingsdatorn. Verifiera Docker-versionen på ägarens Unraid-server med röktestet:
  pusha grenen, klona den till `/tmp` på servern och kör `bash tests/docker_smoke.sh <nät> <ping-ip>`
  (egna namn och portar, städar själv). SSH sker bara med nyckel som ägaren själv godkänt – aldrig med lösenord.
- Ta bort testartefakter efteråt: `backups/`, `data/`, `__pycache__/`.
- Windows: Temp-sökvägar blir för långa för vissa program – kör skript med full sökväg från projektmappen.
  Git Bash gör om argument som `/CN=…`; Git:s `openssl` är ett Windows-program (använd `cygpath -m`).

## Git och GitHub

- `main` är skyddad: inga direkta pushar, ingen force push. Varje ändring görs på en egen gren och blir en pull
  request som ägaren granskar. GitHub Actions (`.github/workflows/tester.yml`) kör Python-testerna och Docker-röktestet;
  båda kontrollerna, "Tester (Python)" och "Docker (röktest)", måste vara gröna innan merge.
- Byter du namn på ett jobb i workflowen måste skyddet av `main` uppdateras med samma namn.

## Leverans

- Installerade kopior (t.ex. Windows-versionen på port 8770) uppdateras bara när ägaren ber om det.
- Zip-filer byggs från koden och checkas inte in.
