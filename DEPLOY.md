# NetAtlas på server (Unraid / Docker)

Två containrar: **netatlas** (appen, HTTPS på port 8770) och **netatlas-db** (PostgreSQL 16, nås bara internt).
All data hamnar i `/mnt/user/appdata/netatlas/` (`app/` och `postgres/`) och följer därmed med i Unraids Appdata Backup.
Uppgifterna krypteras i webbläsaren med ditt huvudlösenord – servern ser aldrig dina lösenord.

## 1. Kopiera till servern

1. Installera pluginet **Docker Compose Manager** från *Apps* (ger kommandot `docker compose`; testat på Unraid 7.1
   med Compose 2.40).
2. Ta reda på var dina containrar har sin appdata: *Docker* → klicka på en container → *Edit* och titta på sökvägarna.
   Standard är `/mnt/user/appdata`, men den kan ligga på annat ställe, t.ex. `/mnt/user/docker/appdata`.
   Exemplen nedan använder `/mnt/user/appdata` – byt till din sökväg.
3. Öppna en terminal i Unraid (ikonen `>_` uppe till höger) och hämta koden:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /mnt/user/appdata/netatlas/src
cd /mnt/user/appdata/netatlas/src
```

## 2. Skapa `.env`

```bash
cp .env.example .env
openssl rand -hex 32   # kör två gånger: till APP_SECRET och POSTGRES_PASSWORD
nano .env
```

Fyll i `APP_PASSWORD` (lösenordet du loggar in med – välj ett eget starkt), `APP_SECRET` och `POSTGRES_PASSWORD`.
Innehåller ett värde tecknet `$`, sätt det inom enkla citattecken: `APP_PASSWORD='...'`. Ändra också `TLS_HOSTS` (serverns IP och namn),
`SCAN_CIDRS` (ditt nät) och `APPDATA` (din appdata-sökväg + `/netatlas`). `LOGIN_2FA` styr tvåstegsinloggningen:
`optional` (standard – erbjuds vid första inloggningen och kan aktiveras senare), `required` (krav) eller `off`.
`.env` innehåller hemligheter: spara en kopia på ett säkert ställe och checka aldrig in den.

## 3. Starta

```bash
docker compose up -d --build
docker compose ps                      # båda ska visa (healthy) efter en halv minut
curl -k https://127.0.0.1:8770/health  # {"status": "ok", "db": "ok"}
```

Öppna **https://SERVERNS-IP:8770** (eller WebUI i Unraids Docker-flik). Första gången varnar webbläsaren för
certifikatet eftersom det är självsignerat – välj *Avancerat → Fortsätt*. Logga in med `APP_USER`/`APP_PASSWORD`
Första gången erbjuds tvåstegsinloggning – den rekommenderas, men du kan hoppa över och aktivera den senare under
*Inställningar → Säkerhet*. Skapa sedan ett huvudlösenord, eller flytta dina data enligt steg 4.

*Bli av med varningen:* hämta `https://SERVERNS-IP:8770/netatlas.crt`, dubbelklicka och installera det under
*Lokal dator → Betrodda rotcertifikatutfärdare*. Byter servern IP eller namn: ta bort `app/certs/*.pem` och starta om.

Kontrollera att data finns kvar efter omstart:

```bash
docker compose down && docker compose up -d
```

## 4. Flytta data från Windows-versionen (en gång)

1. I Windows-NetAtlas: stäng av tvåstegsinloggning om den är på, och välj *Inställningar → Säkerhetskopiera nu*.
2. Kopiera den nya filen `backups\netatlas-ÅÅÅÅMMDD-HHMMSS.json`, och mappen `data\files` om du har bilagor, till
   `/mnt/user/appdata/netatlas/app/import/` (bilagorna i `import/files/`).
3. Kör:

```bash
docker compose exec app python -m server.migrate --hint "din ledtråd"
```

4. Logga in och lås upp med ditt vanliga huvudlösenord. Ta sedan bort `app/import/`.

## 5. Full nätverksskanning (tillval)

I vanligt Docker-nät fungerar ping, portar, Shelly, Home Assistant och SSH-import, men inte MAC-adresser,
Wake-on-LAN och delning till mobilen. Kör appen i värdens nätverk för att få dem:

```bash
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build
```

Lägg gärna till `COMPOSE_FILE=docker-compose.yml:docker-compose.host.yml` i `.env`, så räcker vanliga
`docker compose`-kommandon. Databasen öppnas då på `127.0.0.1:5433` (bara lokalt; ändra med `DB_HOST_PORT`).

## 6. SSH-import av rutiner

Containern skapar en egen SSH-nyckel första gången. Visa den publika delen och lägg in den hos servrarna du vill
importera från (Unraid: *Users → root → SSH authorized keys*):

```bash
docker compose logs app | grep -A1 "SSH-nyckel"
```

## 7. Uppdatera till ny version

```bash
cd /mnt/user/appdata/netatlas/src
git pull
docker compose up -d --build
```

`.env`, databasen och `app/` rörs inte. Vill du prova en ändring innan den hamnar i `main` (en pull request):
`git fetch && git checkout grenens-namn && docker compose up -d --build` – och tillbaka med `git checkout main`.

**Röktest** (valfritt, t.ex. efter en uppdatering): kör testet i en separat kopia – det använder egna namn och
portar (8790/5433), rör inte din installation och städar efter sig:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /tmp/netatlas-smoke-src
bash /tmp/netatlas-smoke-src/tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # ditt nät och din router
rm -rf /tmp/netatlas-smoke-src
```

## 8. Backup och återställning

**Backup av databasen** (valv, bilagor, tvåstegsnycklar):

```bash
mkdir -p /mnt/user/backups/netatlas
docker compose exec -T db pg_dump -U netatlas -d netatlas --clean --if-exists \
  > /mnt/user/backups/netatlas/netatlas-$(date +%F).sql
```

**Återställning:**

```bash
docker compose stop app
docker compose exec -T db psql -q -U netatlas -d netatlas < /mnt/user/backups/netatlas/netatlas-2026-10-09.sql > /dev/null
docker compose start app
```

Valvet i dumpen är krypterat med ditt huvudlösenord. Tvåstegsnycklarna är krypterade med `APP_SECRET` – spara
därför `.env` tillsammans med backuperna (men på ett säkert ställe). Appens egna säkerhetskopior hamnar dessutom i
`app/backups/`, och molnbackup (S3/WebDAV) under *Inställningar* fungerar som tidigare.

## 9. Administration

```bash
docker compose exec app python -m server.cli status      # storlek, version, senast sparat
docker compose exec app python -m server.cli reset-2fa   # tappad telefon: logga in utan kod och aktivera igen
docker compose logs -f app                               # loggar
```

Logga ut: `https://SERVERNS-IP:8770/logout`.

## Felsökning

| Problem | Lösning |
|---|---|
| "Webbläsaren saknar Web Crypto" | Du använder `http://`. Gå till `https://`. |
| Containern startar om hela tiden | `docker compose logs app` – t.ex. saknas `APP_PASSWORD` eller `APP_SECRET`. |
| Behörighetsfel i appdata | Kontrollera `PUID`/`PGID` i `.env` (Unraid: 99/100). |
| Port 8770 upptagen | Ändra `PORT` i `.env`. |
| Databasen långsam | Lägg `APPDATA` direkt på cache-poolen, t.ex. `/mnt/cache/appdata/netatlas`. |

**Vanlig Linux-server i stället för Unraid:** sätt `APPDATA=./data` och `PUID`/`PGID` till din användare (`id -u`, `id -g`).
