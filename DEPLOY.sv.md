# NetAtlas på server (Unraid / Docker)

[English](DEPLOY.md) | **Svenska**

Två containrar: **netatlas** (appen från `ghcr.io/beerbear78/netatlas`, HTTPS på port 8770) och **netatlas-db**
(PostgreSQL 16, nås bara internt). All data hamnar i installationsmappen, t.ex. `/mnt/user/appdata/netatlas/`
(`app/` och `postgres/`), och följer därmed med i Unraids Appdata Backup.
Uppgifterna krypteras i webbläsaren med ditt huvudlösenord – servern ser aldrig dina lösenord.

**Krav:** Docker med Compose v2 (`docker compose`), amd64 eller arm64. På Unraid: installera pluginet
**Docker Compose Manager** från *Apps* (testat på Unraid 7.1 med Compose 2.40).

## 1. Installera

### Med installationsskriptet (enklast)

Öppna en terminal på servern (Unraid: ikonen `>_` uppe till höger) och kör som root:

```bash
curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
```

Skriptet frågar efter installationsmapp, port, användarnamn, lösenord, ditt nät, host-nätverk och tvåstegsinloggning.
Föreslagen mapp är `appdata/netatlas` på Unraid (det hittar både `/mnt/user/appdata` och `/mnt/user/docker/appdata`),
annars `/opt/netatlas`. Det skapar `.env` med slumpade nycklar (bara läsbar för root), hämtar imagen, startar och
väntar tills allt är friskt. Lösenordet visas aldrig och får inte innehålla tecknet `'`. Skriptet frågar på svenska
om systemet är svenskt, annars på engelska (`NETATLAS_LANG=sv|en` väljer).

Utan frågor, t.ex. för automatisering: sätt `NETATLAS_PASSWORD` och `NETATLAS_YES=1`. Övriga val styrs med
`NETATLAS_DIR`, `NETATLAS_PORT`, `NETATLAS_USER`, `NETATLAS_CIDR`, `NETATLAS_HOSTNET` (ja/nej), `NETATLAS_2FA` och
`NETATLAS_TAG` – se början av [install.sh](install.sh).

### Manuellt

Ta reda på var dina containrar har sin appdata (*Docker* → en container → *Edit*). Exemplen använder
`/mnt/user/appdata` – byt till din sökväg.

```bash
mkdir -p /mnt/user/appdata/netatlas && cd /mnt/user/appdata/netatlas
for f in docker-compose.yml docker-compose.host.yml .env.example; do
  curl -fsSLO "https://raw.githubusercontent.com/beerbear78/NetAtlas/main/$f"
done
cp .env.example .env && chmod 600 .env
openssl rand -hex 32   # kör två gånger: till APP_SECRET och POSTGRES_PASSWORD
nano .env
```

Fyll i `APP_PASSWORD` (lösenordet du loggar in med – välj ett eget starkt), `APP_SECRET` och `POSTGRES_PASSWORD`.
Innehåller ett värde tecknet `$`, sätt det inom enkla citattecken: `APP_PASSWORD='...'`. Ändra också `TLS_HOSTS`
(serverns IP och namn), `SCAN_CIDRS` (ditt nät) och `APPDATA` (installationsmappen). `LOGIN_2FA` styr
tvåstegsinloggningen: `optional` (standard – erbjuds vid första inloggningen och kan aktiveras senare), `required`
(krav) eller `off`. `NETATLAS_TAG` väljer version (`latest`, eller lås till t.ex. `1.0.0`).
`.env` innehåller hemligheter: spara en kopia på ett säkert ställe och checka aldrig in den.

```bash
docker compose pull
docker compose up -d
docker compose ps                      # båda ska visa (healthy) efter en halv minut
curl -k https://127.0.0.1:8770/health  # {"status": "ok", "db": "ok"}
```

## 2. Första inloggningen

Öppna **https://SERVERNS-IP:8770** (eller WebUI i Unraids Docker-flik). Första gången varnar webbläsaren för
certifikatet eftersom det är självsignerat – välj *Avancerat → Fortsätt*. Logga in med `APP_USER`/`APP_PASSWORD`.
Första gången erbjuds tvåstegsinloggning – den rekommenderas, men du kan hoppa över och aktivera den senare under
*Inställningar → Säkerhet*. Skapa sedan ett huvudlösenord, eller flytta dina data enligt steg 3.

*Bli av med varningen:* hämta `https://SERVERNS-IP:8770/netatlas.crt`, dubbelklicka och installera det under
*Lokal dator → Betrodda rotcertifikatutfärdare*. Byter servern IP eller namn: ta bort `app/certs/*.pem` och starta om.

Kontrollera att data finns kvar efter omstart:

```bash
docker compose down && docker compose up -d
```

## 3. Flytta data från Windows-versionen (en gång)

1. I Windows-NetAtlas: stäng av tvåstegsinloggning om den är på, och välj *Inställningar → Säkerhetskopiera nu*.
2. Kopiera den nya filen `backups\netatlas-ÅÅÅÅMMDD-HHMMSS.json`, och mappen `data\files` om du har bilagor, till
   `/mnt/user/appdata/netatlas/app/import/` (bilagorna i `import/files/`).
3. Kör:

```bash
docker compose exec app python -m server.migrate --hint "din ledtråd"
```

4. Logga in och lås upp med ditt vanliga huvudlösenord. Ta sedan bort `app/import/`.

## 4. Full nätverksskanning (tillval)

I vanligt Docker-nät fungerar ping, portar, Shelly, Home Assistant och SSH-import, men inte MAC-adresser,
Wake-on-LAN och delning till mobilen. Kör appen i värdens nätverk för att få dem (installationsskriptet frågar om
detta och gör det åt dig). Manuellt: lägg till raden nedan i `.env` och kör `docker compose up -d`.

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.host.yml
```

Databasen öppnas då på `127.0.0.1:5433` (bara lokalt; ändra med `DB_HOST_PORT`).

## 5. SSH-import av rutiner

Containern skapar en egen SSH-nyckel första gången. Visa den publika delen och lägg in den hos servrarna du vill
importera från (Unraid: *Users → root → SSH authorized keys*):

```bash
docker compose logs app | grep -A1 "SSH-nyckel"
```

## 6. Uppdatera till ny version

```bash
cd /mnt/user/appdata/netatlas
docker compose pull
docker compose up -d
```

Eller kör installationsskriptet igen i samma mapp – det hämtar också de senaste compose-filerna. `.env`, databasen
och `app/` rörs inte. Versioner och ändringar: [Releases](https://github.com/beerbear78/NetAtlas/releases).
Med `NETATLAS_TAG=1.0.0` i `.env` står du kvar på en viss version tills du ändrar den; `main` ger den senaste
utvecklingsversionen.

**Bygga från källkoden** (t.ex. för att prova en pull request innan den mergas): klona repot, lägg din `.env` i
mappen och lägg till `docker-compose.build.yml` i `COMPOSE_FILE`, så byggs imagen lokalt i stället för att hämtas:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /mnt/user/appdata/netatlas/src
cd /mnt/user/appdata/netatlas/src
# i .env: COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml   (+ :docker-compose.host.yml i host-läget)
git checkout grenens-namn && docker compose up -d --build
```

Tillbaka: `git checkout main`, ta bort `docker-compose.build.yml` ur `COMPOSE_FILE` och kör `docker compose up -d`.

**Röktest** (valfritt, t.ex. efter en uppdatering): kör testet i en separat kopia – det använder egna namn och
portar (8790/5433), rör inte din installation och städar efter sig:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /tmp/netatlas-smoke-src
bash /tmp/netatlas-smoke-src/tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # ditt nät och din router
rm -rf /tmp/netatlas-smoke-src
```

## 7. Backup och återställning

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

## 8. Administration

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
| "Kunde inte hämta imagen" / `manifest unknown` | Kontrollera internet och `NETATLAS_TAG` i `.env` (finns versionen under *Releases*?). |
| Unraid: `docker compose` saknas | Installera pluginet *Docker Compose Manager* från *Apps*. |

**Vanlig Linux-server i stället för Unraid:** installationsskriptet fungerar likadant (föreslår `/opt/netatlas`).
Vill du att filerna ska ägas av din egen användare: sätt `PUID`/`PGID` i `.env` (`id -u`, `id -g`).
