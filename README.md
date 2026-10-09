# NetAtlas

IT-inventarie på planritningen: brandväggar, switchar, servrar, kameror och IoT-enheter (t.ex. Shelly) placerade på
husets planlösning – med konton och lösenord som krypteras i webbläsaren.

## Funktioner

- **Karta** – planritningar från bild eller PDF, rum, enheter och kamerors synfält
- **Enheter** – sorterbar tabell, översikt med status och "att göra" (svaga lösenord, garantier, certifikat …)
- **Konton och lösenord** – maskerade, med TOTP-koder och bilagor; allt krypterat med huvudlösenordet
- **Nätverk** – skanning (ping, ARP, portar, tillverkare), Live-status, IP-plan, Shelly Gen1–Gen4
- **Rutiner och jobb** – import från Home Assistant, Unraid och Linux (cron/systemd via SSH)
- **Avtal och licenser**, säkerhetskopior (lokalt, synkmapp, S3/WebDAV), mobilkopia, utskrift och tvåstegsinloggning

## Kom igång

**Windows (lokalt):** kräver Python 3. Dubbelklicka på `Start NetAtlas.bat` – appen öppnas på
http://127.0.0.1:8770 och datan sparas krypterad i webbläsaren.

**Server (Docker, t.ex. Unraid):** se [DEPLOY.md](DEPLOY.md). Kort: `cp .env.example .env`, fyll i, och kör
`docker compose up -d --build`. Två containrar (appen och PostgreSQL 16), HTTPS och inloggning med valfri tvåstegskod.

## Säkerhet

- Allt känsligt krypteras i webbläsaren (AES-GCM, nyckel från huvudlösenordet via PBKDF2) innan det sparas –
  varken hjälpprogrammet, servern eller databasen ser klartext.
- Lokalt lyssnar hjälpprogrammet bara på 127.0.0.1. På servern krävs inloggning och HTTPS.
- Repot innehåller inga lösenord, planritningar eller annan personlig data. `.env` checkas aldrig in.

## Struktur

| Fil/mapp | Innehåll |
|---|---|
| `netatlas.html` | hela appen – HTML, CSS och JavaScript i en fil |
| `netatlas-helper.py` | webbserver och API för skanning m.m. (bara Pythons standardbibliotek) |
| `Start NetAtlas.bat` | start i Windows |
| `server/` | serverläget: inloggning, PostgreSQL-lagring, gunicorn |
| `Dockerfile`, `docker-compose.yml`, `docker-compose.host.yml`, `.env.example` | Docker |
| `tests/` | tester för serverläget (körs utan Docker) |

## Utveckling

```bash
python tests/test_server_api.py     # inloggning, valv, bilagor, säkerhetskopior
python tests/test_server_misc.py    # migrering, administration, compose-filer
python tests/server_harness.py      # prova serverläget i webbläsaren: http://localhost:8783
bash tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # på en Docker-värd: hela Docker-versionen, städar själv
```

## Licens

Ingen licens är vald ännu (alla rättigheter förbehållna). Lägg till en `LICENSE`-fil innan repot görs publikt.
