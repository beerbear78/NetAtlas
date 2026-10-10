# NetAtlas

[![Tester](https://github.com/beerbear78/NetAtlas/actions/workflows/tester.yml/badge.svg)](https://github.com/beerbear78/NetAtlas/actions/workflows/tester.yml)

IT-inventarie på planritningen: brandväggar, switchar, servrar, kameror och IoT-enheter (t.ex. Shelly) placerade på
husets planlösning – med konton och lösenord som krypteras i webbläsaren.

## Funktioner

- **Karta** – planritningar från bild eller PDF, rum, enheter och kamerors synfält
- **Enheter** – sorterbar tabell, översikt med status och "att göra" (svaga lösenord, garantier, certifikat …)
- **Konton och lösenord** – maskerade, med TOTP-koder och bilagor; allt krypterat med huvudlösenordet
- **Nätverk** – skanning (ping, ARP, portar, tillverkare), Live-status, IP-plan, Shelly Gen1–Gen4
- **Rutiner och jobb** – import från Home Assistant, Unraid och Linux (cron/systemd via SSH)
- **Avtal och licenser**, säkerhetskopior (lokalt, synkmapp, S3/WebDAV), mobilkopia, utskrift och tvåstegsinloggning
- **Svenska och engelska** – byt med jordgloben (🌐) i toppfältet, på inloggningsrutan eller under Inställningar

## Kom igång

**Windows (lokalt):** kräver [Python 3](https://www.python.org/downloads/). Hämta `NetAtlas-windows-….zip` under
[Releases](https://github.com/beerbear78/NetAtlas/releases/latest), packa upp och dubbelklicka på `Start NetAtlas.bat` –
appen öppnas på http://127.0.0.1:8770 och datan sparas krypterad i webbläsaren.

**Server (Docker, t.ex. Unraid):** kör som root i serverns terminal – skriptet frågar efter port, lösenord och nät,
skapar `.env` med slumpade hemligheter och startar allt:

```bash
curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
```

Två containrar (appen från `ghcr.io/beerbear78/netatlas` och PostgreSQL 16), HTTPS och inloggning med valfri
tvåstegskod. Manuell installation, uppdatering och backup: se [DEPLOY.md](DEPLOY.md).

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
| `Dockerfile`, `docker-compose*.yml`, `.env.example` | Docker (`docker-compose.build.yml` bygger från källkoden) |
| `install.sh` | installationsskript för servern |
| `tests/` | tester för serverläget (körs utan Docker) |
| `.github/workflows/` | tester, publicering av imagen och releaser |

## Utveckling

```bash
python tests/test_server_api.py     # inloggning, valv, bilagor, säkerhetskopior
python tests/test_server_misc.py    # migrering, administration, compose-filer
python tests/test_i18n.py           # svenska/engelska: saknade översättningar och kvarglömd svenska
python tests/server_harness.py      # prova serverläget i webbläsaren: http://localhost:8783
bash tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # på en Docker-värd: hela Docker-versionen, städar själv
```

## Licens

[MIT](LICENSE) – fritt att använda, ändra och dela vidare.
