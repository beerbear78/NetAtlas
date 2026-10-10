# NetAtlas on a server (Unraid / Docker)

**English** | [Svenska](DEPLOY.sv.md)

Two containers: **netatlas** (the app from `ghcr.io/beerbear78/netatlas`, HTTPS on port 8770) and **netatlas-db**
(PostgreSQL 16, internal only). All data is stored in the installation folder, e.g. `/mnt/user/appdata/netatlas/`
(`app/` and `postgres/`), so it is included in Unraid's Appdata Backup.
Your data is encrypted in the browser with your master password – the server never sees your passwords.

**Requirements:** Docker with Compose v2 (`docker compose`), amd64 or arm64. On Unraid: install the
**Docker Compose Manager** plugin from *Apps* (tested on Unraid 7.1 with Compose 2.40).

## 1. Install

### With the installer (easiest)

Open a terminal on the server (Unraid: the `>_` icon in the top right corner) and run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
```

The script asks for the installation folder, port, username, password, your network, host networking and two-factor
authentication. The suggested folder is `appdata/netatlas` on Unraid (it finds both `/mnt/user/appdata` and
`/mnt/user/docker/appdata`), otherwise `/opt/netatlas`. It creates `.env` with random keys (readable by root only),
pulls the image, starts everything and waits until it is healthy. The password is never shown and must not contain
the character `'`. The script talks English, or Swedish if the system language is Swedish (`NETATLAS_LANG=en|sv`
overrides).

Without questions, e.g. for automation: set `NETATLAS_PASSWORD` and `NETATLAS_YES=1`. Other options are
`NETATLAS_DIR`, `NETATLAS_PORT`, `NETATLAS_USER`, `NETATLAS_CIDR`, `NETATLAS_HOSTNET` (yes/no), `NETATLAS_2FA` and
`NETATLAS_TAG` – see the top of [install.sh](install.sh).

### Manually

Find out where your containers keep their appdata (*Docker* → a container → *Edit*). The examples use
`/mnt/user/appdata` – replace it with your path.

```bash
mkdir -p /mnt/user/appdata/netatlas && cd /mnt/user/appdata/netatlas
for f in docker-compose.yml docker-compose.host.yml .env.example; do
  curl -fsSLO "https://raw.githubusercontent.com/beerbear78/NetAtlas/main/$f"
done
cp .env.example .env && chmod 600 .env
openssl rand -hex 32   # run twice: for APP_SECRET and POSTGRES_PASSWORD
nano .env
```

Fill in `APP_PASSWORD` (the password you sign in with – choose your own strong one), `APP_SECRET` and
`POSTGRES_PASSWORD`. If a value contains the character `$`, put it in single quotes: `APP_PASSWORD='...'`. Also
change `TLS_HOSTS` (the server's IP and name), `SCAN_CIDRS` (your network) and `APPDATA` (the installation folder).
`LOGIN_2FA` controls two-factor sign-in: `optional` (default – offered at the first sign-in and can be turned on
later), `required` or `off`. `NETATLAS_TAG` selects the version (`latest`, or pin e.g. `1.0.0`).
`.env` contains secrets: keep a copy in a safe place and never commit it.

```bash
docker compose pull
docker compose up -d
docker compose ps                      # both should show (healthy) after half a minute
curl -k https://127.0.0.1:8770/health  # {"status": "ok", "db": "ok"}
```

## 2. First sign-in

Open **https://SERVER-IP:8770** (or WebUI in Unraid's Docker tab). The first time, the browser warns about the
certificate because it is self-signed – choose *Advanced → Proceed*. Sign in with `APP_USER`/`APP_PASSWORD`.
Two-factor authentication is offered at the first sign-in – it is recommended, but you can skip it and turn it on
later under *Settings → Security*. Then create a master password, or move your data as described in step 3.
Switch language with the globe (🌐) on the sign-in page or in the top bar.

*Get rid of the warning:* download `https://SERVER-IP:8770/netatlas.crt`, double-click it and install it under
*Local Machine → Trusted Root Certification Authorities*. If the server's IP or name changes: delete
`app/certs/*.pem` and restart.

Check that your data survives a restart:

```bash
docker compose down && docker compose up -d
```

## 3. Move data from the Windows version (once)

1. In NetAtlas on Windows: turn off two-factor authentication if it is on, and choose *Settings → Back up now*.
2. Copy the new file `backups\netatlas-YYYYMMDD-HHMMSS.json`, and the folder `data\files` if you have attachments,
   to `/mnt/user/appdata/netatlas/app/import/` (attachments in `import/files/`).
3. Run:

```bash
docker compose exec app python -m server.migrate --hint "your hint"
```

4. Sign in and unlock with your usual master password. Then delete `app/import/`.

## 4. Full network scanning (optional)

On a normal Docker network, ping, ports, Shelly, Home Assistant and SSH import work, but not MAC addresses,
Wake-on-LAN or sharing to a phone. Run the app on the host network to get them (the installer asks about this and
sets it up for you). Manually: add the line below to `.env` and run `docker compose up -d`.

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.host.yml
```

The database is then exposed on `127.0.0.1:5433` (local only; change with `DB_HOST_PORT`).

## 5. SSH import of routines

The container creates its own SSH key on first start. Show the public key and add it on the servers you want to
import from (Unraid: *Users → root → SSH authorized keys*):

```bash
docker compose logs app | grep -A1 "SSH"
```

## 6. Update to a new version

**Unraid:** *Docker* tab → the *Compose* section at the bottom → **netatlas** → **Update Stack**. The installer
registers NetAtlas there when the Docker Compose Manager plugin is installed (for an older installation: run the
installer again). Don't use Unraid's own update link on the containers – it only works for containers created from
Unraid templates and fails with "image not found".

**Terminal (all systems):**

```bash
cd /mnt/user/appdata/netatlas
docker compose pull
docker compose up -d
```

Or run the installer again in the same folder – it also fetches the latest compose files. `.env`, the database and
`app/` are left untouched. Versions and changes: [Releases](https://github.com/beerbear78/NetAtlas/releases).
With `NETATLAS_TAG=1.0.0` in `.env` you stay on a specific version until you change it; `main` gives the latest
development version.

**Build from source** (e.g. to try a pull request before it is merged): clone the repository, put your `.env` in
the folder and add `docker-compose.build.yml` to `COMPOSE_FILE`, so the image is built locally instead of pulled:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /mnt/user/appdata/netatlas/src
cd /mnt/user/appdata/netatlas/src
# in .env: COMPOSE_FILE=docker-compose.yml:docker-compose.build.yml   (+ :docker-compose.host.yml for host mode)
git checkout branch-name && docker compose up -d --build
```

To go back: `git checkout main`, remove `docker-compose.build.yml` from `COMPOSE_FILE` and run `docker compose up -d`.

**Smoke test** (optional, e.g. after an update): run the test from a separate copy – it uses its own names and
ports (8790/5433), does not touch your installation and cleans up after itself:

```bash
git clone https://github.com/beerbear78/NetAtlas.git /tmp/netatlas-smoke-src
bash /tmp/netatlas-smoke-src/tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # your network and your router
rm -rf /tmp/netatlas-smoke-src
```

## 7. Backup and restore

**Database backup** (vault, attachments, two-factor keys):

```bash
mkdir -p /mnt/user/backups/netatlas
docker compose exec -T db pg_dump -U netatlas -d netatlas --clean --if-exists \
  > /mnt/user/backups/netatlas/netatlas-$(date +%F).sql
```

**Restore:**

```bash
docker compose stop app
docker compose exec -T db psql -q -U netatlas -d netatlas < /mnt/user/backups/netatlas/netatlas-2026-10-09.sql > /dev/null
docker compose start app
```

The vault in the dump is encrypted with your master password. The two-factor keys are encrypted with `APP_SECRET` –
so keep `.env` together with the backups (but in a safe place). The app's own backups are also stored in
`app/backups/`, and cloud backup (S3/WebDAV) under *Settings* works as before.

## 8. Administration

```bash
docker compose exec app python -m server.cli status      # size, version, last saved
docker compose exec app python -m server.cli reset-2fa   # lost phone: sign in without a code and set it up again
docker compose logs -f app                               # logs
```

Sign out: `https://SERVER-IP:8770/logout`.

## Troubleshooting

| Problem | Solution |
|---|---|
| "This browser lacks Web Crypto" | You are using `http://`. Go to `https://`. |
| The container keeps restarting | `docker compose logs app` – e.g. `APP_PASSWORD` or `APP_SECRET` is missing. |
| Permission errors in appdata | Check `PUID`/`PGID` in `.env` (Unraid: 99/100). |
| Port 8770 is in use | Change `PORT` in `.env`. |
| The database is slow | Put `APPDATA` directly on the cache pool, e.g. `/mnt/cache/appdata/netatlas`. |
| "Could not pull the image" / `manifest unknown` | Check the internet connection and `NETATLAS_TAG` in `.env` (does the version exist under *Releases*?). |
| Unraid: `docker compose` is missing | Install the *Docker Compose Manager* plugin from *Apps*. |
| Unraid: "image not found" when updating in the Docker tab | Use *Compose → netatlas → Update Stack* (or the terminal), see step 6. |

**A regular Linux server instead of Unraid:** the installer works the same way (it suggests `/opt/netatlas`).
If you want the files to be owned by your own user: set `PUID`/`PGID` in `.env` (`id -u`, `id -g`).

Server logs and admin command output are in Swedish.
