# NetAtlas

**English** | [Svenska](README.sv.md)

[![Tests](https://github.com/beerbear78/NetAtlas/actions/workflows/tester.yml/badge.svg)](https://github.com/beerbear78/NetAtlas/actions/workflows/tester.yml)

IT inventory on your floor plan: firewalls, switches, servers, cameras and IoT devices (e.g. Shelly) placed on the
plan of your home or office – with accounts and passwords that are encrypted in the browser.

## Features

- **Map** – floor plans from an image or PDF, rooms, devices and camera fields of view
- **Devices** – sortable table, overview with status and a to-do list (weak passwords, warranties, certificates …)
- **Accounts and passwords** – masked, with TOTP codes and attachments; everything encrypted with the master password
- **Network** – scanning (ping, ARP, ports, manufacturer), Live status, IP plan, Shelly Gen1–Gen4
- **Routines and jobs** – import from Home Assistant, Unraid and Linux (cron/systemd over SSH)
- **Contracts and licenses**, backups (local, sync folder, S3/WebDAV), mobile copy, printing and two-factor authentication
- **English and Swedish** – switch with the globe (🌐) in the top bar, on the sign-in screen or under Settings

## Getting started

**Windows (local):** requires [Python 3](https://www.python.org/downloads/). Download `NetAtlas-windows-….zip` from
[Releases](https://github.com/beerbear78/NetAtlas/releases/latest), unzip it and double-click `Start NetAtlas.bat` –
the app opens at http://127.0.0.1:8770 and your data is stored encrypted in the browser.

**Server (Docker, e.g. Unraid):** run this as root in the server's terminal – the script asks for port, password and
network, creates `.env` with random secrets and starts everything:

```bash
curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
```

Two containers (the app from `ghcr.io/beerbear78/netatlas` and PostgreSQL 16), HTTPS and sign-in with optional
two-factor authentication. Manual installation, updates and backups: see [DEPLOY.md](DEPLOY.md).

## Security

- Everything sensitive is encrypted in the browser (AES-GCM, key derived from the master password with PBKDF2)
  before it is saved – neither the helper, the server nor the database ever sees plain text.
- Locally the helper only listens on 127.0.0.1. On the server, sign-in and HTTPS are required.
- The repository contains no passwords, floor plans or other personal data. `.env` is never committed.

## Structure

| File/folder | Contents |
|---|---|
| `netatlas.html` | the whole app – HTML, CSS and JavaScript in one file |
| `netatlas-helper.py` | web server and API for scanning etc. (Python standard library only) |
| `Start NetAtlas.bat` | start script for Windows |
| `server/` | server mode: sign-in, PostgreSQL storage, gunicorn |
| `Dockerfile`, `docker-compose*.yml`, `.env.example` | Docker (`docker-compose.build.yml` builds from source) |
| `install.sh` | installer for the server |
| `tests/` | tests for server mode and translations (run without Docker) |
| `.github/workflows/` | tests, image publishing and releases |

## Development

```bash
python tests/test_server_api.py     # sign-in, vault, attachments, backups
python tests/test_server_misc.py    # migration, admin commands, compose files
python tests/test_i18n.py           # Swedish/English: missing translations and leftover Swedish
python tests/server_harness.py      # try server mode in the browser: http://localhost:8783
bash tests/docker_smoke.sh 192.168.1.0/24 192.168.1.1   # on a Docker host: the full Docker version, cleans up after itself
```

The code, comments and commit messages are in Swedish; the user interface is available in Swedish and English.

## License

[MIT](LICENSE) – free to use, modify and share.
