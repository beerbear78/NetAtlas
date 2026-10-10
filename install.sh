#!/usr/bin/env bash
# NetAtlas – installation med ett kommando på Linux eller Unraid (kräver Docker och Docker Compose):
#
#   curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
#
# Frågar efter användarnamn, lösenord, port och nät, slumpar fram övriga nycklar och startar NetAtlas
# (appen + PostgreSQL) med den färdiga imagen från ghcr.io. Körs skriptet igen i samma mapp uppdateras
# installationen (befintlig .env behålls). Texterna är på engelska, eller svenska om systemet är svenskt
# (LANG=sv_…); NETATLAS_LANG=en|sv väljer språk.
#
# Utan frågor (t.ex. för automatisering): sätt NETATLAS_PASSWORD och NETATLAS_YES=1. Övriga val:
#   NETATLAS_DIR, NETATLAS_PORT, NETATLAS_USER, NETATLAS_CIDR, NETATLAS_HOSTNET (ja/nej, yes/no), NETATLAS_2FA,
#   NETATLAS_TAG
set -euo pipefail

RAW="${NETATLAS_RAW:-https://raw.githubusercontent.com/beerbear78/NetAtlas/main}"
SRC="${NETATLAS_SRC:-}"          # lokal mapp med compose-filerna i stället för att ladda ner (används av testerna)
TAG="${NETATLAS_TAG:-latest}"
PULL="${NETATLAS_PULL:-1}"
case "${NETATLAS_LANG:-${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}}" in sv*) SV=1 ;; *) SV= ;; esac

L() { if [ -n "$SV" ]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }   # L "svenska" "English"
say() { printf '%s\n' "$*"; }
die() { printf '\n%s: %s\n' "$(L FEL ERROR)" "$*" >&2; exit 1; }
tty_ok() { [ -z "${NETATLAS_YES:-}" ] && { : < /dev/tty; } 2>/dev/null; }
ask() {  # ask VARIABEL "fråga" "standardvärde"
  local var=$1 q=$2 def=${3:-} ans=''
  if [ -n "${!var:-}" ]; then return 0; fi
  if tty_ok; then read -r -p "$q [$def]: " ans < /dev/tty || true; fi
  printf -v "$var" '%s' "${ans:-$def}"
}
rand() { if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"; else head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi; }

# allt körs i main(), som anropas sist – då har bash läst hela skriptet innan något körs (säkert med curl | bash)
main() {
say "== NetAtlas – $(L installation installer)"
command -v docker >/dev/null 2>&1 || die "$(L 'Docker saknas. Installera Docker först' 'Docker is missing. Install Docker first') (https://docs.docker.com/engine/install/)."
if ! docker compose version >/dev/null 2>&1; then
  if [ -f /etc/unraid-version ]; then die "$(L 'Docker Compose saknas. Installera pluginet "Docker Compose Manager" under Apps i Unraid och kör skriptet igen.' 'Docker Compose is missing. Install the "Docker Compose Manager" plugin under Apps in Unraid and run the script again.')"; fi
  die "$(L 'Docker Compose saknas. Installera tillägget docker-compose-plugin' 'Docker Compose is missing. Install the docker-compose-plugin package') (https://docs.docker.com/compose/install/)."
fi

# ---- standardval ----
if [ -f /etc/unraid-version ]; then
  DEF_DIR=/mnt/user/appdata/netatlas
  for d in /mnt/user/appdata /mnt/user/docker/appdata; do [ -d "$d" ] && DEF_DIR="$d/netatlas" && break; done
elif [ "$(id -u)" = 0 ]; then DEF_DIR=/opt/netatlas
else DEF_DIR="$HOME/netatlas"
fi
DEV=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
ADDR=$( [ -n "$DEV" ] && ip -4 -o addr show dev "$DEV" 2>/dev/null | awk '{print $4; exit}' || true)
IP=${ADDR%/*}
DEF_CIDR=""
if [ -n "$ADDR" ]; then
  if [ "${ADDR#*/}" = 24 ]; then DEF_CIDR="${IP%.*}.0/24"; else DEF_CIDR="$ADDR"; fi
fi
HOST=$(hostname 2>/dev/null | tr 'A-Z' 'a-z' || true)

ask NETATLAS_DIR "$(L 'Installationsmapp (här hamnar även databasen)' 'Installation folder (the database is stored here too)')" "$DEF_DIR"
DIR=$NETATLAS_DIR
mkdir -p "$DIR"
cd "$DIR"

# ---- hämta compose-filerna ----
for f in docker-compose.yml docker-compose.host.yml .env.example; do
  if [ -n "$SRC" ]; then cp "$SRC/$f" "$f"; else curl -fsSL "$RAW/$f" -o "$f" || die "$(L "Kunde inte hämta $f från $RAW" "Could not download $f from $RAW")"; fi
done

if [ -f .env ]; then
  say "$(L "Befintlig .env hittades i $DIR – den behålls (uppdatering)." "Existing .env found in $DIR – it is kept (update).")"
else
  ask NETATLAS_PORT "$(L 'Port för webbgränssnittet (HTTPS)' 'Port for the web interface (HTTPS)')" "8770"
  ask NETATLAS_USER "$(L 'Användarnamn för inloggningen' 'Username for signing in')" "admin"
  if [ -z "${NETATLAS_PASSWORD:-}" ]; then
    tty_ok || die "$(L 'Ange lösenordet med NETATLAS_PASSWORD när skriptet körs utan frågor.' 'Set the password with NETATLAS_PASSWORD when running without questions.')"
    while :; do
      read -r -s -p "$(L 'Lösenord för inloggningen (minst 8 tecken): ' 'Password for signing in (at least 8 characters): ')" p1 < /dev/tty; echo
      read -r -s -p "$(L 'Upprepa lösenordet: ' 'Repeat the password: ')" p2 < /dev/tty; echo
      if [ "$p1" != "$p2" ]; then say "$(L 'Lösenorden matchar inte – försök igen.' 'The passwords do not match – try again.')"; continue; fi
      if [ ${#p1} -lt 8 ]; then say "$(L 'För kort – minst 8 tecken.' 'Too short – at least 8 characters.')"; continue; fi
      case "$p1" in *"'"*) say "$(L "Lösenordet får inte innehålla tecknet ' – välj ett annat." "The password must not contain the character ' – choose another one.")"; continue ;; esac
      NETATLAS_PASSWORD=$p1; break
    done
  fi
  [ ${#NETATLAS_PASSWORD} -ge 8 ] || die "$(L 'Lösenordet måste ha minst 8 tecken.' 'The password must have at least 8 characters.')"
  case "$NETATLAS_PASSWORD" in *"'"*) die "$(L "Lösenordet får inte innehålla tecknet '." "The password must not contain the character '.")" ;; esac
  ask NETATLAS_CIDR "$(L 'Ditt nät (för skanning)' 'Your network (for scanning)')" "${DEF_CIDR:-192.168.1.0/24}"
  ask NETATLAS_HOSTNET "$(L 'Full skanning med MAC-adresser och Wake-on-LAN (host-nätverk)? ja/nej' 'Full scanning with MAC addresses and Wake-on-LAN (host network)? yes/no')" "$(L ja yes)"
  ask NETATLAS_2FA "$(L 'Tvåstegsinloggning: optional (rekommenderas), required eller off' 'Two-factor sign-in: optional (recommended), required or off')" "optional"
  HOSTS="$IP"
  [ -n "$HOST" ] && HOSTS="${HOSTS:+$HOSTS,}$HOST,$HOST.local"
  {
    echo "# NetAtlas – $(L 'skapad av install.sh' 'created by install.sh') $(date '+%Y-%m-%d %H:%M'). $(L 'Se .env.example för alla val.' 'See .env.example for all options.')"
    echo "APP_USER=$NETATLAS_USER"
    echo "APP_PASSWORD='$NETATLAS_PASSWORD'"
    echo "APP_SECRET=$(rand 32)"
    echo "LOGIN_2FA=$NETATLAS_2FA"
    echo "SESSION_HOURS=12"
    echo "PORT=$NETATLAS_PORT"
    echo "TLS=on"
    echo "TLS_HOSTS=$HOSTS"
    echo "ALLOWED_HOSTS="
    echo "SCAN_CIDRS=$NETATLAS_CIDR"
    echo "DB_HOST_PORT=5433"
    echo "APPDATA=$DIR"
    echo "PUID=99"
    echo "PGID=100"
    echo "TZ=${TZ:-Europe/Stockholm}"
    echo "NETATLAS_TAG=$TAG"
    echo "POSTGRES_DB=netatlas"
    echo "POSTGRES_USER=netatlas"
    echo "POSTGRES_PASSWORD=$(rand 24)"
    case "$NETATLAS_HOSTNET" in j*|J*|y*|Y*|1|true) echo "COMPOSE_FILE=docker-compose.yml:docker-compose.host.yml" ;; esac
  } > .env
  chmod 600 .env
  unset NETATLAS_PASSWORD p1 p2 2>/dev/null || true
  say "$(L ".env skapad i $DIR (lösenord och nycklar ligger där – spara en kopia på ett säkert ställe)." ".env created in $DIR (passwords and keys are stored there – keep a copy in a safe place).")"
fi

# ---- Unraid: visa NetAtlas under Compose i Docker-fliken (pluginet Compose Manager), uppdatering med en knapp ----
# Pluginet kör "docker compose -f <stack>/docker-compose.yml -f <stack>/docker-compose.override.yml --env-file …",
# så host-läget läggs som override (alltid sist) och .env pekas ut med envpath.
CM=/boot/config/plugins/compose.manager/projects
if [ -d "$CM" ]; then
  P="$CM/netatlas"
  mkdir -p "$P"
  printf 'netatlas' > "$P/name"
  rm -f "$P/indirect"
  cp docker-compose.yml "$P/docker-compose.yml"
  if grep -qE '^COMPOSE_FILE=.*docker-compose\.host\.yml' .env; then cp docker-compose.host.yml "$P/docker-compose.override.yml"
  else rm -f "$P/docker-compose.override.yml"; fi
  printf '%s' "$DIR/.env" > "$P/envpath"
  CM_OK=1
fi

# ---- starta ----
docker compose config --quiet || die "$(L "Ogiltig konfiguration i $DIR/.env" "Invalid configuration in $DIR/.env")"
if [ "$PULL" = 1 ]; then docker compose pull --quiet || die "$(L 'Kunde inte hämta imagen. Är du ansluten till internet?' 'Could not pull the image. Are you connected to the internet?')"; fi
docker compose up -d
say "$(L 'Väntar på att NetAtlas ska starta …' 'Waiting for NetAtlas to start …')"
for _ in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' netatlas 2>/dev/null)" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' netatlas 2>/dev/null)" = healthy ] || die "$(L 'NetAtlas startade inte. Se loggen:' 'NetAtlas did not start. See the log:') cd $DIR && docker compose logs app"
PORT_NOW=$(grep -E '^PORT=' .env | cut -d= -f2)
URL="https://${IP:-$(L SERVERNS-IP SERVER-IP)}:${PORT_NOW:-8770}"

say ""
if [ -n "$SV" ]; then
  say "== Klart! NetAtlas körs."
  say "   Öppna  $URL  och logga in med användarnamnet och lösenordet du valde."
  say "   Första gången varnar webbläsaren för certifikatet (självsignerat) – välj Avancerat → Fortsätt."
  say "   Sedan skapar du ett huvudlösenord som krypterar all data i webbläsaren."
  say "   Uppdatera senare:  cd $DIR && docker compose pull && docker compose up -d"
  if [ -n "${CM_OK:-}" ]; then say "   … eller i Unraid: Docker-fliken → Compose → netatlas → Update Stack."; fi
else
  say "== Done! NetAtlas is running."
  say "   Open  $URL  and sign in with the username and password you chose."
  say "   The first time, the browser warns about the certificate (self-signed) – choose Advanced → Proceed."
  say "   Then you create a master password that encrypts all data in the browser."
  say "   Update later:  cd $DIR && docker compose pull && docker compose up -d"
  if [ -n "${CM_OK:-}" ]; then say "   … or in Unraid: Docker tab → Compose → netatlas → Update Stack."; fi
fi
}

main "$@"
