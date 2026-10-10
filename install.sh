#!/usr/bin/env bash
# NetAtlas – installation med ett kommando på Linux eller Unraid (kräver Docker och Docker Compose):
#
#   curl -fsSL https://raw.githubusercontent.com/beerbear78/NetAtlas/main/install.sh | bash
#
# Frågar efter användarnamn, lösenord, port och nät, slumpar fram övriga nycklar och startar NetAtlas
# (appen + PostgreSQL) med den färdiga imagen från ghcr.io. Körs skriptet igen i samma mapp uppdateras
# installationen (befintlig .env behålls).
#
# Utan frågor (t.ex. för automatisering): sätt NETATLAS_PASSWORD och NETATLAS_YES=1. Övriga val:
#   NETATLAS_DIR, NETATLAS_PORT, NETATLAS_USER, NETATLAS_CIDR, NETATLAS_HOSTNET (ja/nej), NETATLAS_2FA, NETATLAS_TAG
set -euo pipefail

RAW="${NETATLAS_RAW:-https://raw.githubusercontent.com/beerbear78/NetAtlas/main}"
SRC="${NETATLAS_SRC:-}"          # lokal mapp med compose-filerna i stället för att ladda ner (används av testerna)
TAG="${NETATLAS_TAG:-latest}"
PULL="${NETATLAS_PULL:-1}"

say() { printf '%s\n' "$*"; }
die() { printf '\nFEL: %s\n' "$*" >&2; exit 1; }
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
say "== NetAtlas – installation"
command -v docker >/dev/null 2>&1 || die "Docker saknas. Installera Docker först (https://docs.docker.com/engine/install/)."
if ! docker compose version >/dev/null 2>&1; then
  if [ -f /etc/unraid-version ]; then die "Docker Compose saknas. Installera pluginet \"Docker Compose Manager\" under Apps i Unraid och kör skriptet igen."; fi
  die "Docker Compose saknas. Installera tillägget docker-compose-plugin (https://docs.docker.com/compose/install/)."
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

ask NETATLAS_DIR "Installationsmapp (här hamnar även databasen)" "$DEF_DIR"
DIR=$NETATLAS_DIR
mkdir -p "$DIR"
cd "$DIR"

# ---- hämta compose-filerna ----
for f in docker-compose.yml docker-compose.host.yml .env.example; do
  if [ -n "$SRC" ]; then cp "$SRC/$f" "$f"; else curl -fsSL "$RAW/$f" -o "$f" || die "Kunde inte hämta $f från $RAW"; fi
done

if [ -f .env ]; then
  say "Befintlig .env hittades i $DIR – den behålls (uppdatering)."
else
  ask NETATLAS_PORT "Port för webbgränssnittet (HTTPS)" "8770"
  ask NETATLAS_USER "Användarnamn för inloggningen" "admin"
  if [ -z "${NETATLAS_PASSWORD:-}" ]; then
    tty_ok || die "Ange lösenordet med NETATLAS_PASSWORD när skriptet körs utan frågor."
    while :; do
      read -r -s -p "Lösenord för inloggningen (minst 8 tecken): " p1 < /dev/tty; echo
      read -r -s -p "Upprepa lösenordet: " p2 < /dev/tty; echo
      if [ "$p1" != "$p2" ]; then say "Lösenorden matchar inte – försök igen."; continue; fi
      if [ ${#p1} -lt 8 ]; then say "För kort – minst 8 tecken."; continue; fi
      case "$p1" in *"'"*) say "Lösenordet får inte innehålla tecknet ' – välj ett annat."; continue ;; esac
      NETATLAS_PASSWORD=$p1; break
    done
  fi
  [ ${#NETATLAS_PASSWORD} -ge 8 ] || die "Lösenordet måste ha minst 8 tecken."
  case "$NETATLAS_PASSWORD" in *"'"*) die "Lösenordet får inte innehålla tecknet '." ;; esac
  ask NETATLAS_CIDR "Ditt nät (för skanning)" "${DEF_CIDR:-192.168.1.0/24}"
  ask NETATLAS_HOSTNET "Full skanning med MAC-adresser och Wake-on-LAN (host-nätverk)? ja/nej" "ja"
  ask NETATLAS_2FA "Tvåstegsinloggning: optional (rekommenderas), required eller off" "optional"
  HOSTS="$IP"
  [ -n "$HOST" ] && HOSTS="${HOSTS:+$HOSTS,}$HOST,$HOST.local"
  {
    echo "# NetAtlas – skapad av install.sh $(date '+%Y-%m-%d %H:%M'). Se .env.example för alla val."
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
  say ".env skapad i $DIR (lösenord och nycklar ligger där – spara en kopia på ett säkert ställe)."
fi

# ---- starta ----
docker compose config --quiet || die "Ogiltig konfiguration i $DIR/.env"
if [ "$PULL" = 1 ]; then docker compose pull --quiet || die "Kunde inte hämta imagen. Är du ansluten till internet?"; fi
docker compose up -d
say "Väntar på att NetAtlas ska starta …"
for _ in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' netatlas 2>/dev/null)" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' netatlas 2>/dev/null)" = healthy ] || die "NetAtlas startade inte. Se loggen: cd $DIR && docker compose logs app"
PORT_NOW=$(grep -E '^PORT=' .env | cut -d= -f2)

say ""
say "== Klart! NetAtlas körs."
say "   Öppna  https://${IP:-SERVERNS-IP}:${PORT_NOW:-8770}  och logga in med användarnamnet och lösenordet du valde."
say "   Första gången varnar webbläsaren för certifikatet (självsignerat) – välj Avancerat → Fortsätt."
say "   Sedan skapar du ett huvudlösenord som krypterar all data i webbläsaren."
say "   Uppdatera senare:  cd $DIR && docker compose pull && docker compose up -d"
}

main "$@"
