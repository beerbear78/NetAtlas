#!/bin/sh
# NetAtlas i Docker: förbered /data (rättigheter, certifikat, SSH-nyckel) och starta gunicorn som vanlig användare.
# Containern startar som root bara för att kunna rätta ägare på appdata-mappen (Unraid skapar den som root),
# sedan körs appen som PUID:PGID – standard 99:100 (nobody:users), samma som Unraid använder för appdata.
set -eu

PUID="${PUID:-99}"
PGID="${PGID:-100}"
DATA="${NETATLAS_DATA_DIR:-/data}"
TLS="${TLS:-on}"

mkdir -p "$DATA/backups" "$DATA/certs" "$DATA/import" "$DATA/home/.ssh"

if [ "$(id -u)" = "0" ]; then
  getent group "$PGID" >/dev/null 2>&1 || groupadd -o -g "$PGID" netatlas
  if [ "$(id -u netatlas)" != "$PUID" ] || [ "$(id -g netatlas)" != "$PGID" ]; then
    usermod -o -u "$PUID" -g "$PGID" netatlas
  fi
fi

# HTTPS: skapa ett självsignerat certifikat första gången (om du inte angett ett eget via TLS_CERT/TLS_KEY)
case "$TLS" in
  off|false|0|no|nej) ;;
  *)
    if [ -z "${TLS_CERT:-}" ] && { [ ! -s "$DATA/certs/cert.pem" ] || [ ! -s "$DATA/certs/key.pem" ]; }; then
      SAN="DNS:localhost,DNS:netatlas,IP:127.0.0.1"
      for h in $(echo "${TLS_HOSTS:-}" | tr ',' ' '); do
        case "$h" in
          *:*) SAN="$SAN,IP:$h" ;;
          *[!0-9.]*) SAN="$SAN,DNS:$h" ;;
          *) SAN="$SAN,IP:$h" ;;
        esac
      done
      # egen konfiguration så att resultatet inte beror på systemets openssl.cnf
      CNF="$DATA/certs/.openssl.cnf"
      printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ext' 'prompt = no' \
        '[dn]' 'CN = NetAtlas' \
        '[ext]' "subjectAltName = $SAN" 'basicConstraints = critical,CA:FALSE' \
        'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' 'subjectKeyIdentifier = hash' > "$CNF"
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 -config "$CNF" \
        -keyout "$DATA/certs/key.pem" -out "$DATA/certs/cert.pem" 2>/dev/null
      rm -f "$CNF"
      echo "NetAtlas: skapade ett självsignerat certifikat för $SAN (giltigt i 825 dagar)."
    fi
    ;;
esac

# SSH-nyckel för import av rutiner från Unraid/Linux-servrar
if [ ! -s "$DATA/home/.ssh/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "netatlas" -f "$DATA/home/.ssh/id_ed25519"
fi
echo "NetAtlas: publik SSH-nyckel för import (lägg i ~/.ssh/authorized_keys på servrarna):"
echo "  $(cat "$DATA/home/.ssh/id_ed25519.pub")"

cd /app
if [ "$(id -u)" = "0" ]; then
  chown -R "$PUID:$PGID" "$DATA"
  chmod 700 "$DATA/home/.ssh"
  chmod 600 "$DATA/home/.ssh/id_ed25519" "$DATA/certs/key.pem" 2>/dev/null || true
  exec setpriv --reuid="$PUID" --regid="$PGID" --init-groups gunicorn -c /app/server/gunicorn.conf.py server.app:app
fi
exec gunicorn -c /app/server/gunicorn.conf.py server.app:app
