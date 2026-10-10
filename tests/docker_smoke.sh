#!/bin/bash
# Röktest av Docker-versionen. Körs på Docker-värden (t.ex. Unraid) i en klon av repot:
#
#   bash tests/docker_smoke.sh [nät att skanna] [adress som ska svara på ping]
#   t.ex.  bash tests/docker_smoke.sh 192.168.0.0/24 192.168.0.1
#
# Bygger och startar med egna namn (netatlas-test, port 8790 och 5433), testar grundfunktioner, omstart,
# backup/återställning, tvåstegsinloggning och host-nätverk – och tar sedan bort containrar, data och de images
# testet hämtade. Din .env och en riktig installation rörs inte.
set -u
cd "$(dirname "$0")/.."
CIDR="${1:-}"
PING_IP="${2:-}"
PROJ=netatlas-test
WORK=$(mktemp -d /tmp/netatlas-smoke.XXXXXX)
ENVF="$WORK/test.env"
OVR="$WORK/test.yml"
FAILS=0
HOSTNET=
BEFORE=$(docker images --format '{{.Repository}}:{{.Tag}}' | sort)

cat > "$ENVF" <<EOF
APP_USER=admin
APP_PASSWORD=$(openssl rand -hex 12)
APP_SECRET=$(openssl rand -hex 32)
LOGIN_2FA=optional
PORT=8790
TLS=on
SCAN_CIDRS=$CIDR
APPDATA=$WORK/data
POSTGRES_PASSWORD=$(openssl rand -hex 24)
DB_HOST_PORT=5433
EOF
cat > "$OVR" <<'EOF'
services:
  app:
    image: netatlas-test:latest
    container_name: netatlas-test
  db:
    container_name: netatlas-test-db
EOF

# bygger från källkoden i den här klonen (docker-compose.build.yml) – testar alltså koden, inte den publicerade imagen
dc() { docker compose -p "$PROJ" --env-file "$ENVF" -f docker-compose.yml -f docker-compose.build.yml ${HOSTNET:+-f docker-compose.host.yml} -f "$OVR" "$@"; }

healthy() {
  for _ in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' netatlas-test 2>/dev/null)" = healthy ] && return 0
    sleep 2
  done
  echo "  FEL  appen blev inte frisk – senaste loggraderna:"
  docker logs --tail 30 netatlas-test 2>&1 | sed 's/^/       /'
  FAILS=$((FAILS + 1))
  return 1
}

phase() {
  docker exec -i -e SMOKE_CIDR="$CIDR" -e SMOKE_PING_IP="$PING_IP" netatlas-test python - "$1" < tests/docker_smoke.py || FAILS=$((FAILS + 1))
}

cleanup() {
  echo "== Städar"
  HOSTNET=1 dc down -v >/dev/null 2>&1
  HOSTNET= dc down -v >/dev/null 2>&1
  rm -rf "$WORK"
  AFTER=$(docker images --format '{{.Repository}}:{{.Tag}}' | sort)
  for img in $(comm -13 <(echo "$BEFORE") <(echo "$AFTER")); do
    docker rmi "$img" >/dev/null 2>&1 && echo "  borttagen image: $img"
  done
  docker image prune -f >/dev/null 2>&1
  docker builder prune -af >/dev/null 2>&1
  if [ "$FAILS" -eq 0 ]; then echo "== Klart: alla faser godkända"; else echo "== Klart: $FAILS fas(er) med fel"; fi
}
trap cleanup EXIT

echo "== Bygger och startar"
if ! dc up -d --build > "$WORK/build.log" 2>&1; then
  echo "  FEL  bygget/starten misslyckades:"
  tail -30 "$WORK/build.log" | sed 's/^/       /'
  FAILS=1
  exit 1
fi
healthy || exit 1
docker logs netatlas-test 2>&1 | grep -E "certifikat|gunicorn" | sed 's/^/  /'

echo "== Fas 1: grundfunktioner"
phase seed

echo "== Fas 2: omstart (down/up)"
dc down >/dev/null 2>&1
dc up -d >/dev/null 2>&1
healthy && phase verify

echo "== Fas 3: backup med pg_dump och återställning med psql"
dc exec -T db pg_dump -U netatlas -d netatlas --clean --if-exists > "$WORK/dump.sql"
echo "  dump: $(wc -c < "$WORK/dump.sql") byte"
dc exec -T db psql -qtA -U netatlas -d netatlas -c "DELETE FROM vault; DELETE FROM files;" >/dev/null
dc stop app >/dev/null 2>&1
dc exec -T db psql -q -U netatlas -d netatlas < "$WORK/dump.sql" >/dev/null
dc start app >/dev/null 2>&1
healthy && phase verify

echo "== Fas 4: tvåstegsinloggning"
sed -i 's/^LOGIN_2FA=.*/LOGIN_2FA=required/' "$ENVF"
dc up -d >/dev/null 2>&1
healthy && phase twofa

echo "== Fas 5: host-nätverk (full skanning)"
sed -i 's/^LOGIN_2FA=.*/LOGIN_2FA=off/' "$ENVF"
HOSTNET=1
dc up -d >/dev/null 2>&1
healthy && phase hostnet

exit "$FAILS"
