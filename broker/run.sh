#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
test "${GITHUB_ACTIONS:-}" = true
test "$(uname -s)-$(uname -m)" = Linux-x86_64
work=$(mktemp -d "$RUNNER_TEMP/t27-broker.XXXXXX")
keycloak=$(sed -n '1p' images.lock)
postgres=$(sed -n '2p' images.lock)
cleanup() {
  result=$?
  trap - EXIT
  if [ "$result" -ne 0 ]; then
    docker logs --tail 80 t27-auth-keycloak 2>&1 || true
    docker logs --tail 20 t27-auth-postgres 2>&1 || true
  fi
  docker rm -f -v t27-auth-keycloak t27-auth-postgres >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
python3 acceptance.py render "$work/t27os-telegram-realm.json"
chmod 644 "$work/t27os-telegram-realm.json"
openssl genrsa -out "$work/upstream-fixture.pem" 2048
docker pull "$postgres"
docker pull "$keycloak"
docker run -d --name t27-auth-postgres --network host \
  -e POSTGRES_USER=keycloak -e POSTGRES_DB=keycloak -e POSTGRES_PASSWORD=synthetic-db-password \
  "$postgres" -c listen_addresses=127.0.0.1 -c port=15432 >/dev/null
for i in $(seq 1 30); do
  if docker exec t27-auth-postgres pg_isready -h 127.0.0.1 -p 15432 -U keycloak -d keycloak >/dev/null; then
    break
  fi
  sleep 1
done
docker exec t27-auth-postgres pg_isready -h 127.0.0.1 -p 15432 -U keycloak -d keycloak
docker run -d --name t27-auth-keycloak --network host \
  -e KC_DB=postgres -e KC_DB_URL=jdbc:postgresql://127.0.0.1:15432/keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=synthetic-db-password \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=synthetic-admin-password \
  -e KC_HOSTNAME=http://127.0.0.1:18080 -e KC_HTTP_ENABLED=true -e KC_HTTP_PORT=18080 \
  -e KC_HTTP_HOST=127.0.0.1 -e KC_HTTP_ACCESS_LOG_ENABLED=false \
  --mount "type=bind,src=$work/t27os-telegram-realm.json,dst=/opt/keycloak/data/import/t27os-telegram-realm.json,readonly" \
  "$keycloak" start --import-realm >/dev/null
python3 acceptance.py run "$work/upstream-fixture.pem"
