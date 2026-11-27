#!/usr/bin/env bash
# End-to-end test of the self-hosted Docker Compose stack:
#   setup -> start -> TLS proxy health -> register + sync with the real CLI
#   -> canary checks on the database and the logs (V-Y1)
#   -> backup -> one more change -> destroy every volume -> restore the
#   (now older) backup -> clients refuse to sync until `lk sync --reset`
#   -> the reset uploads the missing change -> a new device gets everything.
# Requires: docker (compose v2), curl, an image tagged $LK_SERVER_IMAGE
# (default lastkeys/server:local) and the lk binary ($LK_BIN).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
lk="${LK_BIN:-$root/target/release/lk}"
[[ "$lk" == /* ]] || lk="$PWD/$lk"   # the script changes directory below
export LK_SERVER_IMAGE="${LK_SERVER_IMAGE:-lastkeys/server:local}"
export COMPOSE_PROJECT_NAME=lastkeys-smoke
work="$(mktemp -d)"
master="smoke test master password"
email="smoke@example.com"
canary="SMOKE-CANARY-PLAINTEXT-7f3a9c"

compose() { docker compose -f docker-compose.yml -f compose-smoke.override.yml "$@"; }
cleanup() {
  (cd "$work/infra" 2>/dev/null && compose down -v --remove-orphans >/dev/null 2>&1) || true
  rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { echo "SMOKE TEST FAILED: $*" >&2; exit 1; }
lkcmd() { local vault="$1"; shift; "$lk" --vault "$vault" --password-stdin "$@"; }

wait_healthy() {
  for _ in $(seq 1 90); do
    if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q server)" 2>/dev/null)" == healthy ]]; then
      return 0
    fi
    sleep 2
  done
  compose logs --tail 50 server >&2 || true
  fail "server did not become healthy"
}

[[ -x "$lk" ]] || fail "lk binary not found at $lk (cargo build --release -p lk-cli)"
docker image inspect "$LK_SERVER_IMAGE" >/dev/null || fail "image $LK_SERVER_IMAGE not found"

step "Prepare an isolated copy of infra/"
cp -r "$root/infra" "$work/infra"
rm -rf "$work/infra/secrets" "$work/infra/backups" "$work/infra/.env"
cp "$root/scripts/compose-smoke.override.yml" "$work/infra/"
cd "$work/infra"
cat > .env <<ENV
LK_DOMAIN=localhost
LK_ALLOW_REGISTRATION=true
LK_HTTP_PORT=18081
LK_HTTPS_PORT=18443
ENV
./setup.sh
[[ "$(stat -c '%a' secrets)" == 700 ]] || fail "secrets directory is not private"

step "Start the stack"
compose up -d
wait_healthy

step "Health through Caddy (TLS, internal CA for localhost)"
# Caddy has no health check: it may still be issuing its internal
# certificate right after start. Retry for up to 30 s.
health=""
for _ in $(seq 1 30); do
  health="$(curl -sfk --resolve localhost:18443:127.0.0.1 https://localhost:18443/v1/health || true)"
  [[ -n "$health" ]] && break
  sleep 1
done
[[ "$health" == *'"status":"ok"'* ]] || fail "unexpected health response: $health"
echo "$health"
[[ "$(compose exec -T server id -u)" == 10001 ]] || fail "server does not run as the unprivileged user"
if curl -s --max-time 2 http://127.0.0.1:5432 >/dev/null 2>&1; then fail "PostgreSQL must not be published"; fi

step "Device A: create, register, add, sync"
init_out="$(printf '%s\n%s\n' "$master" "$master" | lkcmd "$work/a.lkvault" init)"
recovery="$(sed -n 's/^Recovery key: //p' <<<"$init_out")"
printf '%s\n%s\n' "$master" "$recovery" | lkcmd "$work/a.lkvault" register --server http://127.0.0.1:18080 --email "$email"
printf '%s\n' "$master" | lkcmd "$work/a.lkvault" add login --title "Smoke Bank" --username alice --generate
lkcmd "$work/a.lkvault" add note --title "Smoke Note" <<<"$master
$canary"
sync_out="$(printf '%s\n' "$master" | lkcmd "$work/a.lkvault" sync)"
[[ "$sync_out" == *"2 sent"* ]] || fail "unexpected sync output: $sync_out"

step "V-Y1: no plaintext, password or e-mail where the server keeps data"
plain_dump="$(compose exec -T db pg_dump -U lastkeys -d lastkeys --format=plain)"
[[ "$plain_dump" == *"$email"* ]] || fail "sanity: the plain dump should contain the account"
[[ "$plain_dump" != *"$canary"* ]] || fail "item plaintext found in the database"
[[ "$plain_dump" != *"$master"* ]] || fail "master password found in the database"
server_logs="$(compose logs --no-color server)"
[[ "$server_logs" == *"account registered"* ]] || fail "sanity: server logs are empty"
for secret in "$canary" "$master" "$email"; do
  [[ "$server_logs" != *"$secret"* ]] || fail "server logs contain a secret or an e-mail"
done
echo "no canary, password or e-mail found"

step "Backup"
dump="$(./backup.sh 2>/dev/null | tail -1)"
[[ -s "$dump" ]] || fail "backup produced no file"
ls -l "$dump"

step "A change made after the backup"
lkcmd "$work/a.lkvault" add note --title "Smoke Late" <<<"$master
written after the backup"
sync_out="$(printf '%s\n' "$master" | lkcmd "$work/a.lkvault" sync)"
[[ "$sync_out" == *"1 sent"* ]] || fail "unexpected sync output: $sync_out"

step "Destroy every volume, start fresh, restore the older backup"
compose down -v
compose up -d
wait_healthy
./restore.sh "$dump"
wait_healthy

step "Device A refuses to synchronize with the restored (older) server"
if rollback_out="$(printf '%s\n' "$master" | lkcmd "$work/a.lkvault" sync 2>&1)"; then
  fail "sync after a restore must be refused: $rollback_out"
fi
[[ "$rollback_out" == *"lk sync --reset"* ]] || fail "unexpected refusal: $rollback_out"
echo "refused as expected"

step "Full resynchronization uploads what the backup missed"
reset_out="$(printf '%s\n' "$master" | lkcmd "$work/a.lkvault" sync --reset)"
echo "$reset_out"
# Identical items are adopted, only the missing one is sent, no copy needed.
[[ "$reset_out" == *"1 sent, 0 conflict(s)"* && "$reset_out" != *"conflict copy"* ]] || fail "unexpected reset output: $reset_out"

step "Device B enrolls after the restore and receives everything"
login_out="$(printf '%s\n' "$master" | lkcmd "$work/b.lkvault" login --server http://127.0.0.1:18080 --email "$email" --device-name smoke-b)"
[[ "$login_out" == *"3 item(s) received"* ]] || fail "unexpected login output: $login_out"
list_out="$(printf '%s\n' "$master" | lkcmd "$work/b.lkvault" list)"
for title in "Smoke Bank" "Smoke Note" "Smoke Late"; do
  [[ "$list_out" == *"$title"* ]] || fail "item missing after restore: $title"
done
printf '%s\n' "$master" | lkcmd "$work/a.lkvault" sync

echo
echo "SMOKE TEST PASSED"
