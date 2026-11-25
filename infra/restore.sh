#!/usr/bin/env bash
# Restores a dump made by backup.sh. The server secret must be the one in use
# when the dump was made.
#
# The restored data is older than what clients already synchronized, so the
# server history identifier is replaced: every client then stops and asks its
# user for a full resynchronization (`lk sync --reset`), which uploads the
# changes the backup does not contain. Never skip that step.
set -euo pipefail
cd "$(dirname "$0")"
dump="${1:?usage: restore.sh <backups/file.dump>}"
[[ -s "$dump" ]] || { echo "no such dump: $dump" >&2; exit 1; }
docker compose stop server
docker compose exec -T db pg_restore -U lastkeys -d lastkeys --clean --if-exists --no-owner --exit-on-error < "$dump"
# Bring an older dump to the current schema, then start a new history.
docker compose run --rm --no-deps -e LK_LOG=warn server migrate
docker compose exec -T db psql -U lastkeys -d lastkeys -v ON_ERROR_STOP=1 -q \
  -c "UPDATE server_meta SET history_id = gen_random_uuid();"
docker compose start server
echo "Restored $dump"
echo "Every device must now run a full resynchronization (lk sync --reset)." >&2
