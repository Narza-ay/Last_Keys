#!/usr/bin/env bash
# Dumps the database (ciphertext and metadata only) to infra/backups/.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p backups
file="backups/lastkeys-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T db pg_dump -U lastkeys -d lastkeys --format=custom > "$file"
if [[ ! -s "$file" ]]; then
  echo "backup failed: empty dump" >&2
  rm -f "$file"
  exit 1
fi
echo "$file"
echo "Keep secrets/server_secret too (stored separately): a dump without it cannot be used to log in." >&2
