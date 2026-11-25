#!/usr/bin/env bash
# Prepares a Last Keys deployment: .env, secrets, server image.
# Idempotent: existing secrets are never overwritten.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created infra/.env — review LK_DOMAIN before starting."
fi

umask 077
mkdir -p secrets
chmod 700 secrets

if [[ ! -s secrets/db_password ]]; then
  head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 40 > secrets/db_password
fi
printf 'postgres://lastkeys:%s@db:5432/lastkeys\n' "$(cat secrets/db_password)" > secrets/database_url

image="${LK_SERVER_IMAGE:-lastkeys/server:local}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker compose build server
fi
if [[ ! -s secrets/server_secret ]]; then
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets:/out" "$image" generate-secret /out/server_secret
fi

# Containers run as other users: files must be readable; the 0700 directory
# keeps them private on the host.
chmod 644 secrets/db_password secrets/database_url secrets/server_secret

echo "Ready. Start with: docker compose up -d"
echo "IMPORTANT: back up infra/secrets/server_secret separately; without it nobody can log in."
