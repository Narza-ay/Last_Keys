-- Last Keys server schema, version 1.
-- Timestamps are Unix seconds (BIGINT). Vault data is only ever stored as
-- client-produced ciphertext (JSON envelopes in `encrypted`).

CREATE TABLE accounts (
    id                  UUID PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    bundle              JSONB NOT NULL,
    signing_public_key  BYTEA NOT NULL,
    created_at          BIGINT NOT NULL,
    updated_at          BIGINT NOT NULL
);

CREATE TABLE credentials (
    account_id     UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('password', 'recovery')),
    password_file  BYTEA NOT NULL,
    updated_at     BIGINT NOT NULL,
    PRIMARY KEY (account_id, kind)
);

CREATE TABLE devices (
    id            UUID PRIMARY KEY,
    account_id    UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    certificate   JSONB NOT NULL,
    revocation    JSONB,
    revoked_at    BIGINT,
    created_at    BIGINT NOT NULL,
    last_seen_at  BIGINT
);
CREATE INDEX devices_by_account ON devices (account_id);

CREATE TABLE login_attempts (
    id          UUID PRIMARY KEY,
    account_id  UUID REFERENCES accounts (id) ON DELETE CASCADE,
    device_id   UUID NOT NULL,
    credential  TEXT NOT NULL CHECK (credential IN ('password', 'recovery')),
    state       BYTEA NOT NULL,
    expires_at  BIGINT NOT NULL
);
CREATE INDEX login_attempts_by_expiry ON login_attempts (expires_at);

CREATE TABLE sessions (
    verifier    BYTEA PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id   UUID NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('full', 'enrollment', 'recovery')),
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL
);
CREATE INDEX sessions_by_device ON sessions (device_id);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);

CREATE TABLE account_seq (
    account_id  UUID PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    last_seq    BIGINT NOT NULL CHECK (last_seq >= 0)
);

CREATE TABLE vault_keys (
    account_id  UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    vault_id    UUID NOT NULL,
    wrapped     JSONB NOT NULL,
    PRIMARY KEY (account_id, vault_id)
);

CREATE TABLE items (
    account_id  UUID NOT NULL,
    vault_id    UUID NOT NULL,
    item_id     UUID NOT NULL,
    revision    BIGINT NOT NULL CHECK (revision > 0),
    deleted     BOOLEAN NOT NULL,
    encrypted   JSONB,
    seq         BIGINT NOT NULL,
    updated_by  UUID NOT NULL,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (account_id, item_id),
    FOREIGN KEY (account_id, vault_id) REFERENCES vault_keys (account_id, vault_id) ON DELETE CASCADE,
    CHECK ((deleted AND encrypted IS NULL) OR (NOT deleted AND encrypted IS NOT NULL))
);
CREATE INDEX items_by_seq ON items (account_id, vault_id, seq);

CREATE TABLE applied_changes (
    account_id  UUID NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    change_id   UUID NOT NULL,
    item_id     UUID NOT NULL,
    outcome     JSONB NOT NULL,
    applied_at  BIGINT NOT NULL,
    PRIMARY KEY (account_id, change_id)
);
