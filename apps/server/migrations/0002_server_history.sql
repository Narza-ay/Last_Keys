-- Identifier of the server's history (ADR-0008, "Restore"). Clients remember
-- it and refuse to synchronize when it changes. `infra/restore.sh` replaces it
-- after restoring a backup, so that no client mistakes the restored (older)
-- data for the history it already synchronized with.
CREATE TABLE server_meta (
    singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    history_id  UUID NOT NULL
);
INSERT INTO server_meta (history_id) VALUES (gen_random_uuid());
