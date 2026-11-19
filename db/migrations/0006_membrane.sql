-- =====================================================================
-- Membrane (identity membrane: alias universe for remote LLM requests)
-- =====================================================================
-- Originals are stored only as an HMAC (lookup) and AES-GCM ciphertext.
CREATE TABLE IF NOT EXISTS membrane_entries (
    id            BIGSERIAL PRIMARY KEY,
    kind          TEXT NOT NULL,
    original_hmac TEXT NOT NULL,
    original_enc  BYTEA NOT NULL,
    alias         TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'auto'
                  CHECK (source IN ('seed','auto','operator','model_known')),
    company_ids   BIGINT[] NOT NULL DEFAULT '{}',
    task_ids      BIGINT[] NOT NULL DEFAULT '{}',
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_membrane_entries_orig UNIQUE (kind, original_hmac),
    CONSTRAINT uq_membrane_entries_alias UNIQUE (alias)
);
-- Aliases replaced by a re-mint (e.g. a keyword enrolled after a subdomain)
-- stay valid for reverse lookup only.
ALTER TABLE membrane_entries ADD COLUMN IF NOT EXISTS retired_aliases TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_membrane_entries_companies ON membrane_entries USING GIN(company_ids);

-- Per-real-prefix allocation of alias blocks inside 240.0.0.0/4.
CREATE TABLE IF NOT EXISTS membrane_ip_blocks (
    real_prefix  TEXT PRIMARY KEY,
    alias_prefix TEXT NOT NULL UNIQUE,
    bits         INTEGER NOT NULL CHECK (bits BETWEEN 4 AND 32),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit log. Never stores originals.
CREATE TABLE IF NOT EXISTS membrane_events (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL,
    task_id        TEXT NOT NULL DEFAULT '',
    session        TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT '',
    profile        TEXT NOT NULL DEFAULT '',
    direction      TEXT NOT NULL DEFAULT '',
    counts         JSONB NOT NULL DEFAULT '{}',
    enrolled       INTEGER NOT NULL DEFAULT 0,
    flags          JSONB NOT NULL DEFAULT '[]',
    blocked        BOOLEAN NOT NULL DEFAULT false,
    block_reason   TEXT NOT NULL DEFAULT '',
    request_sha256 TEXT NOT NULL DEFAULT '',
    prev_hash      TEXT NOT NULL DEFAULT '',
    hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_membrane_events_task ON membrane_events(task_id, id);

-- Canonical membrane request hash of a recorded LLM call: pairs an llm_records
-- row with its membrane_events "request" event for offline verification.
ALTER TABLE llm_records ADD COLUMN IF NOT EXISTS membrane_request_sha256 TEXT;
