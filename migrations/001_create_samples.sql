CREATE TABLE IF NOT EXISTS samples (
    id BIGSERIAL PRIMARY KEY,
    original_filename TEXT NOT NULL,
    sha256 CHAR(64) NOT NULL UNIQUE,
    file_size BIGINT NOT NULL,
    storage_path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'uploaded',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);