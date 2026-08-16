CREATE TABLE IF NOT EXISTS results (
    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    job_id UUID NOT NULL UNIQUE,

    filename TEXT NOT NULL,

    file_size BIGINT NOT NULL,

    sha256 CHAR(64) NOT NULL,

    status TEXT NOT NULL DEFAULT 'processed',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (job_id) REFERENCES jobs(job_id)
);