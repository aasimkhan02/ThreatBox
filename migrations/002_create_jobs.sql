CREATE TABLE IF NOT EXISTS jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    file_id UUID NOT NULL,
    
    type TEXT NOT NULL DEFAULT 'malware_scan',
    
    status TEXT NOT NULL DEFAULT 'pending',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (file_id) REFERENCES samples(sample_id)
);