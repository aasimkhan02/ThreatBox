CREATE TABLE IF NOT EXISTS analysis_results (
    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    job_id UUID NOT NULL REFERENCES jobs(job_id),
    sample_id UUID NOT NULL REFERENCES samples(sample_id),

    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    status TEXT NOT NULL DEFAULT 'pending',

    CONSTRAINT analysis_results_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed'))
);