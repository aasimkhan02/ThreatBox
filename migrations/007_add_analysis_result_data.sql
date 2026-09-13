ALTER TABLE analysis_results
ADD COLUMN IF NOT EXISTS result_data JSONB;
