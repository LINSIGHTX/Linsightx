-- Add covering indexes for foreign keys flagged by the Supabase performance advisor.
-- These indexes do not change row-level security or authorization behavior.
create index if not exists jobs_posted_by_idx on public.jobs (posted_by);
create index if not exists sightx_applications_applicant_id_idx on public.sightx_applications (applicant_id);
create index if not exists sightx_employers_reviewed_by_idx on public.sightx_employers (reviewed_by);
create index if not exists sightx_job_listings_employer_id_idx on public.sightx_job_listings (employer_id);
create index if not exists sightx_job_listings_reviewed_by_idx on public.sightx_job_listings (reviewed_by);
create index if not exists sightx_job_reports_job_id_idx on public.sightx_job_reports (job_id);
create index if not exists sightx_job_reports_reporter_id_idx on public.sightx_job_reports (reporter_id);
create index if not exists sightx_job_reports_reviewed_by_idx on public.sightx_job_reports (reviewed_by);
