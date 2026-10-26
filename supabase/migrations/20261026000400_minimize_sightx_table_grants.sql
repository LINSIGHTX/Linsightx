-- Remove unnecessary client privileges, especially TRUNCATE, DELETE, TRIGGER,
-- and REFERENCES. Row-level security does not protect TRUNCATE, so client roles
-- should never receive it on application data tables.
--
-- RLS policies remain the row-level authorization boundary after these grants.

revoke all privileges on table
  public.sightx_profiles,
  public.sightx_employers,
  public.sightx_job_listings,
  public.sightx_applications,
  public.sightx_job_reports
from public, anon, authenticated;

-- Anonymous visitors may only read job listings; the published-job RLS policy
-- continues to limit which rows are visible.
grant select on table public.sightx_job_listings to anon;

-- Authenticated client operations required by the current SIGHTX UI.
-- RLS policies continue to restrict which rows each user can access/change.
grant select, insert, update on table
  public.sightx_profiles,
  public.sightx_employers,
  public.sightx_job_listings,
  public.sightx_applications,
  public.sightx_job_reports
to authenticated;
