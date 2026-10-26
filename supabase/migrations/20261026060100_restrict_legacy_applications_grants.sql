-- public.applications is a legacy table with RLS enabled and no policies.
-- The current SIGHTX frontend uses sightx_* tables and does not query this legacy table.
-- Revoke API-role grants as defense in depth; preserve data and service-role access.
revoke all privileges on table public.applications from anon, authenticated;
