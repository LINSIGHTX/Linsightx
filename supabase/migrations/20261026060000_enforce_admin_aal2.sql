-- Require AAL2 for SIGHTX administrator access without forcing MFA on ordinary users.
-- Restrictive policies are ANDed with existing permissive policies, so a separate
-- permissive policy cannot accidentally bypass the administrator AAL2 requirement.
-- Non-admin users retain their existing row-level access rules.

do $$
declare
  target_table text;
begin
  foreach target_table in array array[
    'sightx_profiles',
    'sightx_employers',
    'sightx_job_listings',
    'sightx_applications',
    'sightx_job_reports'
  ]
  loop
    execute format(
      'drop policy if exists %I on public.%I',
      'SIGHTX admins require AAL2',
      target_table
    );
    execute format(
      'create policy %I on public.%I as restrictive for all to authenticated
       using (
         not coalesce((select auth.jwt() -> ''app_metadata'' ->> ''role'') = ''admin'', false)
         or (select auth.jwt() ->> ''aal'') = ''aal2''
       )
       with check (
         not coalesce((select auth.jwt() -> ''app_metadata'' ->> ''role'') = ''admin'', false)
         or (select auth.jwt() ->> ''aal'') = ''aal2''
       )',
      'SIGHTX admins require AAL2',
      target_table
    );
  end loop;
end
$$;

