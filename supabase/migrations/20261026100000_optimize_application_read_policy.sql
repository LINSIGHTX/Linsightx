-- Avoid per-row auth.jwt() evaluation in the application SELECT policy.
-- Authorization semantics are unchanged; only the JWT function call is hoisted.
drop policy if exists "applicants and verified job owners can read applications" on public.sightx_applications;
create policy "applicants and verified job owners can read applications" on public.sightx_applications
for select to authenticated using (
  applicant_id = (select auth.uid())
  or exists (
    select 1
    from public.sightx_job_listings j
    join public.sightx_employers e on e.id = j.employer_id
    where j.id = sightx_applications.job_id
      and e.owner_id = (select auth.uid())
      and e.verification_status = 'verified'
  )
  or coalesce(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin', false)
);
