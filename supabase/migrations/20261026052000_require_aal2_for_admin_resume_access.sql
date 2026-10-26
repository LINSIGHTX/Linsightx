-- Require MFA assurance for administrator-only resume reads.
-- Applicant self-access and verified hiring-team access remain unchanged.
-- Apply only after reviewing against the live Storage policy and testing AAL1/AAL2 behavior.

drop policy if exists "Applicants and hiring teams read resumes" on storage.objects;

create policy "Applicants and hiring teams read resumes"
on storage.objects
for select
to authenticated
using (
  bucket_id = 'resumes'
  and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or exists (
      select 1
      from public.sightx_applications a
      join public.sightx_job_listings j on j.id = a.job_id
      join public.sightx_employers e on e.id = j.employer_id
      where a.resume_path = objects.name
        and e.owner_id = (select auth.uid())
        and e.verification_status = 'verified'
    )
    or (
      coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
      and coalesce((select auth.jwt() ->> 'aal') = 'aal2', false)
    )
  )
);
