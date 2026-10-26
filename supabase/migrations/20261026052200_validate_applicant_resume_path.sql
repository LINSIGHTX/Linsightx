-- Prevent applicants from attaching another user's Storage object to an application.
-- The resumes bucket is private; its INSERT policy already limits uploads to the user's folder.
-- Keep the database reference consistent with that storage ownership rule.

drop policy if exists "applicants can submit own applications" on public.sightx_applications;

create policy "applicants can submit own applications"
on public.sightx_applications
for insert
to authenticated
with check (
  applicant_id = (select auth.uid())
  and status = 'new'
  and employer_notes is null
  and (
    resume_path is null
    or split_part(resume_path, '/', 1) = (select auth.uid())::text
  )
  and exists (
    select 1
    from public.sightx_job_listings j
    join public.sightx_employers e on e.id = j.employer_id
    where j.id = sightx_applications.job_id
      and j.status = 'published'
      and e.verification_status = 'verified'
  )
);
