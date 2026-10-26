-- Allow applicants to clean up only unlinked resume objects in their own folder.
-- Used to roll back resume uploads when application insertion fails.
drop policy if exists "Applicants clean up unlinked own resumes" on storage.objects;
create policy "Applicants clean up unlinked own resumes" on storage.objects
for delete to authenticated using (
  bucket_id = 'resumes'
  and (storage.foldername(name))[1] = (select auth.uid())::text
  and not exists (
    select 1 from public.sightx_applications a where a.resume_path = objects.name
  )
);
