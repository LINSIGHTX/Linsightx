-- Keep public job visibility synchronized with employer verification.

-- Keep the full application-time profile snapshot available on fresh and existing databases.
alter table public.sightx_applications
  add column if not exists applicant_profile jsonb not null default '{}'::jsonb;
comment on column public.sightx_applications.applicant_profile is
  'Snapshot of the applicant profile intentionally shared with the employer for this specific application.';

-- Applicants cannot SELECT employer verification rows under employer-table RLS.
-- This private SECURITY DEFINER helper performs only the application eligibility
-- check and explicitly binds the check to the caller's authenticated user id.
create or replace function private.sightx_can_apply_to_job(
  target_job_id uuid,
  target_applicant_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $sightx$
  select auth.uid() is not null
    and auth.uid() = target_applicant_id
    and exists (
      select 1
      from public.sightx_job_listings j
      join public.sightx_employers e on e.id = j.employer_id
      where j.id = target_job_id
        and j.status = 'published'
        and e.verification_status = 'verified'
    );
$sightx$;
revoke all on function private.sightx_can_apply_to_job(uuid, uuid) from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.sightx_can_apply_to_job(uuid, uuid) to authenticated;
-- RLS on sightx_employers intentionally hides employer rows from anonymous visitors.
-- Therefore, do not query that table from the public SELECT policy. Instead, use a
-- private trigger to suspend listings whenever an employer loses verified status.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

-- A listing may only be published while its employer remains verified.
create or replace function public.sightx_require_verified_employer_for_published_job()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.status = 'published' and not exists (
    select 1
    from public.sightx_employers e
    where e.id = new.employer_id
      and e.verification_status = 'verified'
  ) then
    raise exception 'Only jobs belonging to verified employers can be published.'
      using errcode = '23514';
  end if;
  return new;
end;
$$;

drop trigger if exists sightx_require_verified_employer_for_published_job
  on public.sightx_job_listings;
create trigger sightx_require_verified_employer_for_published_job
before insert or update of status, employer_id
on public.sightx_job_listings
for each row
execute function public.sightx_require_verified_employer_for_published_job();

-- This trigger runs only when an employer's verification status changes.
-- It suspends published and pending listings on rejection/suspension; re-verification
-- never republishes them automatically, so an administrator must review them again.
create or replace function private.sightx_suspend_jobs_when_employer_unverified()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.verification_status <> 'verified' then
    update public.sightx_job_listings
       set status = 'suspended',
           reviewed_by = new.reviewed_by,
           reviewed_at = new.reviewed_at
     where employer_id = new.id
       and status in ('published', 'pending_review');
  end if;
  return new;
end;
$$;
revoke all on function private.sightx_suspend_jobs_when_employer_unverified() from public, anon, authenticated;

drop trigger if exists sightx_suspend_jobs_when_employer_unverified on public.sightx_employers;
create trigger sightx_suspend_jobs_when_employer_unverified
after update of verification_status on public.sightx_employers
for each row
when (old.verification_status is distinct from new.verification_status)
execute function private.sightx_suspend_jobs_when_employer_unverified();

-- Private resume bucket: 5 MB maximum, with only supported document formats.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'resumes',
  'resumes',
  false,
  5242880,
  array[
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]::text[]
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- Applicants may upload only into their own user-id folder.
drop policy if exists "Authenticated users upload own resumes" on storage.objects;
create policy "Authenticated users upload own resumes" on storage.objects
for insert to authenticated with check (
  bucket_id = 'resumes'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "public can view approved published jobs" on public.sightx_job_listings;
create policy "public can view approved published jobs" on public.sightx_job_listings
for select to anon, authenticated using (status = 'published');