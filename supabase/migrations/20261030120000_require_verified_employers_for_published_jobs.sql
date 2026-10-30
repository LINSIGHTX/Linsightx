-- Keep public job visibility synchronized with employer verification.
-- RLS on sightx_employers intentionally hides employer rows from anonymous visitors.
-- Therefore, do not query that table from the public SELECT policy. Instead, use a
-- private trigger to suspend listings whenever an employer loses verified status.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

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

drop policy if exists "public can view approved published jobs" on public.sightx_job_listings;
create policy "public can view approved published jobs" on public.sightx_job_listings
for select to anon, authenticated using (status = 'published');