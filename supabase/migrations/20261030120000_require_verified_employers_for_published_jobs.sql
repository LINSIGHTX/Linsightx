-- Keep public visibility and admin publishing tied to current employer verification.
-- A published job cannot be newly published (or re-published) unless its employer is verified.
-- Existing published jobs belonging to employers later suspended become invisible publicly
-- because the public SELECT policy checks the employer's current verification status.

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

 drop policy if exists "public can view approved published jobs" on public.sightx_job_listings;
create policy "public can view approved published jobs" on public.sightx_job_listings
for select to anon, authenticated using (
  status = 'published'
  and exists (
    select 1 from public.sightx_employers e
    where e.id = sightx_job_listings.employer_id
      and e.verification_status = 'verified'
  )
);
