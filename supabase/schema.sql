-- SIGHTX launch-ready MVP database foundation for Supabase
-- Run this in Supabase Dashboard > SQL Editor after creating your project.
-- This schema intentionally does not store resume files in table rows; use a private Storage bucket later.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  phone text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
-- Admins must be added manually by the project owner in SQL Editor.
-- Never let a browser/client insert its own row into admin_users.

create table if not exists public.employers (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references auth.users(id) on delete cascade,
  company_name text not null,
  company_website text,
  company_email text not null,
  business_phone text,
  business_address text,
  registration_details text,
  evidence_notes text,
  verification_status text not null default 'pending'
    check (verification_status in ('pending','under_review','verified','rejected','suspended')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  review_notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.jobs (
  id uuid primary key default gen_random_uuid(),
  employer_id uuid not null references public.employers(id) on delete cascade,
  title text not null,
  location text not null,
  employment_type text not null default 'Full-time'
    check (employment_type in ('Full-time','Part-time','Contract','Internship')),
  description text not null,
  salary_text text,
  experience_text text,
  application_email text,
  status text not null default 'pending_review'
    check (status in ('pending_review','published','rejected','closed','suspended')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.jobs(id) on delete cascade,
  applicant_id uuid not null references auth.users(id) on delete cascade,
  full_name text not null,
  email text not null,
  resume_path text,
  cover_message text not null,
  status text not null default 'new'
    check (status in ('new','under_review','shortlisted','interview','hired','rejected')),
  employer_notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(job_id, applicant_id)
);

create table if not exists public.job_reports (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.jobs(id) on delete cascade,
  reporter_id uuid references auth.users(id) on delete set null,
  reason text not null,
  details text,
  status text not null default 'open'
    check (status in ('open','reviewing','resolved','dismissed')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);


-- Prevent employers from approving themselves or publishing jobs without admin review.
create or replace function public.guard_job_moderation_fields()
returns trigger
language plpgsql
security definer
set search_path = ''
as $
declare
  caller_is_admin boolean;
  caller_owns_job boolean;
begin
  caller_is_admin := public.is_sightx_admin();
  select exists (
    select 1 from public.employers e
    where e.id = old.employer_id and e.owner_id = auth.uid()
  ) into caller_owns_job;

  if caller_is_admin then
    return new;
  end if;

  if not caller_owns_job then
    raise exception 'Not authorized to edit this job';
  end if;

  if new.employer_id is distinct from old.employer_id
     or new.reviewed_by is distinct from old.reviewed_by
     or new.reviewed_at is distinct from old.reviewed_at then
    raise exception 'Only SIGHTX administrators can change job moderation fields';
  end if;

  if old.status = 'pending_review' and new.status <> 'pending_review' then
    raise exception 'Jobs must be reviewed by SIGHTX before publication';
  end if;

  if old.status = 'published' and new.status not in ('published','closed') then
    raise exception 'Employers may only close their own published jobs';
  end if;

  if old.status = 'closed' and new.status <> 'closed' then
    raise exception 'Closed jobs require administrator review to reopen';
  end if;

  return new;
end;
$;

drop trigger if exists jobs_guard_moderation_fields on public.jobs;
create trigger jobs_guard_moderation_fields
before update on public.jobs
for each row execute procedure public.guard_job_moderation_fields();

create index if not exists jobs_status_created_idx on public.jobs(status, created_at desc);
create index if not exists jobs_employer_idx on public.jobs(employer_id);
create index if not exists applications_job_idx on public.applications(job_id, created_at desc);
create index if not exists applications_applicant_idx on public.applications(applicant_id, created_at desc);
create index if not exists job_reports_status_idx on public.job_reports(status, created_at desc);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at before update on public.profiles
for each row execute procedure public.set_updated_at();
drop trigger if exists employers_set_updated_at on public.employers;
create trigger employers_set_updated_at before update on public.employers
for each row execute procedure public.set_updated_at();
drop trigger if exists jobs_set_updated_at on public.jobs;
create trigger jobs_set_updated_at before update on public.jobs
for each row execute procedure public.set_updated_at();
drop trigger if exists applications_set_updated_at on public.applications;
create trigger applications_set_updated_at before update on public.applications
for each row execute procedure public.set_updated_at();

alter table public.profiles enable row level security;
alter table public.admin_users enable row level security;
alter table public.employers enable row level security;
alter table public.jobs enable row level security;
alter table public.applications enable row level security;
alter table public.job_reports enable row level security;


-- SECURITY DEFINER avoids recursive row-level-security evaluation when checking admin membership.
create or replace function public.is_sightx_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $
  select exists (select 1 from public.admin_users where user_id = auth.uid());
$;
revoke all on function public.is_sightx_admin() from public;
grant execute on function public.is_sightx_admin() to authenticated;

-- No client-facing insert/update/delete policy exists for admin_users.
drop policy if exists "admins can read admin list" on public.admin_users;
create policy "admins can read admin list" on public.admin_users
for select to authenticated
using (public.is_sightx_admin());

drop policy if exists "users can read own profile" on public.profiles;
create policy "users can read own profile" on public.profiles
for select to authenticated using (id = auth.uid());
drop policy if exists "users can update own profile" on public.profiles;
create policy "users can update own profile" on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "users can view own employer application" on public.employers;
create policy "users can view own employer application" on public.employers
for select to authenticated
using (owner_id = auth.uid() or public.is_sightx_admin());
drop policy if exists "users can submit employer application" on public.employers;
create policy "users can submit employer application" on public.employers
for insert to authenticated
with check (owner_id = auth.uid() and verification_status = 'pending' and reviewed_by is null and reviewed_at is null);
drop policy if exists "employers can update own unreviewed details" on public.employers;
create policy "employers can update own unreviewed details" on public.employers
for update to authenticated
using (owner_id = auth.uid() and verification_status in ('pending','rejected'))
with check (owner_id = auth.uid() and verification_status in ('pending','rejected') and reviewed_by is null and reviewed_at is null);
drop policy if exists "admins can manage employer verification" on public.employers;
create policy "admins can manage employer verification" on public.employers
for all to authenticated
using (public.is_sightx_admin())
with check (public.is_sightx_admin());

drop policy if exists "public can view approved published jobs" on public.jobs;
create policy "public can view approved published jobs" on public.jobs
for select to anon, authenticated
using (
  status = 'published'
  and exists (
    select 1 from public.employers e
    where e.id = jobs.employer_id and e.verification_status = 'verified'
  )
);
drop policy if exists "employer can view own jobs" on public.jobs;
create policy "employer can view own jobs" on public.jobs
for select to authenticated
using (
  exists (select 1 from public.employers e where e.id = jobs.employer_id and e.owner_id = auth.uid())
  or public.is_sightx_admin()
);
drop policy if exists "verified employers can submit jobs for review" on public.jobs;
create policy "verified employers can submit jobs for review" on public.jobs
for insert to authenticated
with check (
  status = 'pending_review'
  and reviewed_by is null and reviewed_at is null
  and exists (
    select 1 from public.employers e
    where e.id = jobs.employer_id and e.owner_id = auth.uid() and e.verification_status = 'verified'
  )
);
drop policy if exists "employers can edit own pending or published jobs" on public.jobs;
create policy "employers can edit own pending or published jobs" on public.jobs
for update to authenticated
using (
  exists (select 1 from public.employers e where e.id = jobs.employer_id and e.owner_id = auth.uid())
  and status in ('pending_review','published','closed')
)
with check (
  exists (select 1 from public.employers e where e.id = jobs.employer_id and e.owner_id = auth.uid())
  and status in ('pending_review','published','closed')
);
drop policy if exists "admins can moderate jobs" on public.jobs;
create policy "admins can moderate jobs" on public.jobs
for all to authenticated
using (public.is_sightx_admin())
with check (public.is_sightx_admin());

drop policy if exists "applicants can submit own applications" on public.applications;
create policy "applicants can submit own applications" on public.applications
for insert to authenticated
with check (
  applicant_id = auth.uid()
  and status = 'new'
  and employer_notes is null
  and exists (
    select 1 from public.jobs j
    join public.employers e on e.id = j.employer_id
    where j.id = applications.job_id and j.status = 'published' and e.verification_status = 'verified'
  )
);
drop policy if exists "applicants and job owners can read applications" on public.applications;
create policy "applicants and job owners can read applications" on public.applications
for select to authenticated
using (
  applicant_id = auth.uid()
  or exists (
    select 1 from public.jobs j
    join public.employers e on e.id = j.employer_id
    where j.id = applications.job_id and e.owner_id = auth.uid()
  )
  or public.is_sightx_admin()
);
drop policy if exists "job owners can update application status" on public.applications;
create policy "job owners can update application status" on public.applications
for update to authenticated
using (
  exists (
    select 1 from public.jobs j
    join public.employers e on e.id = j.employer_id
    where j.id = applications.job_id and e.owner_id = auth.uid()
  )
  or public.is_sightx_admin()
)
with check (
  exists (
    select 1 from public.jobs j
    join public.employers e on e.id = j.employer_id
    where j.id = applications.job_id and e.owner_id = auth.uid()
  )
  or public.is_sightx_admin()
);


-- Employers can update only application status and their private notes, not applicant-submitted identity/details.
create or replace function public.guard_application_updates()
returns trigger
language plpgsql
security definer
set search_path = ''
as $
begin
  if public.is_sightx_admin() then
    return new;
  end if;

  if new.job_id is distinct from old.job_id
     or new.applicant_id is distinct from old.applicant_id
     or new.full_name is distinct from old.full_name
     or new.email is distinct from old.email
     or new.resume_path is distinct from old.resume_path
     or new.cover_message is distinct from old.cover_message then
    raise exception 'Applicant-submitted fields cannot be changed';
  end if;

  if not exists (
    select 1 from public.jobs j
    join public.employers e on e.id = j.employer_id
    where j.id = old.job_id and e.owner_id = auth.uid()
  ) then
    raise exception 'Not authorized to update this application';
  end if;

  return new;
end;
$;

drop trigger if exists applications_guard_updates on public.applications;
create trigger applications_guard_updates
before update on public.applications
for each row execute procedure public.guard_application_updates();

drop policy if exists "authenticated users can report jobs" on public.job_reports;
create policy "authenticated users can report jobs" on public.job_reports
for insert to authenticated
with check (reporter_id = auth.uid() and status = 'open' and reviewed_by is null and reviewed_at is null);
drop policy if exists "reporters and admins can view reports" on public.job_reports;
create policy "reporters and admins can view reports" on public.job_reports
for select to authenticated
using (reporter_id = auth.uid() or public.is_sightx_admin());
drop policy if exists "admins can manage reports" on public.job_reports;
create policy "admins can manage reports" on public.job_reports
for update to authenticated
using (public.is_sightx_admin())
with check (public.is_sightx_admin());

-- Note: configure a private Supabase Storage bucket and its access policies before enabling resume uploads.
-- Do not put the Supabase service_role key in browser code or commit it to GitHub.
