-- SIGHTX launch-ready MVP database foundation for Supabase
-- This is additive: it uses sightx_* tables so existing public.jobs, public.applications, and public.profiles data is preserved.
-- Apply to the connected SIGHTX Supabase project only after reviewing the current project and this schema.
-- This schema intentionally does not store resume files in table rows; use a private Storage bucket later.

create extension if not exists pgcrypto;

-- Keep privileged helper functions outside the exposed public API schema.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;

create table if not exists public.sightx_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  phone text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.sightx_admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
-- Keep a private roster for administrative audit. Actual admin authorization is a trusted app_metadata.role='admin' claim set only by a privileged server/admin action; never accept user_metadata for authorization.

create table if not exists public.sightx_employers (
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

create table if not exists public.sightx_job_listings (
  id uuid primary key default gen_random_uuid(),
  employer_id uuid not null references public.sightx_employers(id) on delete cascade,
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

create table if not exists public.sightx_applications (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.sightx_job_listings(id) on delete cascade,
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

create table if not exists public.sightx_job_reports (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.sightx_job_listings(id) on delete cascade,
  reporter_id uuid references auth.users(id) on delete set null,
  reason text not null,
  details text,
  status text not null default 'open'
    check (status in ('open','reviewing','resolved','dismissed')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);



create index if not exists sightx_jobs_status_created_idx on public.sightx_job_listings(status, created_at desc);
create index if not exists sightx_jobs_employer_idx on public.sightx_job_listings(employer_id);
create index if not exists sightx_applications_job_idx on public.sightx_applications(job_id, created_at desc);
create index if not exists sightx_applications_applicant_idx on public.sightx_applications(applicant_id, created_at desc);
create index if not exists sightx_job_reports_status_idx on public.sightx_job_reports(status, created_at desc);

-- All new SIGHTX tables use RLS; tables with no matching policy are deny-by-default.
alter table public.sightx_profiles enable row level security;
alter table public.sightx_admin_users enable row level security;
alter table public.sightx_employers enable row level security;
alter table public.sightx_job_listings enable row level security;
alter table public.sightx_applications enable row level security;
alter table public.sightx_job_reports enable row level security;

-- Admin authorization must be a trusted app_metadata.role='admin' claim managed by a privileged server/admin action.
-- Never use user_metadata for roles, and never expose service-role credentials in the browser.

grant select, insert, update on public.sightx_profiles to authenticated;
grant select on public.sightx_job_listings to anon, authenticated;
grant insert, update on public.sightx_job_listings to authenticated;
grant select, insert, update on public.sightx_employers to authenticated;
grant select, insert, update on public.sightx_applications to authenticated;
grant select, insert, update on public.sightx_job_reports to authenticated;
revoke all on public.sightx_admin_users from anon, authenticated;

drop policy if exists "users can create own profile" on public.sightx_profiles;
create policy "users can create own profile" on public.sightx_profiles
for insert to authenticated with check (id = auth.uid());
drop policy if exists "users can read own profile" on public.sightx_profiles;
create policy "users can read own profile" on public.sightx_profiles
for select to authenticated using (id = auth.uid() or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));
drop policy if exists "users can update own profile" on public.sightx_profiles;
create policy "users can update own profile" on public.sightx_profiles
for update to authenticated using (id = auth.uid() or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)) with check (id = auth.uid() or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));

drop policy if exists "users can view own employer application" on public.sightx_employers;
create policy "users can view own employer application" on public.sightx_employers
for select to authenticated using (owner_id = auth.uid() or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));
drop policy if exists "users can submit employer application" on public.sightx_employers;
create policy "users can submit employer application" on public.sightx_employers
for insert to authenticated with check (
  owner_id = auth.uid() and verification_status = 'pending'
  and reviewed_by is null and reviewed_at is null
);
drop policy if exists "employers can update own unreviewed details" on public.sightx_employers;
create policy "employers can update own unreviewed details" on public.sightx_employers
for update to authenticated using (
  owner_id = auth.uid() and verification_status in ('pending','rejected')
) with check (
  owner_id = auth.uid() and verification_status in ('pending','rejected')
  and reviewed_by is null and reviewed_at is null
);
drop policy if exists "admins can manage employer verification" on public.sightx_employers;
create policy "admins can manage employer verification" on public.sightx_employers
for all to authenticated using (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)) with check (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));

drop policy if exists "SIGHTX public read published jobs" on public.sightx_job_listings;
drop policy if exists "public can view approved published jobs" on public.sightx_job_listings;
create policy "public can view approved published jobs" on public.sightx_job_listings
for select to anon, authenticated using (
  status = 'published' and exists (
    select 1 from public.sightx_employers e
    where e.id = sightx_job_listings.employer_id and e.verification_status = 'verified'
  )
);
drop policy if exists "employer can view own jobs" on public.sightx_job_listings;
create policy "employer can view own jobs" on public.sightx_job_listings
for select to authenticated using (
  exists (select 1 from public.sightx_employers e
    where e.id = sightx_job_listings.employer_id and e.owner_id = auth.uid())
  or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
);
drop policy if exists "verified employers can submit jobs for review" on public.sightx_job_listings;
create policy "verified employers can submit jobs for review" on public.sightx_job_listings
for insert to authenticated with check (
  status = 'pending_review' and reviewed_by is null and reviewed_at is null
  and exists (select 1 from public.sightx_employers e
    where e.id = sightx_job_listings.employer_id and e.owner_id = auth.uid()
      and e.verification_status = 'verified')
);
drop policy if exists "admins can moderate jobs" on public.sightx_job_listings;
create policy "admins can moderate jobs" on public.sightx_job_listings
for all to authenticated using (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)) with check (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));

drop policy if exists "applicants can submit own applications" on public.sightx_applications;
create policy "applicants can submit own applications" on public.sightx_applications
for insert to authenticated with check (
  applicant_id = auth.uid() and status = 'new' and employer_notes is null
  and exists (
    select 1 from public.sightx_job_listings j
    join public.sightx_employers e on e.id = j.employer_id
    where j.id = sightx_applications.job_id and j.status = 'published'
      and e.verification_status = 'verified'
  )
);
drop policy if exists "applicants and job owners can read applications" on public.sightx_applications;
create policy "applicants and job owners can read applications" on public.sightx_applications
for select to authenticated using (
  applicant_id = auth.uid()
  or exists (
    select 1 from public.sightx_job_listings j
    join public.sightx_employers e on e.id = j.employer_id
    where j.id = sightx_applications.job_id and e.owner_id = auth.uid()
  )
  or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
);
drop policy if exists "admins can update applications" on public.sightx_applications;
create policy "admins can update applications" on public.sightx_applications
for update to authenticated using (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)) with check (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));

drop policy if exists "authenticated users can report jobs" on public.sightx_job_reports;
create policy "authenticated users can report jobs" on public.sightx_job_reports
for insert to authenticated with check (
  reporter_id = auth.uid() and status = 'open' and reviewed_by is null and reviewed_at is null
);
drop policy if exists "reporters and admins can view reports" on public.sightx_job_reports;
create policy "reporters and admins can view reports" on public.sightx_job_reports
for select to authenticated using (reporter_id = auth.uid() or coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));
drop policy if exists "admins can manage reports" on public.sightx_job_reports;
create policy "admins can manage reports" on public.sightx_job_reports
for update to authenticated using (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)) with check (coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false));

-- Employer edits to submitted jobs and application status transitions are intentionally restricted to admins
-- until trusted server-side moderation actions are implemented.
