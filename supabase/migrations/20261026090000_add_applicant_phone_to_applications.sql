-- Persist the contact phone already collected by the live application form.
-- Nullable for compatibility with existing applications and older clients.
alter table public.sightx_applications
  add column if not exists applicant_phone text;
