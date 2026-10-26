# SIGHTX admin MFA enforcement — proposal only

Status: **proposal; not applied to Supabase**  
Scope: restrict trusted SIGHTX administrators to MFA-authenticated (`aal2`) sessions for privileged access through the public Data API.

## Why this is staged

The current portal work in PR #11 adds authenticator enrollment and a login challenge, but the client-side gate alone is not a database security boundary. Current policies use the trusted JWT claim `app_metadata.role = 'admin'` and do not explicitly require `aal2`.

Do **not** deploy the RLS restriction until every active administrator has enrolled and completed a fresh-login MFA test. Otherwise an administrator could lose access to review and recovery screens. The policy below is a design template, not a migration to run now.

## Design

Add a **restrictive** RLS policy on the tables where trusted administrators have privileged access. It allows non-admin users to continue through the existing ownership/public policies, but requires `aal2` whenever the JWT has the trusted admin role.

Candidate tables based on the current application policies:
- `public.sightx_profiles` — admin profile support/access
- `public.sightx_employers` — employer verification
- `public.sightx_job_listings` — job moderation
- `public.sightx_applications` — administrative application updates and access
- `public.sightx_job_reports` — report moderation and access

Do not add this to `sightx_admin_users`: ordinary client roles have no table grants, and the table has no client policies. Do not change legacy `jobs`, `applications`, or `profiles` until their consumers are confirmed.

## Policy template (review before use)

For each candidate table, a policy of this form can be added **after the rollout gate below**. Replace the example policy name with a unique per-table name.

```sql
create policy "require aal2 for admin access"
on public.sightx_job_listings
as restrictive
for all
to authenticated
using (
  coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false) is not true
  or (select auth.jwt() ->> 'aal') = 'aal2'
)
with check (
  coalesce((select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false) is not true
  or (select auth.jwt() ->> 'aal') = 'aal2'
);
```

Repeat the policy for the other candidate tables with a distinct name. The policy is intentionally restrictive: it combines with existing permissive policies rather than replacing ownership checks, published-job reads, applicant access, or verified-employer rules. The admin predicate must continue to use trusted `app_metadata`, never user-editable `user_metadata`.

## Rollout gate — all must pass first

1. Review and merge the authenticator UI PR only after a real browser test of enrollment, valid/invalid TOTP, cancellation, logout/login challenge, and recovery behavior.
2. Sign in as each active admin and enroll an authenticator. Confirm a fresh login requires a code and reaches the admin dashboard only after successful verification.
3. Confirm at least one documented admin recovery path works before changing RLS. Do not depend solely on a browser session that could expire.
4. Test the SQL policy in a non-production Supabase project or a safe staging clone with real JWT assurance levels.
5. Only then prepare a separate, reviewed migration. Apply it during a planned change window and immediately run the checks below.

## Required verification matrix

| Actor/session | Expected result after enforcement |
| --- | --- |
| Anonymous visitor | Can read published jobs only through existing public policy |
| Applicant at AAL1 | Can access only their permitted application/profile data; can submit applications per current policy |
| Verified employer at AAL1 | Can access only their existing permitted employer/job data; no new moderation powers |
| Admin at AAL1 | Cannot read or mutate privileged rows in protected tables |
| Admin at AAL2 | Existing admin review/moderation operations continue to work |
| User with forged `user_metadata.role=admin`, AAL2 | Gets no admin access |
| Admin with stale AAL1 JWT after enrollment | Must refresh/re-authenticate and complete MFA; do not assume client UI alone enforces it |

## Rollback plan

If the admin-at-AAL2 path fails, drop only the newly added restrictive policies by their exact names, verify the existing policies remain unchanged, and restore access. Do not disable RLS, grant broader access, or expose a service-role key as a workaround.

## Current state

No SQL has been applied by this proposal. The live database and deployed site remain unchanged. This document does not claim that the MFA UI has passed an end-to-end browser test.
