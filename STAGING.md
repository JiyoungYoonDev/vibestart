# Staging environment

A `staging` branch, mirroring `master`, deploys to its own isolated
environment — push here to validate a change against real infrastructure
before it ever reaches production.

## URLs

- auth-service: `https://auth-service-staging-8bde.up.railway.app`
- woojoo-shop backend and woojoo-studio (separate repos) each have a
  matching `staging` branch pointed at this URL — see their own STAGING.md.

## What's isolated

- **Database + Redis**: staging has its own Postgres and Redis (Railway
  "staging" environment, created by duplicating "production" —
  `railway environment new staging --duplicate production`). Schema is
  migrated fresh via Flyway; no production data is copied.
- **Secrets**: `JWT_SECRET` is a staging-only value, different from
  production's — a staging-issued token doesn't work against production,
  and vice versa. It matches woojoo-shop backend's own staging environment
  (they must agree — that service only verifies tokens this one issues).
- **Not isolated**: `GOOGLE_CLIENT_ID` (same as production) — Google sign-in
  may not work on the staging domain unless its redirect URIs are also
  registered in Google Cloud Console.

## Workflow

1. Push a branch to `staging` (or merge into it) instead of `master`.
2. CI runs the same test suite that gates production
   (`.github/workflows/auth-service-ci.yml` — `staging` was added alongside
   `master`/`main` as a trigger branch).
3. Once it looks right on staging, merge/fast-forward `master` to the same
   commit and push — that's what actually ships to production.

## Known gaps (not yet automated)

- No automatic promotion from staging → production; merging is a manual step.
- `apps/web` and `apps/vibestarter-api` were left out of this staging setup
  (not confirmed deployed anywhere this session) — only auth-service, the
  actively-deployed service, got a staging counterpart.
