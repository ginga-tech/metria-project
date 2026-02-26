Metria API — MemoryBank

Purpose
- Centralize knowledge for humans/AI: architecture, env, Stripe notes, and future items.

Project Snapshot
- ASP.NET Core (Minimal APIs), .NET 9.
- Data: PostgreSQL via EF Core (AppDbContext).
- Auth: JWT (email in claims). Front sends `Authorization: Bearer <token>`.

Key Models
- `User` (Id, Name, Email, PasswordHash, BirthDate, ...)
- `Goal` (soft-delete via `IsActive`)
- `Subscription` (provider-agnostic; plan/status enums; period fields; provider IDs)

Endpoints (billing)
- `POST /api/billing/checkout` (optional): creates Stripe Checkout Session (mode=subscription)
- `POST /api/billing/portal`: opens customer billing portal
- `GET /api/billing/subscription`: returns `{ active, plan, renewsAtUtc }` for current user
- `GET /api/billing/subscriptions/history`: subscription history
- `POST /api/billing/webhook`: Stripe webhooks (checkout.session.completed & customer.subscription.*)
- `POST /api/billing/sync`: reconcile by subscription/customer/email

Stripe Config (env/appsettings)
- `Stripe:SecretKey` (or `STRIPE_SECRET_KEY`)
- `Stripe:WebhookSecret` (or `STRIPE_WEBHOOK_SECRET`)
- Optional mapping: `Stripe:MonthlyPriceId`, `Stripe:AnnualPriceId`
- CORS/front:
  - `FrontendOrigin` (or `FRONTEND_ORIGIN`)
  - `BackendBaseUrl` (used for oauth flows)

Local Dev
- DB connection: `POSTGRES_CONNECTION` or `ConnectionStrings:Postgres`
- Migrate: `dotnet ef database update` (auto-migrate also runs at startup)
- Stripe CLI (dev):
  - Test: `stripe listen --events checkout.session.completed,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted --forward-to http://localhost:5104/api/billing/webhook`
  - Live: add `--live` when using live Payment Links

Troubleshooting
- Webhook not firing: check `--live` vs test; ensure `STRIPE_WEBHOOK_SECRET` matches current listen.
- Subscription not active after payment: confirm `customer.subscription.updated` arrived; check logs.
- Email mismatch (Payment Links): prefer Checkout Sessions (client_reference_id) or add mapping by customer.

