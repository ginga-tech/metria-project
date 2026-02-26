Stripe Integration Notes (API)

Endpoints
- `POST /api/billing/checkout`: creates Checkout Session (mode=subscription), sets `ClientReferenceId = userId`, `CustomerEmail = user.Email`.
- `POST /api/billing/webhook`: handles `checkout.session.completed` and `customer.subscription.*`.
  - On `checkout.session.completed`, fetches `Subscription` by id and upserts immediately.
  - On `customer.subscription.*`, updates status/periods (`CurrentPeriodStartUtc`, `CurrentPeriodEndUtc`, `CanceledAtUtc`).
- `POST /api/billing/sync`: reconcile by `SubscriptionId`, `CustomerId` or `Email`.

Config
- Keys: `Stripe:SecretKey`, `Stripe:WebhookSecret` (or env `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`).
- Optional plan mapping: `Stripe:MonthlyPriceId`, `Stripe:AnnualPriceId`.

Logs
- Webhook logs event type and upsert actions; useful for diagnosing live/test mismatches.

Common issues
- Live Payment Links + test keys → webhook validated but API cannot fetch objects; align modes.
- Payment Link with different email → record not associated; use `/api/billing/sync` or migrate to Checkout Sessions.

