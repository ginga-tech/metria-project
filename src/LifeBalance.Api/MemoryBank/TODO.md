Backlog / Ideas

- Add mapping table (StripeCustomerId → UserId) to strengthen association when Payment Links email differs.
- Add retry/backfill job to reconcile subscriptions nightly via Stripe API.
- Harden webhook security (idempotency keys, request size limits, structured logging).
- Add metrics around webhook deliveries and subscription state changes.
- Expose admin endpoint to view raw last webhook payloads for a user.

