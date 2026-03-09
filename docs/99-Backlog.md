# Backlog

## Billing and Stripe

- Move webhook idempotency from memory cache to persistent store
- Add explicit mapping table `StripeCustomerId -> UserId`
- Add scheduled reconciliation job for failed/missed webhook scenarios

## Auth and Security

- Add refresh token strategy (current model is access token only)
- Externalize DataProtection keys for multi-instance scenarios
- Add rate limiting on auth endpoints

## Quality and Observability

- Add integration tests for endpoint contracts
- Add webhook fixture-based tests
- Add deploy smoke script for health, oauth redirect, and billing checks
- Add metrics for webhook processing latency and failures

## Product and Domain

- Revisit checkout mode strategy (`payment` vs recurring subscription) and document migration path
- Improve free-plan upgrade diagnostics for goal creation limit responses
