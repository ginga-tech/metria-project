# Billing and Stripe

## Current Backend Checkout Flow

`POST /api/billing/checkout` creates a Stripe Checkout Session.

Current behavior:

- Accepts `priceId` directly, or resolves by `plan` (`monthly` / `annual`)
- Validates Stripe price before session creation
- Uses checkout `Mode = payment`
- Stores `plan` and `price_id` in session metadata
- Returns `{ url }` for frontend redirection/popup

## Subscription Status

`GET /api/billing/subscription` returns current status for authenticated user:

- `active`
- `plan`
- `renewsAtUtc`

If local state is not active, endpoint attempts an on-demand Stripe reconciliation.

## Stripe Webhook

Endpoint: `POST /api/billing/webhook`

Processing highlights:

- Validates signature against one or multiple configured webhook secrets
- Uses in-memory idempotency cache by event id
- Handles:
  - `checkout.session.completed`
  - `customer.subscription.created`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
- Has fallback verification by fetching event from Stripe API when signature check fails but event id is present

## Sync and Portal

- `POST /api/billing/sync`: manual reconciliation by `checkoutSessionId`, `subscriptionId`, `customerId`, or `email`
- `POST /api/billing/portal`: creates Stripe Billing Portal session for known customer
- `GET /api/billing/subscriptions/history`: returns historical rows from local DB

## Required Stripe Variables

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`

Optional plan mapping:

- `STRIPE_MONTHLY_PRICE_ID`
- `STRIPE_ANNUAL_PRICE_ID`

## Common Failures

- Webhook secret mismatch
- Live/test mode mismatch
- Invalid price id or inactive Stripe price
- Domain misalignment between frontend, backend, and Stripe redirect URLs
