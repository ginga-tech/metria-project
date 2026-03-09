# API Contracts (Client Consumption)

## Auth

- `POST /api/auth/signup`
  - request: `{ name, email, password }`
  - response: `{ token, expiresInSeconds }`
- `POST /api/auth/login`
  - request: `{ email, password }`
  - response: `{ token, expiresInSeconds }`
- `GET /api/auth/google/start?redirectUri=<url>`
- `GET|POST /api/auth/google/callback`

## User

- `GET /api/me`
  - response: `{ email }`
- `GET /api/user/preferences`
  - response: `{ name, email, birthDate }`
- `PUT /api/user/preferences`
  - request: `{ name?, birthDate? }`
- `GET /api/user/status`
  - response includes: `{ hasAssessment, hasGoals, lastAssessmentDate, email, name }`

## Assessment

- `POST /api/assessment`
  - request: `{ scores, average, createdAtUtc }`
- `GET /api/assessment/latest`
  - response: `AssessmentDto`

## Billing

- `POST /api/billing/checkout`
  - request: `{ priceId?, successUrl?, cancelUrl?, plan? }`
  - rule: at least `priceId` or `plan` is required
  - response: `{ url }`
- `GET /api/billing/subscription`
  - response: `{ active, plan?, renewsAtUtc? }`
- `GET /api/billing/subscriptions/history`
- `POST /api/billing/portal`
  - request: `{ returnUrl? }`
  - response: `{ url }`
- `POST /api/billing/sync`
  - request: `{ subscriptionId?, customerId?, email?, checkoutSessionId? }`

## Goals

- `POST /api/goals`
  - request: `{ text, period, startDate, endDate, category? }`
- `GET /api/goals?period=&startDate=&endDate=`
- `PUT /api/goals/{id}`
  - request: `{ done }`
- `DELETE /api/goals/{id}`

## Sub-goals

- `POST /api/goals/{goalId}/subgoals`
  - request: `{ text, startDate, endDate }`
- `GET /api/goals/{goalId}/subgoals`
- `PUT /api/goals/{goalId}/subgoals/{subGoalId}`
  - request: `{ text?, done?, startDate?, endDate? }`
- `DELETE /api/goals/{goalId}/subgoals/{subGoalId}`
