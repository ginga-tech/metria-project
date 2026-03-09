# API Modules and Routes

## Route Groups

Defined through extension methods in `src/Metria.Api/Endpoints/*`.

## System

- `GET /health-check` (anonymous)

## Auth (`/api/auth`)

- `POST /signup`
- `POST /login`
- `GET /google/start`
- `GET|POST /google/callback`

## User (`/api` and `/api/user`)

- `GET /api/me`
- `GET /api/user/preferences`
- `PUT /api/user/preferences`
- `GET /api/user/status`

## Assessment (`/api/assessment`)

- `POST /api/assessment`
- `GET /api/assessment/latest`

## Goals (`/api/goals`)

- `POST /api/goals`
- `GET /api/goals`
- `PUT /api/goals/{id}`
- `DELETE /api/goals/{id}`

Sub-goals:

- `POST /api/goals/{goalId}/subgoals`
- `GET /api/goals/{goalId}/subgoals`
- `PUT /api/goals/{goalId}/subgoals/{subGoalId}`
- `DELETE /api/goals/{goalId}/subgoals/{subGoalId}`

## Billing (`/api/billing`)

- `GET /api/billing/subscription`
- `GET /api/billing/subscriptions/history`
- `POST /api/billing/checkout`
- `POST /api/billing/portal`
- `POST /api/billing/webhook` (anonymous webhook endpoint)
- `POST /api/billing/sync`
- `GET /api/billing/debug` (development only)
