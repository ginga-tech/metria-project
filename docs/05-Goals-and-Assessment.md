# Goals and Assessment

## Goals Domain Rules

Goals endpoint: `/api/goals`

- Supports periods:
  - `Weekly`
  - `Monthly`
  - `Quarterly`
  - `Semiannual`
  - `Annual`
  - `Custom`
- Goal text max length: 500
- Goal start date must be before end date
- Soft delete via `IsActive`

## Free vs Premium Limit

For users without active/trialing subscription:

- max 5 active goals
- API returns HTTP `402` when limit is exceeded

## Sub-goals Rules

Sub-goals endpoint: `/api/goals/{goalId}/subgoals`

- Text max length: 300
- Sub-goal date range must be inside parent goal period
- Goal deletion is blocked when active sub-goals exist
- Sub-goals use soft delete (`IsActive`)

## Assessment Module

Endpoints:

- `POST /api/assessment`
- `GET /api/assessment/latest`

Behavior:

- Stores scores as JSON (`ScoresJson`)
- Persists average and timestamp
- Retrieves latest assessment for authenticated user
