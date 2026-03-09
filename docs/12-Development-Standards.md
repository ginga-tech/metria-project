# Development Standards

## Code Changes

- Keep patches focused and minimal.
- Preserve endpoint and contract compatibility unless migration is explicit.
- Do not mix unrelated refactors with functional fixes.

## Backend Conventions

- Keep route orchestration in `Endpoints`.
- Keep DTO contracts in `Contracts`.
- Keep data model mapping in `Data/AppDbContext`.
- Keep Stripe plan/status mapping in `Billing`.

## Error Handling and Logging

- Return explicit `BadRequest` messages for actionable integration errors.
- Add structured logs for auth, billing, and webhook critical paths.
- Remove temporary debug-only logs after validation.

## Documentation Rule

- Any change in environment, endpoints, OAuth, Stripe, or deploy flow must update `docs/`.

## Semantic Commits (Conventional Commits)

Format:

- `type(scope): short description`
- Breaking change: `type(scope)!: short description`

Supported types:

- `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `build`, `ci`, `revert`

Examples:

- `feat(billing): support checkout fallback by plan`
- `fix(auth): harden oauth callback redirect fallback`
- `docs(deploy): align railway dockerfile configuration`
