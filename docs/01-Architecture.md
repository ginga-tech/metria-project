# Architecture

## Style

Modular Minimal API organized by endpoint responsibility.

## Main Folders

- `src/Metria.Api/Endpoints`: route groups and request handling
- `src/Metria.Api/Contracts`: request/response DTO contracts
- `src/Metria.Api/Data`: `AppDbContext` and EF mappings
- `src/Metria.Api/Models`: domain entities and enums
- `src/Metria.Api/Services`: subscription business services
- `src/Metria.Api/Repositories`: data access abstractions
- `src/Metria.Api/Billing`: Stripe plan/status mapping helpers

## Runtime Flow

1. `Program.cs` loads env/config and configures services.
2. JWT auth, CORS, Swagger, DbContext, and Stripe key are initialized.
3. App maps endpoint groups (`auth`, `user`, `billing`, `assessment`, `goals`).
4. Startup attempts `db.Database.Migrate()`.
5. Requests execute through endpoint handlers with auth checks.

## Cross-Cutting Concerns

- CORS policy `frontend` controlled by `FRONTEND_ORIGIN`
- JWT validation based on `Jwt__*` configuration keys
- Stripe webhook signature verification and idempotency cache
- Health endpoint at `GET /health-check`
