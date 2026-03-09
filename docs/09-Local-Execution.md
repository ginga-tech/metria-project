# Local Execution

## Prerequisites

- .NET SDK 9
- PostgreSQL instance available
- Stripe CLI (optional, for webhook testing)

## Setup

1. Configure environment variables:
  - `POSTGRES_CONNECTION` (or `DATABASE_URL`)
  - JWT settings (`Jwt__*`)
  - Optional: Stripe/Google env values
2. Restore and build:
  - `dotnet restore src/Metria.Api/Metria.Api.csproj`
  - `dotnet build src/Metria.Api/Metria.Api.csproj`
3. Run:
  - `dotnet run --project src/Metria.Api/Metria.Api.csproj`

## Swagger Local

- Development environment enables Swagger UI at `/` by default.

## Stripe Local Webhook (Optional)

```bash
stripe listen --events checkout.session.completed,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted --forward-to http://localhost:5104/api/billing/webhook
```

Use the emitted `whsec_...` value in `STRIPE_WEBHOOK_SECRET`.
