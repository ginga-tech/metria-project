# AI Guidelines

## Objective

Keep AI-assisted changes aligned with current architecture and operational constraints.

## Working Rules

- Prefer surgical edits over broad rewrites.
- Preserve API contracts unless change is explicitly requested.
- Validate integration-critical flows after edits:
  - auth
  - billing
  - goals
- Update `docs/` when behavior or env requirements change.

## High-Signal Files

- Bootstrap/config: `src/Metria.Api/Program.cs`
- Contracts: `src/Metria.Api/Contracts/ApiContracts.cs`
- Billing flow: `src/Metria.Api/Endpoints/BillingEndpoints.cs`
- OAuth flow: `src/Metria.Api/Endpoints/AuthEndpoints.cs`
- Data model: `src/Metria.Api/Data/AppDbContext.cs`

## Validation Baseline

- `dotnet build src/Metria.Api/Metria.Api.csproj -c Release`
- Manual smoke for changed flow (if applicable)
