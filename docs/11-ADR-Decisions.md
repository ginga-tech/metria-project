# ADR Decisions

## ADR-001: Use `docs/` as single source of truth

- Decision: keep canonical documentation under `docs/` with numbered files.
- Rationale: align documentation model with `metria-web` and `metria-worker`.
- Consequence: `MemoryBank` remains only as compatibility pointers.

## ADR-002: Accept `DATABASE_URL` and `POSTGRES_CONNECTION`

- Decision: backend supports both connection formats.
- Rationale: Railway provides URI by default, while local setup often uses full connection string.
- Consequence: normalization logic remains in `Program.cs`.

## ADR-003: Production Swagger controlled by env

- Decision: enable Swagger in production only when `ENABLE_SWAGGER=true`.
- Rationale: allow operational diagnostics without forcing public docs exposure.
- Consequence: root `/` may return `404` when Swagger is disabled.

## ADR-004: Keep webhook-driven subscription source of truth

- Decision: subscription state is primarily driven by Stripe webhook processing.
- Rationale: avoids client-side trust and keeps billing state server-authoritative.
- Consequence: webhook reliability and secret correctness are integration-critical.
