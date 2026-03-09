# Metria Project - Documentation Index

This folder is the single source of truth for backend documentation.

## Naming Convention

- Stable docs: `NN-Topic.md` (numeric order by context priority)
- Backlog items: `99-Backlog.md`
- Entry point: `README.md`

## Documents

- `00-Overview.md`: purpose, scope, stack
- `01-Architecture.md`: backend structure and runtime flow
- `02-API-Modules-and-Routes.md`: route groups and responsibilities
- `03-Auth-and-OAuth-Flow.md`: JWT and Google OAuth flow
- `04-Billing-and-Stripe.md`: checkout, webhook, sync, portal
- `05-Goals-and-Assessment.md`: goals, sub-goals, and assessment behavior
- `06-Environment-Variables.md`: required and optional env vars
- `07-API-Contracts.md`: request/response contracts used by clients
- `08-Testing-Strategy.md`: build and smoke validation
- `09-Local-Execution.md`: local run instructions
- `10-Deployment-Railway.md`: deployment and post-deploy checks
- `11-ADR-Decisions.md`: architectural decisions and consequences
- `12-Development-Standards.md`: coding and collaboration standards
- `13-AI-Guidelines.md`: guidance for AI-assisted changes
- `14-Security-OWASP.md`: OWASP-based security validation baseline
- `99-Backlog.md`: pending improvements

## Quick Start

1. Read `00-Overview.md`
2. Read `01-Architecture.md`
3. Configure env from `06-Environment-Variables.md`
4. Execute local setup from `09-Local-Execution.md`
5. For Stripe work, read `04-Billing-and-Stripe.md`
